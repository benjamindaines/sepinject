#!/usr/bin/env python3
"""
session.py -- gitomic-backed editing sessions for the SEPolicy LSP server.

Each LSP server process that edits .te files under a git working tree is bound to one gitomic session on a
dedicated branch. The session is created when the first .te file is opened and stopped when the server exits.
During the session gitomic's watcher records every settled burst of edits as its own commit, so the policy
author gets a diffable, revertable history without running git by hand.

Design constraints (from the policy-editing workflow):
  - One commit spans from the first edit of a burst to roughly `debounce_ms` of quiescence (default 5000 ms).
  - Cross-burst coalescing is disabled (`coalesce_same_file = false`): once a commit is recorded it is never
    amended, so a later undo of an earlier edit becomes a new commit rather than rewriting history. The
    rationale is preservation -- any intermediate policy state may turn out to be the one that boots.
  - The session never calls `gitomic finish`, which rebuilds and restamps the batch. Finalizing is left to the
    author, by hand, from a terminal. The server only starts, observes, and stops.

Configuration isolation:
  gitomic reads its configuration from `$XDG_CONFIG_HOME/gitomic/gitomic.cfg`, resolving `XDG_CONFIG_HOME`
  before `$HOME/.config`. The session therefore writes a private config tree and points every gitomic
  invocation at it via the child process environment, so the author's global gitomic configuration is left
  untouched. gitomic's watcher is a double-fork daemon that keeps the Config loaded by the `init` process in
  memory, so the private settings reach the watcher without any gitomic source change.
"""

import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger('sepolicy-lsp.session')


@dataclass
class SessionConfig:
    """Tunables for a gitomic-backed session. Supplied via LSP initializationOptions or CLI flags."""
    enabled: bool = True
    gitomic_bin: str = 'gitomic'
    git_bin: str = 'git'
    # Quiescence window handed to gitomic as debounce_ms. A burst of edits collapses into one commit once no
    # further change has arrived for this long.
    debounce_ms: int = 5000
    # Cross-burst coalescing. False keeps every settled burst a distinct, immutable commit.
    coalesce_same_file: bool = False
    # Prefix for the per-session branch name; the timestamp is appended.
    branch_prefix: str = 'sepolicy-lsp'
    # Stop the watcher when the last .te document closes, rather than only at server exit. Off by default so a
    # close-then-reopen within one server lifetime stays on the same branch.
    stop_on_last_close: bool = False


@dataclass
class SessionState:
    """Observable state of the active session, surfaced by the status command."""
    repo_root: Path
    branch: str
    base_branch: str
    config_home: Path
    started_at: float = field(default_factory=time.time)
    active: bool = False


def _run(cmd: list[str], cwd: Optional[Path] = None, env: Optional[dict] = None,
         timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command with captured output. Never raises on non-zero exit; callers inspect returncode."""
    log.debug('run: %s (cwd=%s)', ' '.join(cmd), cwd)
    return subprocess.run(
        cmd, cwd=str(cwd) if cwd else None, env=env,
        capture_output=True, text=True, timeout=timeout)


def find_repo_root(start: Path, git_bin: str = 'git') -> Optional[Path]:
    """Return the git working-tree root containing `start`, or None if `start` is not inside a work tree.

    A filesystem walk is used in preference to shelling out, so the lookup works before any tool is confirmed
    present. The presence of a `.git` entry (directory for a normal clone, file for a worktree or submodule)
    marks the root.
    """
    start = start.resolve()
    for d in (start, *start.parents):
        if (d / '.git').exists():
            return d
    return None


def _current_branch(repo_root: Path, git_bin: str) -> Optional[str]:
    """Return the checked-out branch name, or None on a detached HEAD or error."""
    cp = _run([git_bin, 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=repo_root)
    if cp.returncode != 0:
        return None
    name = cp.stdout.strip()
    return None if name == 'HEAD' or not name else name


def _git_state_is_clean_enough(repo_root: Path, git_bin: str) -> tuple[bool, str]:
    """Reject session start during an in-progress rebase, merge, bisect, or cherry-pick.

    Branching off HEAD during one of these leaves the repository in a state the author did not intend to carry
    onto a new branch. A detached HEAD is also rejected because gitomic records on a named branch.
    """
    git_dir_cp = _run([git_bin, 'rev-parse', '--git-dir'], cwd=repo_root)
    if git_dir_cp.returncode != 0:
        return False, 'not a git repository'
    git_dir = (repo_root / git_dir_cp.stdout.strip()).resolve()
    for marker in ('rebase-merge', 'rebase-apply', 'MERGE_HEAD', 'CHERRY_PICK_HEAD', 'BISECT_LOG'):
        if (git_dir / marker).exists():
            return False, f'git operation in progress ({marker})'
    if _current_branch(repo_root, git_bin) is None:
        return False, 'detached HEAD'
    return True, ''


class GitomicSession:
    """Owns the lifecycle of one gitomic session on a dedicated branch for a single LSP server process."""

    def __init__(self, cfg: SessionConfig):
        self.cfg = cfg
        self.state: Optional[SessionState] = None
        self._open_te_docs: set[str] = set()

    # -- availability ------------------------------------------------------

    def available(self) -> bool:
        """Whether the session feature can operate: enabled and both binaries resolvable."""
        if not self.cfg.enabled:
            return False
        return bool(shutil.which(self.cfg.gitomic_bin) and shutil.which(self.cfg.git_bin))

    def is_active(self) -> bool:
        return self.state is not None and self.state.active

    # -- document bookkeeping ---------------------------------------------

    def note_open(self, uri: str, fs_path: Optional[Path]) -> Optional[str]:
        """Record a .te document opening. Starts the session on the first open. Returns a user-facing note or
        None. Failures are swallowed into the returned note so editing is never blocked."""
        self._open_te_docs.add(uri)
        if self.is_active() or not self.available():
            return None
        if fs_path is None:
            return None
        try:
            return self._start(fs_path)
        except Exception as e:  # defensive: a session must never take the editor down
            log.exception('session start failed')
            return f'sepolicy-lsp: git session not started ({e})'

    def note_close(self, uri: str) -> Optional[str]:
        """Record a .te document closing. Optionally stops the session when the last one closes."""
        self._open_te_docs.discard(uri)
        if self.cfg.stop_on_last_close and not self._open_te_docs and self.is_active():
            return self.stop()
        return None

    # -- lifecycle ---------------------------------------------------------

    def _write_config_home(self, repo_root: Path) -> Path:
        """Write a private gitomic config tree and return the directory to use as XDG_CONFIG_HOME.

        The tree lives under the repository's git-dir so it is per-clone and ignored by git automatically
        (everything under .git is outside the work tree).
        """
        git_dir_cp = _run([self.cfg.git_bin, 'rev-parse', '--git-dir'], cwd=repo_root)
        git_dir = (repo_root / git_dir_cp.stdout.strip()).resolve() if git_dir_cp.returncode == 0 \
            else repo_root / '.git'
        config_home = git_dir / 'sepolicy-lsp' / 'xdg'
        (config_home / 'gitomic').mkdir(parents=True, exist_ok=True)
        cfg_text = (
            '# Written by sepolicy-lsp for policy-editing sessions. Not the author\'s global gitomic config.\n'
            f'debounce_ms = {int(self.cfg.debounce_ms)}\n'
            f'coalesce_same_file = {"true" if self.cfg.coalesce_same_file else "false"}\n'
            '# .te files are the edited artifact; stage only what the watcher observed.\n'
            'stage = observed\n'
        )
        (config_home / 'gitomic' / 'gitomic.cfg').write_text(cfg_text)
        return config_home

    def _env_for(self, config_home: Path) -> dict:
        env = dict(os.environ)
        env['XDG_CONFIG_HOME'] = str(config_home)
        return env

    def _start(self, fs_path: Path) -> Optional[str]:
        repo_root = find_repo_root(fs_path, self.cfg.git_bin)
        if repo_root is None:
            log.info('%s is not inside a git work tree; session not started', fs_path)
            return None

        ok, why = _git_state_is_clean_enough(repo_root, self.cfg.git_bin)
        if not ok:
            return f'sepolicy-lsp: git session not started ({why})'

        base_branch = _current_branch(repo_root, self.cfg.git_bin) or 'HEAD'
        branch = f'{self.cfg.branch_prefix}/{time.strftime("%Y%m%d-%H%M%S")}'

        co = _run([self.cfg.git_bin, 'checkout', '-b', branch], cwd=repo_root)
        if co.returncode != 0:
            return f'sepolicy-lsp: branch creation failed ({co.stderr.strip()})'

        config_home = self._write_config_home(repo_root)
        env = self._env_for(config_home)

        init = _run([self.cfg.gitomic_bin, 'init'], cwd=repo_root, env=env)
        if init.returncode != 0:
            # Leave the branch in place; the author is now on a fresh branch even if the watcher did not arm.
            return (f'sepolicy-lsp: on branch {branch}, but gitomic init failed '
                    f'({init.stderr.strip() or init.stdout.strip()})')

        self.state = SessionState(
            repo_root=repo_root, branch=branch, base_branch=base_branch,
            config_home=config_home, active=True)
        log.info('session started on %s (base %s), config_home=%s', branch, base_branch, config_home)
        return (f'sepolicy-lsp: recording edits on branch {branch} '
                f'(gitomic, {self.cfg.debounce_ms} ms bursts). Run `gitomic status` in the repo to inspect.')

    def _gitomic(self, *args: str, timeout: int = 30) -> subprocess.CompletedProcess:
        if self.state is None:
            raise RuntimeError('no active session')
        env = self._env_for(self.state.config_home)
        return _run([self.cfg.gitomic_bin, *args], cwd=self.state.repo_root, env=env, timeout=timeout)

    def status(self) -> str:
        if not self.is_active():
            return 'sepolicy-lsp: no active git session.'
        cp = self._gitomic('status')
        out = (cp.stdout or cp.stderr).strip()
        return f'Session branch {self.state.branch} (base {self.state.base_branch}):\n{out}'

    def diff(self) -> str:
        """Summarize the session's commits as `git log base_branch..branch`."""
        if not self.is_active():
            return 'sepolicy-lsp: no active git session.'
        cp = _run([self.cfg.git_bin, 'log', '--oneline', '--stat',
                   f'{self.state.base_branch}..{self.state.branch}'], cwd=self.state.repo_root)
        out = (cp.stdout or cp.stderr).strip()
        return out or '(no commits recorded yet)'

    def finish(self, message: Optional[str]) -> str:
        """Stop the watcher and stamp a message across the batch. This rewrites the batch, so it is offered
        only on explicit request; the author supplies the intent message."""
        if not self.is_active():
            return 'sepolicy-lsp: no active git session.'
        if not message:
            return ('sepolicy-lsp: finish needs a message. Run `gitomic finish -m "..."` in the repo, '
                    'or pass a message to sepolicy.session.finish.')
        cp = self._gitomic('finish', '-m', message, timeout=120)
        if cp.returncode == 0:
            self.state.active = False
            return f'sepolicy-lsp: session finished on {self.state.branch}.'
        return f'sepolicy-lsp: finish failed ({cp.stderr.strip() or cp.stdout.strip()})'

    def stop(self) -> Optional[str]:
        """Stop the watcher, keeping the base marker and every recorded commit for later inspection."""
        if not self.is_active():
            return None
        cp = self._gitomic('stop')
        self.state.active = False
        if cp.returncode == 0:
            return f'sepolicy-lsp: stopped recording on {self.state.branch}; commits preserved.'
        return f'sepolicy-lsp: gitomic stop reported an error ({cp.stderr.strip() or cp.stdout.strip()})'

    def abort(self) -> str:
        """Discard the session, resetting the branch to its base. Destructive; offered only on explicit
        request."""
        if not self.is_active():
            return 'sepolicy-lsp: no active git session.'
        cp = self._gitomic('abort', '--force')
        self.state.active = False
        if cp.returncode == 0:
            return f'sepolicy-lsp: session aborted; {self.state.branch} reset to base.'
        return f'sepolicy-lsp: abort failed ({cp.stderr.strip() or cp.stdout.strip()})'

    def shutdown(self) -> Optional[str]:
        """Called on LSP exit. Stops the watcher but never finalizes or discards."""
        return self.stop()
