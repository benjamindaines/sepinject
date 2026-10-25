"""Tests for the gitomic-backed session layer.

A fake `gitomic` executable records its invocations and exits successfully, so the session's branch creation,
private-config generation, and command sequencing can be verified without building the real tool.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from session import GitomicSession, SessionConfig, find_repo_root  # noqa: E402

FAKE_GITOMIC = """\
#!/usr/bin/env bash
echo "$@" >> "$GITOMIC_SHIM_LOG"
case "$1" in
  status) echo "base: deadbeef; pending: 3; watcher: alive" ;;
  *) : ;;
esac
exit 0
"""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(['git', *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path) -> Path:
    r = tmp_path / 'policy'
    r.mkdir()
    _git(r, 'init', '-b', 'main')
    _git(r, 'config', 'user.email', 'test@example.invalid')
    _git(r, 'config', 'user.name', 'test')
    (r / 'foo.te').write_text('allow domain_a file_x:file { read };\n')
    _git(r, 'add', '.')
    _git(r, 'commit', '-m', 'init')
    return r


@pytest.fixture
def shim(tmp_path) -> Path:
    s = tmp_path / 'gitomic'
    s.write_text(FAKE_GITOMIC)
    s.chmod(0o755)
    return s


def _session(shim: Path, log: Path, **overrides) -> GitomicSession:
    os.environ['GITOMIC_SHIM_LOG'] = str(log)
    cfg = SessionConfig(gitomic_bin=str(shim), debounce_ms=5000, coalesce_same_file=False, **overrides)
    return GitomicSession(cfg)


def test_find_repo_root(repo):
    assert find_repo_root(repo / 'foo.te') == repo.resolve()
    assert find_repo_root(Path('/')) is None


def test_start_creates_branch_and_private_config(repo, shim, tmp_path):
    log = tmp_path / 'calls.log'
    sess = _session(shim, log)
    note = sess.note_open('file://' + str(repo / 'foo.te'), repo / 'foo.te')
    assert sess.is_active()
    assert note and 'sepolicy-lsp/' in note

    branch = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=repo,
                            capture_output=True, text=True).stdout.strip()
    assert branch.startswith('sepolicy-lsp/')

    # gitomic init was invoked.
    assert 'init' in log.read_text().splitlines()

    # The private config carries the burst settings and does not touch the global config.
    cfg_file = sess.state.config_home / 'gitomic' / 'gitomic.cfg'
    text = cfg_file.read_text()
    assert 'debounce_ms = 5000' in text
    assert 'coalesce_same_file = false' in text


def test_status_and_stop(repo, shim, tmp_path):
    log = tmp_path / 'calls.log'
    sess = _session(shim, log)
    sess.note_open('file://' + str(repo / 'foo.te'), repo / 'foo.te')
    assert 'watcher: alive' in sess.status()
    stop_note = sess.stop()
    assert stop_note and 'stopped recording' in stop_note
    assert not sess.is_active()
    assert 'stop' in log.read_text().splitlines()


def test_only_one_session_per_process(repo, shim, tmp_path):
    log = tmp_path / 'calls.log'
    sess = _session(shim, log)
    sess.note_open('file://' + str(repo / 'foo.te'), repo / 'foo.te')
    first_branch = sess.state.branch
    # A second open must not start a new session or a second branch.
    sess.note_open('file://' + str(repo / 'bar.te'), repo / 'bar.te')
    assert sess.state.branch == first_branch
    assert log.read_text().count('init') == 1


def test_not_a_git_repo_is_graceful(tmp_path, shim):
    log = tmp_path / 'calls.log'
    plain = tmp_path / 'plain'
    plain.mkdir()
    (plain / 'x.te').write_text('allow a b:file { read };\n')
    sess = _session(shim, log)
    note = sess.note_open('file://' + str(plain / 'x.te'), plain / 'x.te')
    assert note is None
    assert not sess.is_active()


def test_stop_on_last_close(repo, shim, tmp_path):
    log = tmp_path / 'calls.log'
    sess = _session(shim, log, stop_on_last_close=True)
    uri = 'file://' + str(repo / 'foo.te')
    sess.note_open(uri, repo / 'foo.te')
    assert sess.is_active()
    note = sess.note_close(uri)
    assert note and 'stopped recording' in note
    assert not sess.is_active()
