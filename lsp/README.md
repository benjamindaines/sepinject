# sepolicy-lsp

SEPolicy Language Server providing context-aware editing for Android `.te` files.

## Features

- **Context-aware completions**: types, attributes, classes, permissions, macros — filtered by cursor position within access-vector rules, type declarations, typeattribute statements, etc.
- **Semantic diagnostics**: unknown types/attributes, unknown classes, unknown permissions flagged on edit.
- **Compile diagnostics on save**: the buffer is converted to CIL (via `sepinject.rules_to_cil`) and compiled against the loaded base policy with `secilc`; real compiler errors are surfaced. A version-pinned static `secilc` is bundled (`bin/secilc`), so the check does not depend on the system libsepol.
- **Hover information**: type attributes, attribute members, class permissions, macro expansions.
- **Code actions**: add missing semicolons, declare unknown types, trigger neverallow conflict checks.
- **Neverallow conflict checks**: invoke `sepinject`'s `find_neverallow_conflicts` in-process on the rule under the cursor.
- **Git sessions via gitomic**: each editing session records every settled burst of edits as its own commit on a dedicated branch, for a diffable, revertable history (see below).

## Requirements

- Python 3.10+
- `pygls` 2.x (`pip install pygls`)
- `lsprotocol` (installed as pygls dependency)
- One or more CIL files from the target ROM (typically `plat_sepolicy.cil`)
- Optional: `sepinject.py` (repo root) for neverallow conflict resolution and the secilc compile path
- `secilc` for compile diagnostics — a static x86_64 build is bundled at `bin/secilc`; see `bin/README.md` to rebuild natively or for another architecture
- Optional: `gitomic` on `PATH` for per-session commit recording

## Usage

### Standalone (stdio mode, for editor integration)

```bash
python3 sepolicy_lsp.py --cil /path/to/plat_sepolicy.cil [--sepinject /path/to/sepinject.py] [--rom-root /path/to/rom]
```

### TCP mode (for development/debugging)

```bash
python3 sepolicy_lsp.py --tcp 2087 --cil /path/to/plat_sepolicy.cil
```

### Multiple CIL files

```bash
python3 sepolicy_lsp.py --cil plat_sepolicy.cil plat_sepolicy_30.0.cil vendor_sepolicy.cil
```

Loading via `--rom-root` discovers the standard CIL files automatically and makes them available to the neverallow and secilc features as well.

## Git sessions (gitomic)

When the opened `.te` file lives inside a git work tree and `gitomic` is on `PATH`, the server binds the editing session to a new branch and records changes automatically:

1. On the first `.te` file opened, the server cuts a branch `sepolicy-lsp/<timestamp>` off the current HEAD and runs `gitomic init`.
2. `gitomic`'s watcher commits each settled burst of edits as its own commit. A burst closes after roughly `--session-debounce-ms` (default 5000 ms) of quiescence. Cross-burst coalescing is disabled, so once a commit is recorded it is never amended — a later undo of an earlier edit becomes a new commit. The intent is preservation: any intermediate policy state may be the one that boots.
3. On server exit, the watcher is stopped with `gitomic stop`. The batch is **never** finalized or discarded automatically; the recorded commits remain on the branch.

Session settings are isolated from the global gitomic configuration. The server writes a private `gitomic.cfg` under `<git-dir>/sepolicy-lsp/xdg/gitomic/` and points gitomic at it via `XDG_CONFIG_HOME`, so `~/.config/gitomic/gitomic.cfg` is untouched.

To stamp an intent message across the batch, run `gitomic finish -m "..."` by hand in the repository after the session (or use the `sepolicy.session.finish` command). `finish` rebuilds and restamps the batch, so it is left as an explicit author action.

### Session flags

- `--no-git-session` — disable the feature entirely.
- `--gitomic <path>` — gitomic binary (default: `gitomic`).
- `--session-debounce-ms <ms>` — burst quiescence window (default: 5000).
- `--session-branch-prefix <prefix>` — branch name prefix (default: `sepolicy-lsp`).
- `--session-stop-on-last-close` — stop recording when the last `.te` document closes, not only at server exit.

## Compile checks (secilc)

On save, the buffer's rules are converted to a CIL fragment and compiled with the other loaded CIL files,
mirroring the project's `sepcheck.sh` Pass 1:

```
secilc -M true -G -N -c <policyvers> <base CILs...> <buffer.cil> -o <tmp> -f /dev/null
```

`-N` disables neverallow checking so intentional carve-outs in the base policy do not abort the syntax and
resolution check (neverallow conflicts are handled by `sepolicy.checkNeverallow`). The policy version defaults
to **30** (the MediaTek target; override with `--secilc-policyvers`). Resolution needs the full CIL set, so run
with `--rom-root` or all four `--cil` files — otherwise the check reports resolution noise. secilc is resolved
in the order `--secilc` → `$SEPOLICY_LSP_SECILC` → bundled `bin/secilc` → `PATH`.

### secilc flags

- `--secilc <path>` — override the secilc binary (default: bundled static build, then PATH).
- `--secilc-policyvers <n>` — policy version passed to `secilc -c` (default: 30).

## Custom commands

- `sepolicy.checkNeverallow` — check the allow rule on a line against the loaded CIL neverallows.
- `sepolicy.reloadUniverse` — hot-reload the policy universe from CIL files.
- `sepolicy.session.status` — show `gitomic status` for the active session.
- `sepolicy.session.diff` — list the session's commits (`git log base..branch`).
- `sepolicy.session.finish` — stop the watcher and stamp a message across the batch (argument: message).
- `sepolicy.session.abort` — discard the session and reset the branch to its base (destructive).

## Kate configuration

Copy `kate-lspclient.json` into `~/.config/kate/lspclient/` (create the directory if needed) and edit the paths.

Kate does not natively recognize `.te` as a filetype. Install the bundled highlighting definition so the mode is assigned and the server attaches:

```bash
mkdir -p ~/.local/share/org.kde.syntax-highlighting/syntax/
cp te.xml ~/.local/share/org.kde.syntax-highlighting/syntax/
```

The definition is named `SELinux TE`, which the `highlightingModeRegex` in `kate-lspclient.json` matches.

## Architecture

- `policy_universe.py` — Parses CIL files into an in-memory model of all types, attributes, classes, permissions, and neverallow rules.
- `te_parser.py` — Analyzes `.te` file text at a cursor position to determine statement kind and cursor context (source, target, class, permission, etc.).
- `session.py` — Manages the per-session gitomic branch and commit recording.
- `sepolicy_lsp.py` — The LSP server itself, wiring `pygls` features to the parser, universe, sepinject, secilc, and the session.

## Tests

```bash
python3 -m pytest lsp/tests
```

The neverallow integration test requires `sepinject.py` at the repository root (or `SEPINJECT_PATH`); it skips otherwise.

## Remaining Work

- Map `secilc` compile errors back to specific `.te` lines (the rule-to-CIL transform does not preserve source lines one-to-one; errors are currently reported at file level).
- A hard time cap on a single burst (seal a commit after a maximum elapsed editing time even without quiescence). Requires a new `max_commit_ms` knob in gitomic; filed as a follow-up.
- Inline neverallow/mlsconstrain conflict diagnostics (currently a code action, not a live squiggle).
