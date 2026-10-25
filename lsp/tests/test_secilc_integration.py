"""Integration test for the secilc compile-check path.

Exercises `_secilc_check` against a complete, self-contained synthetic base policy using the bundled static
secilc. Skips when the bundled binary cannot execute on this host (e.g. a non-x86_64 CI runner) or when
sepinject is not alongside the checkout, so the suite stays green off-target.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sepolicy_lsp as S  # noqa: E402

# A complete, valid CIL policy: compiles clean on its own, so any diagnostic comes from the buffer fragment.
BASE_CIL = """\
(class file (read write open getattr))
(classorder (file))
(sid kernel)
(sidorder (kernel))
(user u)(role r)(type t)(roletype r t)(userrole u r)
(category c0)(categoryorder (c0))(sensitivity s0)(sensitivityorder (s0))
(sensitivitycategory s0 (c0))(level l0 (s0))(levelrange lr0 (l0 l0))
(userlevel u l0)(userrange u lr0)(context ctx (u r t lr0))(sidcontext kernel ctx)
(allow t self (file (read)))
"""


def _bundled_secilc_runs(tmp_dir: Path) -> bool:
    """True when the bundled binary executes on this host (arch match) and compiles a valid policy.

    secilc returns a non-zero exit for --help, so liveness is probed by compiling the valid base policy; a
    wrong-architecture binary raises on exec and is reported as not runnable.
    """
    b = Path(__file__).resolve().parent.parent / 'bin' / 'secilc'
    if not (b.is_file() and os.access(b, os.X_OK)):
        return False
    probe = tmp_dir / 'probe.cil'
    probe.write_text(BASE_CIL)
    try:
        r = subprocess.run([str(b), '-M', 'true', '-c', '30', str(probe),
                            '-o', str(tmp_dir / 'probe.bin'), '-f', '/dev/null'],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def _sepinject() -> Path | None:
    env = os.environ.get('SEPINJECT_PATH')
    if env and Path(env).is_file():
        return Path(env)
    c = Path(__file__).resolve().parents[2] / 'sepinject.py'
    return c if c.is_file() else None


@pytest.fixture(autouse=True)
def _wire(tmp_path, monkeypatch):
    if not _bundled_secilc_runs(tmp_path):
        pytest.skip('bundled secilc not runnable on this host')
    sep = _sepinject()
    if sep is None:
        pytest.skip('sepinject.py not found alongside the checkout')
    base = tmp_path / 'base.cil'
    base.write_text(BASE_CIL)
    monkeypatch.setattr(S, '_cil_paths', [str(base)])
    monkeypatch.setattr(S, '_secilc_path', str(Path(__file__).resolve().parent.parent / 'bin' / 'secilc'))
    monkeypatch.setattr(S, '_secilc_policyvers', 30)
    monkeypatch.setattr(S, '_sepinject_path', sep)
    monkeypatch.setattr(S, '_sepinject_mod', None)


def test_clean_buffer_produces_no_diagnostics():
    assert S._secilc_check('allow t t:file { write };\n') == []


def test_unknown_class_flagged():
    diags = S._secilc_check('allow t t:bogusclass { read };\n')
    assert diags and diags[0].source == 'sepolicy-lsp/secilc'


def test_unknown_permission_flagged():
    diags = S._secilc_check('allow t t:file { bogusperm };\n')
    assert diags and diags[0].source == 'sepolicy-lsp/secilc'
