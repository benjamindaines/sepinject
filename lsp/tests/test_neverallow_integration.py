"""Integration test for the in-process neverallow conflict check.

sepinject.py lives at the repository root (the parent of lsp/). When present, it is imported in-process the
same way the LSP server does, and exercised against the synthetic policy: an allow that the synthetic
neverallow forbids must be reported, and an allow it permits must not be. The test skips when sepinject is
not alongside the checkout.
"""

import contextlib
import importlib.util
import io
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures import SYNTH_CIL  # noqa: E402


def _locate_sepinject() -> Path | None:
    env = os.environ.get('SEPINJECT_PATH')
    if env and Path(env).is_file():
        return Path(env)
    candidate = Path(__file__).resolve().parents[2] / 'sepinject.py'
    return candidate if candidate.is_file() else None


def _import_sepinject(path: Path):
    spec = importlib.util.spec_from_file_location('sepinject', str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules['sepinject'] = mod
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def sep():
    path = _locate_sepinject()
    if path is None:
        pytest.skip('sepinject.py not found alongside the checkout')
    return _import_sepinject(path)


@pytest.fixture
def cil(tmp_path) -> Path:
    p = tmp_path / 'synth.cil'
    p.write_text(SYNTH_CIL)
    return p


def _conflicts_for(sep, cil: Path, rule_text: str, tmp_path: Path):
    te = tmp_path / 'rule.te'
    te.write_text(rule_text + '\n')
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rules = [r for r in sep.parse_te_file(str(te)) if getattr(r, 'op', '') == 'allow']
        conflicts, _am, _at = sep.find_neverallow_conflicts(rules, [('synth', cil)])
    return conflicts


def test_forbidden_allow_is_flagged(sep, cil, tmp_path):
    # app_domain members may not write file_x; domain_a is in app_domain.
    conflicts = _conflicts_for(sep, cil, 'allow domain_a file_x:file { write };', tmp_path)
    assert conflicts, 'expected a neverallow conflict for a forbidden write'


def test_permitted_allow_is_clean(sep, cil, tmp_path):
    conflicts = _conflicts_for(sep, cil, 'allow domain_a file_x:file { read };', tmp_path)
    assert not conflicts, 'read is not covered by the neverallow; no conflict expected'
