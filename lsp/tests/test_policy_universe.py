"""Tests for policy_universe CIL parsing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fixtures import SYNTH_CIL  # noqa: E402
from policy_universe import load_from_cil_paths  # noqa: E402


def _load(tmp_path) -> object:
    cil = tmp_path / 'synth.cil'
    cil.write_text(SYNTH_CIL)
    return load_from_cil_paths([cil])


def test_types_and_attributes_parsed(tmp_path):
    u = _load(tmp_path)
    assert 'domain_a' in u.types
    assert 'domain_b' in u.types
    assert 'file_x' in u.types
    assert 'app_domain' in u.attributes


def test_attribute_membership_bidirectional(tmp_path):
    u = _load(tmp_path)
    assert u.types_in_attribute('app_domain') == {'domain_a', 'domain_b'}
    assert 'app_domain' in u.attributes_for_type('domain_a')
    assert 'app_domain' in u.attributes_for_type('domain_b')


def test_class_permissions_including_common(tmp_path):
    u = _load(tmp_path)
    assert u.permissions_for_class('file') == {'read', 'write', 'open', 'getattr'}
    # sem inherits the ipc common's permissions plus its own.
    assert u.permissions_for_class('sem') == {'associate', 'create', 'destroy'}


def test_genfscon_recorded(tmp_path):
    u = _load(tmp_path)
    assert ('proc', '/sys/x', '(u object_r file_x ((s0) (s0)))') in [
        (fs, path, ctx) for (fs, path, ctx) in u.genfscons]


def test_all_names_includes_types_and_attrs(tmp_path):
    u = _load(tmp_path)
    assert {'domain_a', 'domain_b', 'file_x', 'app_domain'} <= u.all_names
