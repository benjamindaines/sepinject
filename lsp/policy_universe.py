#!/usr/bin/env python3
"""
policy_universe.py -- Load the SELinux policy universe from Android ROM CIL files.

Parses plat_sepolicy.cil, vendor_sepolicy.cil, system_ext_sepolicy.cil, and
plat_pub_versioned.cil to extract:
  - All type declarations
  - All typeattribute declarations and their memberships
  - All class declarations and their valid permissions
  - All common declarations (shared permission sets)
  - All neverallow rules (for conflict detection)
  - All mlsconstrain rules (for conflict detection)
  - genfscon entries

The resulting PolicyUniverse object provides fast lookups for LSP completions
and diagnostics.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ClassInfo:
    """An SELinux object class and its valid permissions."""
    name: str
    permissions: set[str] = field(default_factory=set)
    # If this class inherits from a common, the common's name.
    common: Optional[str] = None


@dataclass
class TypeInfo:
    """A declared SELinux type and its attribute memberships."""
    name: str
    attributes: set[str] = field(default_factory=set)


@dataclass
class AttributeInfo:
    """A declared SELinux typeattribute and its member types."""
    name: str
    members: set[str] = field(default_factory=set)


@dataclass
class NeverallowRule:
    """A parsed neverallow rule for conflict checking."""
    source_expr: object  # Raw S-expression from CIL
    target_expr: object
    class_perms: dict[str, set[str]]  # class -> set of permissions
    line_number: int
    file_path: str


@dataclass
class PolicyUniverse:
    """The complete SELinux policy model loaded from CIL files."""
    types: dict[str, TypeInfo] = field(default_factory=dict)
    attributes: dict[str, AttributeInfo] = field(default_factory=dict)
    classes: dict[str, ClassInfo] = field(default_factory=dict)
    commons: dict[str, set[str]] = field(default_factory=dict)
    # All type and attribute names as a flat set for quick membership checks.
    all_names: set[str] = field(default_factory=set)
    # Neverallow and mlsconstrain rules for conflict detection.
    neverallows: list[NeverallowRule] = field(default_factory=list)
    # genfscon entries: (fs_type, path, context_str)
    genfscons: list[tuple[str, str, str]] = field(default_factory=list)
    # Source CIL file paths that were loaded.
    cil_files: list[str] = field(default_factory=list)

    # --- Macro dictionaries (from AOSP te_macros / global_macros) ---
    # Populated from sepinject's definitions for completion suggestions.
    perm_macros: dict[str, str] = field(default_factory=dict)
    class_macros: dict[str, str] = field(default_factory=dict)
    te_macros: list[str] = field(default_factory=list)

    def type_names(self) -> set[str]:
        """All declared type names (not attributes)."""
        return set(self.types.keys())

    def attribute_names(self) -> set[str]:
        """All declared typeattribute names."""
        return set(self.attributes.keys())

    def class_names(self) -> set[str]:
        """All declared class names."""
        return set(self.classes.keys())

    def permissions_for_class(self, cls_name: str) -> set[str]:
        """Valid permissions for a given class, including inherited common perms."""
        ci = self.classes.get(cls_name)
        if ci is None:
            return set()
        perms = set(ci.permissions)
        if ci.common and ci.common in self.commons:
            perms |= self.commons[ci.common]
        return perms

    def all_permissions(self) -> set[str]:
        """Every distinct permission name across all classes and commons."""
        result = set()
        for ci in self.classes.values():
            result |= ci.permissions
        for perms in self.commons.values():
            result |= perms
        return result

    def attributes_for_type(self, type_name: str) -> set[str]:
        """Which attributes a given type belongs to."""
        ti = self.types.get(type_name)
        return ti.attributes if ti else set()

    def types_in_attribute(self, attr_name: str) -> set[str]:
        """Which types belong to a given attribute."""
        ai = self.attributes.get(attr_name)
        return ai.members if ai else set()


# ---------------------------------------------------------------------------
# CIL parser patterns
# ---------------------------------------------------------------------------

_RE_TYPE_DECL = re.compile(
    r'^\s*\(\s*type\s+([A-Za-z_][\w]*)\s*\)')
_RE_TYPEATTR_DECL = re.compile(
    r'^\s*\(\s*typeattribute\s+([A-Za-z_][\w]*)\s*\)')
_RE_TYPEATTR_SET = re.compile(
    r'^\s*\(\s*typeattributeset\s+([A-Za-z_][\w]*)\s+(.*)\)\s*$')
_RE_CLASS_DECL = re.compile(
    r'^\s*\(\s*class\s+([A-Za-z_][\w]*)\s*\((.*?)\)\s*\)')
_RE_COMMON_DECL = re.compile(
    r'^\s*\(\s*common\s+([A-Za-z_][\w]*)\s*\((.*?)\)\s*\)')
_RE_CLASSCOMMON = re.compile(
    r'^\s*\(\s*classcommon\s+([A-Za-z_][\w]*)\s+([A-Za-z_][\w]*)\s*\)')
_RE_CLASSPERM = re.compile(
    r'^\s*\(\s*classpermission\s+([A-Za-z_][\w]*)\s*\)')
# The context is a CIL s-expression -- e.g. (u object_r t ((s0) (s0))) -- so the context group is matched
# greedily to the final close paren. A non-greedy match truncates at the first ')' inside the context.
_RE_GENFSCON = re.compile(
    r'^\s*\(\s*genfscon\s+"?([^"\s]+)"?\s+"([^"]*)"\s+(.*)\)\s*$')
_RE_NEVERALLOW = re.compile(
    r'^\s*\(\s*neverallow\s+')


def _extract_names_from_sexpr(sexpr_text: str) -> set[str]:
    """Extract bare names from a simple CIL S-expression string.

    Handles patterns like:
        (type1 type2 type3)
        ((not (type1 type2)))
        (and type1 type2)
    Returns just the alphanumeric identifiers, filtering out operators.
    """
    names = set()
    operators = {'and', 'or', 'not', 'xor', 'all'}
    for token in re.findall(r'[A-Za-z_][\w]*', sexpr_text):
        if token not in operators:
            names.add(token)
    return names


def load_cil_file(path: Path, universe: PolicyUniverse) -> None:
    """Parse a single CIL file and populate the universe."""
    if not path.exists():
        return

    text = path.read_text(errors='replace')
    str_path = str(path)
    universe.cil_files.append(str_path)

    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(';'):
            continue

        # Type declaration: (type NAME)
        m = _RE_TYPE_DECL.match(stripped)
        if m:
            name = m.group(1)
            if name not in universe.types:
                universe.types[name] = TypeInfo(name=name)
            universe.all_names.add(name)
            continue

        # Typeattribute declaration: (typeattribute NAME)
        m = _RE_TYPEATTR_DECL.match(stripped)
        if m:
            name = m.group(1)
            if name not in universe.attributes:
                universe.attributes[name] = AttributeInfo(name=name)
            universe.all_names.add(name)
            continue

        # Typeattributeset: (typeattributeset ATTR (members...))
        m = _RE_TYPEATTR_SET.match(stripped)
        if m:
            attr_name = m.group(1)
            members_text = m.group(2)
            members = _extract_names_from_sexpr(members_text)
            # Ensure attr exists.
            if attr_name not in universe.attributes:
                universe.attributes[attr_name] = AttributeInfo(name=attr_name)
            universe.attributes[attr_name].members |= members
            universe.all_names.add(attr_name)
            # Also record reverse: each member type knows it belongs to this attr.
            for member in members:
                if member in universe.types:
                    universe.types[member].attributes.add(attr_name)
                elif member in universe.attributes:
                    # Attribute nesting -- an attr is a member of another attr.
                    pass
            continue

        # Class declaration: (class NAME (perm1 perm2 ...))
        m = _RE_CLASS_DECL.match(stripped)
        if m:
            cls_name = m.group(1)
            perms_text = m.group(2)
            perms = set(perms_text.split()) if perms_text.strip() else set()
            if cls_name not in universe.classes:
                universe.classes[cls_name] = ClassInfo(name=cls_name, permissions=perms)
            else:
                universe.classes[cls_name].permissions |= perms
            continue

        # Common declaration: (common NAME (perm1 perm2 ...))
        m = _RE_COMMON_DECL.match(stripped)
        if m:
            common_name = m.group(1)
            perms_text = m.group(2)
            perms = set(perms_text.split()) if perms_text.strip() else set()
            if common_name not in universe.commons:
                universe.commons[common_name] = perms
            else:
                universe.commons[common_name] |= perms
            continue

        # Classcommon linkage: (classcommon CLASS COMMON)
        m = _RE_CLASSCOMMON.match(stripped)
        if m:
            cls_name = m.group(1)
            common_name = m.group(2)
            if cls_name in universe.classes:
                universe.classes[cls_name].common = common_name
            else:
                universe.classes[cls_name] = ClassInfo(
                    name=cls_name, common=common_name)
            continue

        # Genfscon: (genfscon "fs" "/path" context)
        m = _RE_GENFSCON.match(stripped)
        if m:
            universe.genfscons.append((m.group(1), m.group(2), m.group(3)))
            continue


def _find_cil_files(rom_root: Path) -> list[Path]:
    """Locate the standard Android CIL files under a ROM root."""
    candidates = [
        'system/fs_tree/system/etc/selinux/plat_sepolicy.cil',
        'system/etc/selinux/plat_sepolicy.cil',
        'vendor/fs_tree/etc/selinux/vendor_sepolicy.cil',
        'vendor/etc/selinux/vendor_sepolicy.cil',
        'system_ext/fs_tree/system_ext/etc/selinux/system_ext_sepolicy.cil',
        'system_ext/etc/selinux/system_ext_sepolicy.cil',
        'system/fs_tree/system/etc/selinux/plat_pub_versioned.cil',
        'system/etc/selinux/plat_pub_versioned.cil',
    ]
    # Also check for mapping CIL files.
    mapping_patterns = [
        'system/fs_tree/system/etc/selinux/mapping/',
        'system/etc/selinux/mapping/',
    ]

    found = []
    for c in candidates:
        p = rom_root / c
        if p.exists():
            found.append(p)
    for mp in mapping_patterns:
        d = rom_root / mp
        if d.is_dir():
            for f in sorted(d.glob('*.cil')):
                found.append(f)
    return found


def load_from_rom(rom_root: str | Path) -> PolicyUniverse:
    """Load the full policy universe from an extracted Android ROM."""
    rom_root = Path(rom_root)
    universe = PolicyUniverse()

    # Populate AOSP macro dictionaries (from sepinject's definitions).
    universe.perm_macros = {
        'x_file_perms':         'getattr execute execute_no_trans map',
        'r_file_perms':         'getattr open read ioctl lock map watch watch_reads',
        'w_file_perms':         'open append write lock map',
        'rx_file_perms':        'r_file_perms x_file_perms',
        'ra_file_perms':        'r_file_perms append',
        'rw_file_perms':        'r_file_perms w_file_perms',
        'rwx_file_perms':       'rw_file_perms x_file_perms',
        'create_file_perms':    'create rename setattr unlink rw_file_perms',
        'r_dir_perms':          'open getattr read search ioctl lock watch watch_reads',
        'w_dir_perms':          'open search write add_name remove_name lock',
        'ra_dir_perms':         'r_dir_perms add_name write',
        'rw_dir_perms':         'r_dir_perms w_dir_perms',
        'create_dir_perms':     'create reparent rename rmdir setattr rw_dir_perms',
        'r_ipc_perms':          'getattr read associate unix_read',
        'w_ipc_perms':          'write unix_write',
        'rw_ipc_perms':         'r_ipc_perms w_ipc_perms',
        'create_ipc_perms':     'create setattr destroy rw_ipc_perms',
        'rw_socket_perms':
            'ioctl read getattr write setattr lock append bind connect '
            'getopt setopt shutdown map',
        'rw_socket_perms_no_ioctl':
            'read getattr write setattr lock append bind connect '
            'getopt setopt shutdown map',
        'create_socket_perms':            'create rw_socket_perms',
        'create_socket_perms_no_ioctl':   'create rw_socket_perms_no_ioctl',
        'rw_stream_socket_perms':         'rw_socket_perms listen accept',
        'create_stream_socket_perms':     'create rw_stream_socket_perms',
    }
    universe.class_macros = {
        'capability_class_set':         'capability capability2 cap_userns cap2_userns',
        'global_capability_class_set':  'capability cap_userns',
        'global_capability2_class_set': 'capability2 cap2_userns',
        'devfile_class_set':            'chr_file blk_file',
        'notdevfile_class_set':         'file lnk_file sock_file fifo_file',
        'file_class_set':               'devfile_class_set notdevfile_class_set',
        'dir_file_class_set':           'dir file_class_set',
        'dgram_socket_class_set':       'udp_socket unix_dgram_socket',
        'stream_socket_class_set':      'tcp_socket unix_stream_socket sctp_socket',
        'unpriv_socket_class_set':
            'tcp_socket udp_socket unix_stream_socket unix_dgram_socket sctp_socket',
        'network_socket_class_set':     'icmp_socket rawip_socket tcp_socket udp_socket',
        'ipc_class_set':                'sem msgq shm ipc',
    }
    universe.te_macros = [
        'init_daemon_domain',
        'domain_auto_trans',
        'domain_trans',
        'set_prop',
        'get_prop',
        'binder_use',
        'binder_call',
        'binder_service',
        'unix_socket_connect',
    ]

    cil_files = _find_cil_files(rom_root)
    for cil_path in cil_files:
        load_cil_file(cil_path, universe)

    # Back-fill reverse attribute memberships: for any type that appeared
    # as a member in a typeattributeset but was not declared with (type ...),
    # create a TypeInfo entry so completions can find it.
    for attr_name, attr_info in universe.attributes.items():
        for member in attr_info.members:
            if member not in universe.types and member not in universe.attributes:
                universe.types[member] = TypeInfo(name=member)
                universe.all_names.add(member)
            if member in universe.types:
                universe.types[member].attributes.add(attr_name)

    return universe


def load_from_cil_paths(cil_paths: list[str | Path]) -> PolicyUniverse:
    """Load the policy universe from explicit CIL file paths."""
    universe = PolicyUniverse()
    for p in cil_paths:
        load_cil_file(Path(p), universe)
    return universe


# ---------------------------------------------------------------------------
# CLI for quick inspection
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <rom-root | cil-file ...>')
        print()
        print('Load the SELinux policy universe and print summary statistics.')
        sys.exit(1)

    target = Path(sys.argv[1])
    if target.is_dir():
        u = load_from_rom(target)
    else:
        u = load_from_cil_paths([Path(a) for a in sys.argv[1:]])

    print(f'CIL files loaded: {len(u.cil_files)}')
    print(f'Types:            {len(u.types)}')
    print(f'Attributes:       {len(u.attributes)}')
    print(f'Classes:          {len(u.classes)}')
    print(f'Commons:          {len(u.commons)}')
    print(f'Genfscons:        {len(u.genfscons)}')
    print(f'Total names:      {len(u.all_names)}')

    if '--classes' in sys.argv:
        print('\n--- Classes ---')
        for name in sorted(u.classes):
            perms = u.permissions_for_class(name)
            print(f'  {name}: {len(perms)} perms')

    if '--types' in sys.argv:
        print('\n--- Types (first 50) ---')
        for name in sorted(u.types)[:50]:
            attrs = u.attributes_for_type(name)
            attr_str = ', '.join(sorted(attrs)[:5])
            if len(attrs) > 5:
                attr_str += f' ... (+{len(attrs)-5})'
            print(f'  {name}: [{attr_str}]')
