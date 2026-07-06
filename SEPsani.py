#!/usr/bin/env python3
"""
sanitize_cil.py

Clean up ROM-shipped CIL files so they can be re-compiled by secilc.

Background
----------
This ROM's CIL files contain structural duplicates that prevent fresh
compilation by secilc.  The precompiled_sepolicy binary was produced by
Google's build pipeline (which uses custom CIL combiner tooling that
handles these duplicates) — but `secilc` on Ubuntu/Linux refuses them.

The duplicates appear to fall into a few specific categories:

  (1) Same `(type X)` declared in both plat_sepolicy.cil and
      plat_pub_versioned.cil.  The ppv file is supposed to hold only
      VERSIONED types (like adbd_31_0), but here it also redeclares
      UNVERSIONED ones that plat owns.  Solution: remove duplicates
      from ppv, since plat is the canonical owner.

  (2) Same `(typeattribute X)` declared in both files.  Same fix.

  (3) Within plat_sepolicy.cil itself, `system_and_vendor_property_type`
      is declared twice.  The second occurrence is part of an explicit
      "workaround" block — but the type was already auto-declared earlier.
      Solution: comment out the second occurrence.

  (4) A handful of `(type X)` duplicates between plat and vendor_sepolicy.cil
      (e.g. `proc_cpu_alignment`).  These are vendor types that plat
      somehow also declares.  Solution: comment them out of vendor since
      plat owns them at the platform layer.

  (5) Some `(typeattributeset X ...)` lines may also conflict, especially
      if both files claim the same attribute as a complex S-expression.
      Solution: detect at compile time, address case by case.

Usage
-----
    python3 sanitize_cil.py /path/to/rom/

Where /path/to/rom/ is the directory containing system/, vendor/, and
system_ext/ subtrees.  The script will locate the CIL files itself.

Or pass paths explicitly:

    python3 sanitize_cil.py \
        --plat /path/.../plat_sepolicy.cil \
        --ppv /path/.../plat_pub_versioned.cil \
        --vendor /path/.../vendor_sepolicy.cil \
        --system-ext /path/.../system_ext_sepolicy.cil

A `.before_sanitize.bak` backup is made of each file before modification
(skipped if a backup already exists).  All removals are by COMMENTING
OUT the offending lines with a `; sanitize:` marker — never destructive.
Re-running is idempotent.

After running, you'll want to verify with secilc:

    secilc -M true -G -N -c 30 \\
        plat_sepolicy.cil system_ext_sepolicy.cil \\
        vendor_sepolicy.cil plat_pub_versioned.cil \\
        -o /tmp/check.bin

If new errors surface, address them and re-run.
"""

import argparse
import re
import sys
from pathlib import Path


# ----- File location helpers --------------------------------------------------

def autodiscover(rom_root: Path) -> dict:
    """Find the CIL files inside a ROM directory tree.

    The directory layout this ROM uses:
      system/fs_tree/system/etc/selinux/plat_sepolicy.cil
      system/fs_tree/system/etc/selinux/mapping/<ver>.cil
      system/fs_tree/system/etc/selinux/mapping/<ver>.compat.cil
      system_ext/fs_tree/system_ext/etc/selinux/system_ext_sepolicy.cil
      system_ext/fs_tree/system_ext/etc/selinux/mapping/<ver>.cil
      vendor/fs_tree/etc/selinux/vendor_sepolicy.cil
      vendor/fs_tree/etc/selinux/plat_pub_versioned.cil

    Init's CIL recompile loads ALL of these files together — including the
    mapping files — so they all participate in the duplicate-detection
    problem and need sanitizing.
    """
    # Read vendor compat version (e.g. "31.0")
    vendor_ver = None
    vers_file = rom_root / 'vendor' / 'fs_tree' / 'etc' / 'selinux' / 'plat_sepolicy_vers.txt'
    if vers_file.exists():
        vendor_ver = vers_file.read_text().strip()
        print(f"  [+] vendor compat version: {vendor_ver}")

    candidates = {
        'plat':       'system/fs_tree/system/etc/selinux/plat_sepolicy.cil',
        'system_ext': 'system_ext/fs_tree/system_ext/etc/selinux/system_ext_sepolicy.cil',
        'vendor':     'vendor/fs_tree/etc/selinux/vendor_sepolicy.cil',
        'ppv':        'vendor/fs_tree/etc/selinux/plat_pub_versioned.cil',
    }
    if vendor_ver:
        candidates.update({
            'mapping_plat':        f'system/fs_tree/system/etc/selinux/mapping/{vendor_ver}.cil',
            'mapping_plat_compat': f'system/fs_tree/system/etc/selinux/mapping/{vendor_ver}.compat.cil',
            'mapping_system_ext':  f'system_ext/fs_tree/system_ext/etc/selinux/mapping/{vendor_ver}.cil',
        })

    out = {}
    for key, rel in candidates.items():
        p = rom_root / rel
        if p.exists():
            out[key] = p
        else:
            # Mapping files are version-specific — silently skip if absent
            if not key.startswith('mapping_'):
                print(f"  [~] not found ({key}): {p}")
    return out


# ----- Declaration extraction -------------------------------------------------

TYPE_RE = re.compile(r'^\s*\(type\s+([A-Za-z_][\w]*)\s*\)\s*$')
TYPEATTR_RE = re.compile(r'^\s*\(typeattribute\s+([A-Za-z_][\w]*)\s*\)\s*$')

GENFSCON_RE = re.compile(r'^\s*\(genfscon\s+(\S+)\s+("[^"]*"|\S+)\s+\(')


def collect_declarations(path: Path) -> tuple[dict, dict]:
    types: dict = {}
    typeattrs: dict = {}
    if not path.exists():
        return types, typeattrs
    for n, line in enumerate(path.read_text(errors='replace').splitlines(), start=1):
        if line.lstrip().startswith(';'):
            continue
        m = TYPE_RE.match(line)
        if m:
            name = m.group(1)
            if name not in types:
                types[name] = n
            continue
        m = TYPEATTR_RE.match(line)
        if m:
            name = m.group(1)
            if name not in typeattrs:
                typeattrs[name] = n
    return types, typeattrs


# ----- Sanitizer core ---------------------------------------------------------

def backup(path: Path) -> None:
    bak = path.with_suffix(path.suffix + '.before_sanitize.bak')
    if not bak.exists():
        bak.write_bytes(path.read_bytes())
        print(f"  [+] backup: {bak.name}")


def comment_duplicates(path: Path,
                       drop_types: set,
                       drop_typeattrs: set,
                       reason: str) -> int:
    if not path.exists():
        return 0

    lines = path.read_text(errors='replace').splitlines(keepends=True)
    new_lines = []
    commented = 0
    for line in lines:
        if line.lstrip().startswith(';'):
            new_lines.append(line)
            continue

        m_type = TYPE_RE.match(line)
        m_attr = TYPEATTR_RE.match(line)
        target = None
        kind = None
        if m_type and m_type.group(1) in drop_types:
            target = m_type.group(1); kind = 'type'
        elif m_attr and m_attr.group(1) in drop_typeattrs:
            target = m_attr.group(1); kind = 'typeattribute'

        if target is None:
            new_lines.append(line)
            continue

        # Preserve original indentation and newline
        stripped_no_nl = line.rstrip('\n')
        trailing = '\n' if line.endswith('\n') else ''
        new_lines.append(
            f'; sanitize: duplicate {kind} {target} ({reason}) -- '
            f'{stripped_no_nl.lstrip()}{trailing}'
        )
        commented += 1

    if commented:
        path.write_text(''.join(new_lines))
    return commented


def remove_intrafile_duplicate(path: Path,
                               name: str,
                               kind: str = 'typeattribute') -> int:
    if not path.exists():
        return 0
    pat = TYPE_RE if kind == 'type' else TYPEATTR_RE
    lines = path.read_text(errors='replace').splitlines(keepends=True)
    seen = False
    commented = 0
    new_lines = []
    for line in lines:
        if line.lstrip().startswith(';'):
            new_lines.append(line)
            continue
        m = pat.match(line)
        if m and m.group(1) == name:
            if not seen:
                seen = True
                new_lines.append(line)
            else:
                stripped_no_nl = line.rstrip('\n')
                trailing = '\n' if line.endswith('\n') else ''
                new_lines.append(
                    f'; sanitize: intra-file duplicate {kind} {name} -- '
                    f'{stripped_no_nl.lstrip()}{trailing}'
                )
                commented += 1
        else:
            new_lines.append(line)
    if commented:
        path.write_text(''.join(new_lines))
    return commented


# ----- Main -------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('rom_root', nargs='?', type=Path,
                        help='ROM root containing system/, vendor/, system_ext/')
    parser.add_argument('--plat', type=Path, help='Path to plat_sepolicy.cil')
    parser.add_argument('--ppv',  type=Path, help='Path to plat_pub_versioned.cil')
    parser.add_argument('--vendor', type=Path, help='Path to vendor_sepolicy.cil')
    parser.add_argument('--system-ext', type=Path, help='Path to system_ext_sepolicy.cil')
    parser.add_argument('--dry-run', action='store_true',
                        help='Report what would change without writing')
    args = parser.parse_args()

    paths: dict = {}
    if args.rom_root:
        paths.update(autodiscover(args.rom_root))
    if args.plat:       paths['plat'] = args.plat
    if args.ppv:        paths['ppv'] = args.ppv
    if args.vendor:     paths['vendor'] = args.vendor
    if args.system_ext: paths['system_ext'] = args.system_ext

    if 'plat' not in paths:
        print("[!] plat_sepolicy.cil is required (pass --plat or a ROM root).")
        return 1

    print("[*] CIL files in scope:")
    for k, p in paths.items():
        print(f"     {k}: {p}")
    print()

    if not args.dry_run:
        for p in paths.values():
            backup(p)
        print()

    # --- Step 1: Collect declarations from each file -----------------------
    print("[*] Collecting declarations from each CIL file...")
    decls = {}
    for k, p in paths.items():
        types, attrs = collect_declarations(p)
        decls[k] = (types, attrs)
        print(f"     {k}: {len(types)} types, {len(attrs)} typeattributes")
    print()

    plat_types = set(decls['plat'][0].keys())
    plat_attrs = set(decls['plat'][1].keys())

    # --- Step 2: De-dup ppv vs plat ----------------------------------------
    # plat_pub_versioned.cil is supposed to contain only VERSIONED types
    # (like adbd_31_0). Unversioned types in ppv that overlap with plat are
    # the structural problem; remove from ppv since plat is the owner.
    if 'ppv' in paths:
        ppv_types = set(decls['ppv'][0].keys())
        ppv_attrs = set(decls['ppv'][1].keys())
        dup_types = ppv_types & plat_types
        dup_attrs = ppv_attrs & plat_attrs
        print(f"[*] plat_pub_versioned.cil duplicates: "
              f"{len(dup_types)} types, {len(dup_attrs)} typeattributes")
        if not args.dry_run and (dup_types or dup_attrs):
            n = comment_duplicates(paths['ppv'], dup_types, dup_attrs, 'also in plat')
            print(f"     commented {n} line(s)")
        print()

    # --- Step 3: De-dup vendor vs plat -------------------------------------
    # Only a handful expected (e.g. proc_cpu_alignment).
    if 'vendor' in paths:
        v_types = set(decls['vendor'][0].keys())
        v_attrs = set(decls['vendor'][1].keys())
        dup_types = v_types & plat_types
        dup_attrs = v_attrs & plat_attrs
        print(f"[*] vendor_sepolicy.cil duplicates with plat: "
              f"{len(dup_types)} types, {len(dup_attrs)} typeattributes")
        if dup_types:
            print(f"     types: {sorted(dup_types)}")
        if dup_attrs:
            print(f"     attrs: {sorted(dup_attrs)}")
        if not args.dry_run and (dup_types or dup_attrs):
            n = comment_duplicates(paths['vendor'], dup_types, dup_attrs, 'also in plat')
            print(f"     commented {n} line(s)")
        print()

    # --- Step 4: De-dup system_ext vs plat ---------------------------------
    if 'system_ext' in paths:
        se_types = set(decls['system_ext'][0].keys())
        se_attrs = set(decls['system_ext'][1].keys())
        dup_types = se_types & plat_types
        dup_attrs = se_attrs & plat_attrs
        print(f"[*] system_ext_sepolicy.cil duplicates with plat: "
              f"{len(dup_types)} types, {len(dup_attrs)} typeattributes")
        if dup_types or dup_attrs:
            if dup_types: print(f"     types: {sorted(dup_types)}")
            if dup_attrs: print(f"     attrs: {sorted(dup_attrs)}")
            if not args.dry_run:
                n = comment_duplicates(paths['system_ext'], dup_types, dup_attrs,
                                       'also in plat')
                print(f"     commented {n} line(s)")
        print()

    # --- Step 4b: De-dup ppv vs system_ext ---------------------------------
    # plat_pub_versioned also redeclares unversioned system_ext types.
    # Since system_ext owns these at its layer, remove from ppv.
    # (Order matters: we already removed plat-owned duplicates from ppv,
    # so anything left in ppv that matches system_ext is system_ext-owned.)
    if 'ppv' in paths and 'system_ext' in paths:
        # Re-collect ppv state since we modified it in step 2
        ppv_types_now, ppv_attrs_now = collect_declarations(paths['ppv'])
        ppv_types_set = set(ppv_types_now.keys())
        ppv_attrs_set = set(ppv_attrs_now.keys())
        se_types = set(decls['system_ext'][0].keys())
        se_attrs = set(decls['system_ext'][1].keys())
        dup_types = ppv_types_set & se_types
        dup_attrs = ppv_attrs_set & se_attrs
        print(f"[*] plat_pub_versioned.cil duplicates with system_ext: "
              f"{len(dup_types)} types, {len(dup_attrs)} typeattributes")
        if not args.dry_run and (dup_types or dup_attrs):
            n = comment_duplicates(paths['ppv'], dup_types, dup_attrs,
                                   'also in system_ext')
            print(f"     commented {n} line(s)")
        print()

    # --- Step 5: Intra-file duplicate in plat_sepolicy.cil -----------------
    # `system_and_vendor_property_type` is declared in two places within
    # plat_sepolicy.cil — once auto-generated earlier in the file, once near
    # the bottom as part of an explanatory workaround block. Comment out the
    # second occurrence.
    print("[*] Checking known intra-file duplicates in plat_sepolicy.cil...")
    known_intra = [
        ('system_and_vendor_property_type', 'typeattribute'),
    ]
    for name, kind in known_intra:
        if not args.dry_run:
            n = remove_intrafile_duplicate(paths['plat'], name, kind)
            print(f"     {name} ({kind}): commented {n} duplicate(s)")
    print()

    # --- Step 5b: De-dup mapping CIL files vs everything else --------------
    # Each mapping file gets deduplicated against all upstream sources.
    # The ownership chain (decreasing priority): plat > system_ext > ppv.
    # Mapping files come last — anything they redeclare that exists in an
    # upstream file gets commented out.  This catches a few hundred more
    # duplicates that init's combined-CIL compile would otherwise reject.
    mapping_keys = [k for k in paths if k.startswith('mapping_')]
    if mapping_keys:
        print(f"[*] Deduplicating mapping CIL files...")
        ppv_types_now = set()
        ppv_attrs_now = set()
        if 'ppv' in paths:
            t, a = collect_declarations(paths['ppv'])
            ppv_types_now = set(t.keys())
            ppv_attrs_now = set(a.keys())
        se_types_now = set(decls.get('system_ext', ({}, {}))[0].keys())
        se_attrs_now = set(decls.get('system_ext', ({}, {}))[1].keys())
        for mk in mapping_keys:
            mp = paths[mk]
            m_types, m_attrs = collect_declarations(mp)
            m_types_s = set(m_types.keys())
            m_attrs_s = set(m_attrs.keys())
            for upstream_name, up_types, up_attrs in [
                ('plat',       plat_types,    plat_attrs),
                ('system_ext', se_types_now,  se_attrs_now),
                ('ppv',        ppv_types_now, ppv_attrs_now),
            ]:
                dup_t = m_types_s & up_types
                dup_a = m_attrs_s & up_attrs
                if not (dup_t or dup_a):
                    continue
                if not args.dry_run:
                    n = comment_duplicates(mp, dup_t, dup_a, f'also in {upstream_name}')
                    print(f"     {mk}: commented {n} (vs {upstream_name})")
                m_types, m_attrs = collect_declarations(mp)
                m_types_s = set(m_types.keys())
                m_attrs_s = set(m_attrs.keys())
        print()

    # --- Step 6: Cross-file duplicate genfscon rules -----------------------
    # secilc rejects two `(genfscon fs path ...)` rules with the same
    # fs+path combination, even if their contexts match.  This ROM has
    # a few of these between plat and vendor (proc_cpu_alignment etc.).
    # plat is the canonical owner; remove duplicates from other files.
    print("[*] Checking for duplicate genfscon rules across files...")
    plat_genfscon: set = set()
    if 'plat' in paths:
        for line in paths['plat'].read_text(errors='replace').splitlines():
            if line.lstrip().startswith(';'):
                continue
            m = GENFSCON_RE.match(line)
            if m:
                fs, path = m.group(1), m.group(2).strip('"')
                plat_genfscon.add((fs, path))
    other_keys = ['vendor', 'system_ext', 'ppv'] + mapping_keys
    for key in other_keys:
        if key not in paths:
            continue
        p = paths[key]
        lines = p.read_text(errors='replace').splitlines(keepends=True)
        new_lines = []
        commented = 0
        for line in lines:
            if line.lstrip().startswith(';'):
                new_lines.append(line)
                continue
            m = GENFSCON_RE.match(line)
            if m:
                fs, path = m.group(1), m.group(2).strip('"')
                if (fs, path) in plat_genfscon:
                    stripped_no_nl = line.rstrip('\n')
                    trailing = '\n' if line.endswith('\n') else ''
                    new_lines.append(
                        f'; sanitize: duplicate genfscon {fs} {path!r} '
                        f'(also in plat) -- {stripped_no_nl.lstrip()}{trailing}'
                    )
                    commented += 1
                    continue
            new_lines.append(line)
        if commented and not args.dry_run:
            p.write_text(''.join(new_lines))
            print(f"     {key}: commented {commented} duplicate genfscon(s)")
    print()

    print("[OK] CIL sanitization complete.")
    print()
    print("    Next: verify with secilc, e.g.:")
    cil_args = []
    for k in ('plat', 'system_ext', 'vendor', 'ppv'):
        if k in paths:
            cil_args.append(str(paths[k]))
    print(f"    secilc -M true -G -N -c 30 \\")
    for c in cil_args[:-1]:
        print(f"        {c} \\")
    print(f"        {cil_args[-1]} \\")
    print(f"        -o /tmp/check.bin")
    print()
    print("    If new errors surface, address them and re-run this script.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
