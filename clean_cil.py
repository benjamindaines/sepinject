#!/usr/bin/env python3
"""
clean_cil.py — Clean up and regroup a sepinject-patched plat_sepolicy.cil.

Two regions, split at the marker line:  ; ~~~:BEGIN_MODS:~~~

ABOVE the marker (the AOSP-generated stock policy + in-place neverallow
rewrites):
  * Every sepinject *comment* is stripped:
      - ';; sepinject: ...'                (all sepinject annotation lines)
      - ';; (neverallow ...)'              (commented-out original neverallows)
      - ';(neverallow sepinject_aux ...)'  (commented-out duplicate rewrites)
  * Everything else is left byte-for-byte in place, including the AOSP
    ';;* lmx N <file>' / ';;* lme' provenance markers and every active rule.
    The active rewritten '(neverallow sepinject_aux ...)' lines stay put
    UNLESS --relocate-neverallows is given, in which case they are pulled
    down into the mods region.

BELOW the marker (the sepinject mods) is fully rebuilt:
  * All non-active (commented / disabled) lines are dropped.
  * Active statements are regrouped.
  * typepermissive statements, at the very bottom.

Safety: the multiset of active (paren-leading) statements is asserted
identical before/after in each region (accounting for any relocation).
Nothing active is ever added, dropped, or altered. On ANY failure the
tool aborts without touching the filesystem.

Non-destructive I/O:
  The input file is renamed to '<input>.unclean' (preserved untouched) and
  the cleaned result is written under the input's ORIGINAL name, ready to
  drop into the ROM. Refuses to run if '<input>.unclean' already exists
  (protects the true original from a double-run) unless --force is given.

Usage:
  python3 clean_cil.py plat_sepolicy.cil
  python3 clean_cil.py plat_sepolicy.cil --relocate-neverallows
  python3 clean_cil.py plat_sepolicy.cil --dry-run          # write nothing
  python3 clean_cil.py plat_sepolicy.cil -o cleaned.cil     # custom output,
                                                            #  no rename
"""

import argparse
import re
import sys
from collections import Counter, defaultdict, OrderedDict
from pathlib import Path

MARKER_SUBSTR = "~~~:BEGIN_MODS:~~~"

# ---- line classifiers ------------------------------------------------------

def is_active(line: str) -> bool:
    """An active CIL statement line begins (after whitespace) with '('."""
    return line.lstrip().startswith("(")

def norm(line: str) -> str:
    """Whitespace-normalized form for multiset comparison."""
    return " ".join(line.split())

RE_SEPINJECT_ANNOT   = re.compile(r"^\s*;;\s*sepinject:")
RE_COMMENTED_ORIG_NA = re.compile(r"^\s*;;\s*\(neverallow\b")
RE_COMMENTED_DUP_NA  = re.compile(r"^\s*;\(neverallow\s+sepinject_aux")
RE_ACTIVE_AUX_NA     = re.compile(r"^\(neverallow\s+sepinject_aux")

def is_sepinject_cruft(line: str) -> bool:
    return bool(
        RE_SEPINJECT_ANNOT.match(line)
        or RE_COMMENTED_ORIG_NA.match(line)
        or RE_COMMENTED_DUP_NA.match(line)
    )

def paren_balanced(s: str) -> bool:
    depth = 0
    inq = False
    for ch in s:
        if ch == '"':
            inq = not inq
        elif not inq:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    return False
    return depth == 0 and not inq

# ---- statement parsing -----------------------------------------------------

RE_KEYWORD = re.compile(r"^\(\s*([a-z_]+)\b")
RE_ALLOWLIKE = re.compile(
    r"^\(\s*(?:allow|dontaudit|auditallow|neverallow|typetransition)\s+([A-Za-z0-9_]+)"
)
RE_TYPE = re.compile(r"^\(\s*type\s+([A-Za-z0-9_]+)\s*\)\s*$")
RE_ROLETYPE = re.compile(r"^\(\s*roletype\s+[A-Za-z0-9_]+\s+([A-Za-z0-9_]+)\s*\)\s*$")
RE_TYPEPERM = re.compile(r"^\(\s*typepermissive\s+([A-Za-z0-9_]+)\s*\)\s*$")
RE_TYPEATTR = re.compile(r"^\(\s*typeattribute\s+([A-Za-z0-9_]+)\s*\)\s*$")
RE_TASET = re.compile(r"^\(\s*typeattributeset\s+([A-Za-z0-9_]+)\s+(.*)\)\s*$")
RE_TASET_SINGLE = re.compile(r"^\(\s*([A-Za-z0-9_]+)\s*\)$")
RE_ALLOW_TGTCLS = re.compile(
    r"^\(\s*(?:allow|dontaudit|auditallow)\s+[A-Za-z0-9_]+\s+([A-Za-z0-9_]+)\s+\(\s*([A-Za-z0-9_]+)"
)

def keyword(line: str):
    m = RE_KEYWORD.match(line)
    return m.group(1) if m else None


class Stmt:
    __slots__ = ("raw", "kw", "subject", "attr", "member")

    def __init__(self, raw):
        self.raw = norm(raw)
        self.kw = keyword(self.raw)
        self.subject = None   
        self.attr = None      
        self.member = None     
        self._classify()

    def _classify(self):
        kw = self.kw
        r = self.raw
        if kw in ("allow", "dontaudit", "auditallow", "typetransition", "neverallow"):
            m = RE_ALLOWLIKE.match(r)
            self.subject = m.group(1) if m else None
        elif kw == "type":
            m = RE_TYPE.match(r)
            self.subject = m.group(1) if m else None
        elif kw == "roletype":
            m = RE_ROLETYPE.match(r)
            self.subject = m.group(1) if m else None
        elif kw == "typepermissive":
            m = RE_TYPEPERM.match(r)
            self.subject = m.group(1) if m else None
        elif kw == "typeattribute":
            m = RE_TYPEATTR.match(r)
            self.subject = m.group(1) if m else None
        elif kw == "typeattributeset":
            m = RE_TASET.match(r)
            if m:
                self.attr = m.group(1)
                rest = m.group(2).strip()
                sm = RE_TASET_SINGLE.match(rest)
                if sm:
                    self.member = sm.group(1)
                    self.subject = sm.group(1)
        elif kw == "genfscon":
            self.subject = None 

    def allow_sortkey(self):
        m = RE_ALLOW_TGTCLS.match(self.raw)
        if m:
            return (m.group(1), m.group(2), self.raw)
        return ("", "", self.raw)


# ---- region processing -----------------------------------------------------

def process_above(above_lines, relocate):
    """Return (kept_lines, relocated_neverallow_raws)."""
    kept = []
    relocated = []
    for line in above_lines:
        if is_sepinject_cruft(line):
            continue
        if relocate and RE_ACTIVE_AUX_NA.match(line):
            relocated.append(norm(line))
            continue
        kept.append(line)
    return kept, relocated


def build_below(below_lines, relocated):
    """Parse, categorize, and re-render the mods region. Returns list of
    output lines (no trailing newlines)."""
    stmts = [Stmt(l) for l in below_lines if is_active(l)]

    # --- sanity: every active statement must be single-line & balanced ---
    for s in stmts:
        if not paren_balanced(s.raw):
            raise AssertionError(f"unbalanced parens in below stmt: {s.raw}")
        if s.kw is None:
            raise AssertionError(f"could not read keyword: {s.raw}")

    # --- determine domains ---
    sources = set()
    for s in stmts:
        if s.kw in ("allow", "dontaudit", "auditallow", "typetransition") and s.subject:
            sources.add(s.subject)
    domain_members = set()
    for s in stmts:
        if s.kw == "typeattributeset" and s.attr == "domain" and s.member:
            domain_members.add(s.member)
    domains = sources | domain_members

    declared_types = {s.subject for s in stmts if s.kw == "type" and s.subject}
    new_domains = sorted(d for d in domains if d in declared_types)
    base_domains = sorted(d for d in domains if d not in declared_types)

    def owner_of(objtype):
        cands = [d for d in domains if objtype.startswith(d + "_")]
        return max(cands, key=len) if cands else None

    domain_bucket = defaultdict(list)   
    global_bucket = []                  
    typeperms = []                      
    aux = OrderedDict()             

    def aux_slot(name):
        if name not in aux:
            aux[name] = {"attr": None, "set": None}
        return aux[name]

    for s in stmts:
        if s.kw == "typepermissive":
            typeperms.append(s)
        elif s.kw == "typeattribute" and s.subject and s.subject.startswith("sepinject_aux"):
            aux_slot(s.subject)["attr"] = s
        elif s.kw == "typeattributeset" and s.attr and s.attr.startswith("sepinject_aux"):
            aux_slot(s.attr)["set"] = s
        elif s.kw == "genfscon":
            global_bucket.append(s)
        elif s.kw in ("allow", "dontaudit", "auditallow", "typetransition"):
            domain_bucket[s.subject].append(s)
        else:
            subj = s.subject
            if subj is None:
                global_bucket.append(s)          
            elif subj in domains:
                domain_bucket[subj].append(s)
            else:
                owner = owner_of(subj)
                if owner:
                    domain_bucket[owner].append(s)
                else:
                    global_bucket.append(s)

    # --- renderers ---
    out = []

    def hdr(title):
        out.append(";")
        out.append("; " + "=" * 58)
        out.append(";  " + title)
        out.append("; " + "=" * 58)
        out.append(";")

    def render_type_decls_for(subj, bucket):
        """Emit (type)/(roletype)/(memberships) for a single type `subj`
        found in bucket, in a stable order. Returns list of used Stmts."""
        used = []
        t = [s for s in bucket if s.kw == "type" and s.subject == subj]
        rt = [s for s in bucket if s.kw == "roletype" and s.subject == subj]
        mem = [s for s in bucket
               if s.kw == "typeattributeset" and s.member == subj]
        for s in t:
            out.append(s.raw); used.append(s)
        for s in rt:
            out.append(s.raw); used.append(s)
        for s in sorted(mem, key=lambda x: (x.attr, x.raw)):
            out.append(s.raw); used.append(s)
        return used

    def render_domain_block(dom):
        bucket = domain_bucket[dom]
        hdr(f"domain: {dom}")
        rendered = set()

        for s in render_type_decls_for(dom, bucket):
            rendered.add(id(s))

        owned_objs = sorted({
            s.subject for s in bucket
            if s.subject and s.subject != dom
            and s.kw in ("type", "roletype")
            or (s.kw == "typeattributeset" and s.member and s.member != dom
                and s.member is not None)
        })
        owned_objs = sorted({
            s.subject for s in bucket
            if s.kw in ("type", "roletype") and s.subject and s.subject != dom
        } | {
            s.member for s in bucket
            if s.kw == "typeattributeset" and s.member and s.member != dom
        })
        for obj in owned_objs:
            for s in render_type_decls_for(obj, bucket):
                rendered.add(id(s))

        tts = sorted([s for s in bucket if s.kw == "typetransition"],
                     key=lambda x: x.raw)
        if tts:
            for s in tts:
                out.append(s.raw); rendered.add(id(s))

        allows = sorted([s for s in bucket if s.kw in ("allow", "auditallow")],
                        key=lambda x: x.allow_sortkey())
        for s in allows:
            out.append(s.raw); rendered.add(id(s))

        das = sorted([s for s in bucket if s.kw == "dontaudit"],
                     key=lambda x: x.allow_sortkey())
        for s in das:
            out.append(s.raw); rendered.add(id(s))

        for s in bucket:
            if id(s) not in rendered:
                out.append(s.raw); rendered.add(id(s))

        out.append("")

    out.append("; ~~~ mods region cleaned & regrouped by clean_cil.py ~~~")
    out.append("")

    if new_domains:
        hdr("NEW DOMAINS (declared in mods)")
        out.append("")
        for dom in new_domains:
            render_domain_block(dom)

    if base_domains:
        hdr("EXTENDED BASE DOMAINS (rules added to stock domains)")
        out.append("")
        for dom in base_domains:
            render_domain_block(dom)

    if global_bucket:
        hdr("GLOBAL DECLARATIONS (object types w/o domain owner + genfscon)")
        objs = sorted({s.subject for s in global_bucket
                       if s.kw in ("type", "roletype")} |
                      {s.member for s in global_bucket
                       if s.kw == "typeattributeset" and s.member})
        rendered = set()
        for obj in objs:
            for s in global_bucket:
                if id(s) in rendered:
                    continue
                if (s.kw == "type" and s.subject == obj) or \
                   (s.kw == "roletype" and s.subject == obj):
                    out.append(s.raw); rendered.add(id(s))
            mem = sorted([s for s in global_bucket
                          if s.kw == "typeattributeset" and s.member == obj],
                         key=lambda x: (x.attr, x.raw))
            for s in mem:
                out.append(s.raw); rendered.add(id(s))
        genfs = sorted([s for s in global_bucket if s.kw == "genfscon"],
                       key=lambda x: x.raw)
        if genfs:
            out.append("")
            for s in genfs:
                out.append(s.raw); rendered.add(id(s))
        for s in global_bucket:
            if id(s) not in rendered:
                out.append(s.raw); rendered.add(id(s))
        out.append("")

    if aux:
        hdr("NEVERALLOW-REWRITE AUXILIARY ATTRIBUTES")
        for name in sorted(aux):
            slot = aux[name]
            if slot["attr"] is None or slot["set"] is None:
                raise AssertionError(
                    f"aux attribute {name} missing its "
                    f"{'typeattribute' if slot['attr'] is None else 'typeattributeset'}")
            out.append(slot["attr"].raw)
            out.append(slot["set"].raw)
        out.append("")

        if relocated:
            hdr("REWRITTEN NEVERALLOWS (relocated from above BEGIN_MODS)")
            for raw in relocated:
                out.append(raw)
            out.append("")

    if typeperms:
        hdr("TYPEPERMISSIVE DOMAINS")
        for s in sorted(typeperms, key=lambda x: x.subject or x.raw):
            out.append(s.raw)
        out.append("")

    return out, stmts


# ---- validation ------------------------------------------------------------

def validate(above_in, above_out, below_in, below_out_lines,
             relocated, relocate):
    errors = []

    def active_norms(lines):
        return Counter(norm(l) for l in lines if is_active(l))

    for l in above_out:
        if is_sepinject_cruft(l):
            errors.append(f"cruft survived above: {l!r}")
    if relocate:
        for l in above_out:
            if RE_ACTIVE_AUX_NA.match(l):
                errors.append(f"relocated neverallow left above: {l!r}")

    ai = active_norms(above_in)
    ao = active_norms(above_out)
    rc = Counter(relocated)
    if relocate:
        if (ai - rc) != ao:
            errors.append("ABOVE active multiset changed unexpectedly "
                          "(after removing relocated neverallows)")
        if rc - ai:
            errors.append("relocated neverallows were not all present above")
    else:
        if ai != ao:
            errors.append("ABOVE active multiset changed")

    bi = active_norms(below_in)
    bo = active_norms(below_out_lines)
    expected = bi + (rc if relocate else Counter())
    if bo != expected:
        missing = expected - bo
        extra = bo - expected
        errors.append("BELOW active multiset mismatch")
        for k, v in list(missing.items())[:8]:
            errors.append(f"   MISSING x{v}: {k}")
        for k, v in list(extra.items())[:8]:
            errors.append(f"   EXTRA   x{v}: {k}")

    for l in below_out_lines:
        if is_active(l) and not paren_balanced(l):
            errors.append(f"emitted unbalanced line: {l!r}")

    return errors


# ---- main ------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Clean & regroup a sepinject CIL.")
    ap.add_argument("input", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=None,
                    help="write cleaned output here and do NOT rename input "
                         "(default: rename input to <input>.unclean and write "
                         "the cleaned result under the input's original name)")
    ap.add_argument("--relocate-neverallows", action="store_true",
                    help="pull active rewritten neverallows from above the "
                         "marker down into the mods region")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate and report, but write nothing")
    ap.add_argument("--force", action="store_true",
                    help="allow overwriting an existing <input>.unclean")
    args = ap.parse_args()

    src = args.input
    if not src.is_file():
        sys.exit(f"[!] not a file: {src}")

    text = src.read_text(errors="replace")
    lines = text.split("\n")
    mi = None
    for i, l in enumerate(lines):
        if MARKER_SUBSTR in l:
            mi = i
            break
    if mi is None:
        sys.exit(f"[!] marker '{MARKER_SUBSTR}' not found")

    above_in = lines[:mi]
    marker = lines[mi]
    below_in = lines[mi + 1:]

    above_out, relocated = process_above(above_in, args.relocate_neverallows)
    below_out, stmts = build_below(below_in, relocated)

    errors = validate(above_in, above_out, below_in, below_out,
                      relocated, args.relocate_neverallows)
    if errors:
        print("[FAILED] validation errors — nothing written:", file=sys.stderr)
        for e in errors:
            print("   " + e, file=sys.stderr)
        sys.exit(2)

    result = "\n".join(above_out + [marker, ""] + below_out)
    if not result.endswith("\n"):
        result += "\n"

    # ---- report ----
    kw_in = Counter(keyword(norm(l)) for l in below_in if is_active(l))
    print("[OK] validation passed")
    print(f"  above: {len(above_in)} -> {len(above_out)} lines "
          f"({len(above_in) - len(above_out)} sepinject comment lines stripped)")
    if args.relocate_neverallows:
        print(f"  relocated neverallows: {len(relocated)}")
    print(f"  below: {len(below_in)} -> {len(below_out)} lines")
    print("  below active statement counts (preserved):")
    for k in sorted(kw_in):
        print(f"     {k:16} {kw_in[k]}")

    if args.dry_run:
        print("[--] dry-run: no files written")
        return

    if args.output is not None:
        args.output.write_text(result)
        print(f"[OK] wrote cleaned output: {args.output}")
        return

    unclean = src.with_name(src.name + ".unclean")
    if unclean.exists() and not args.force:
        sys.exit(f"[!] {unclean} already exists — refusing to clobber the "
                 f"original. Use --force to override, or -o to write elsewhere.")
    src.rename(unclean)
    src.write_text(result)
    print(f"[OK] original preserved: {unclean}")
    print(f"[OK] cleaned output:     {src}")


if __name__ == "__main__":
    main()
