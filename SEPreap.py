#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEPreap.py — Reap Android SELinux AVC denials from logs into .te rules.

Feed it a dmesg dump, a logcat capture, an audit.log, or any mix of those
(files as positional args, or on stdin) and it will scrape every
`avc: denied` line, dedup them, merge permissions per (source, target,
class), group the resulting rules BY SOURCE DOMAIN, and print them
ready to paste — or pipe — into SEPinject's --te.

    adb shell dmesg | SEPreap --rom-root ./my_rom
    SEPreap dmesg.txt logcat.txt --rom-root ./my_rom -o new.te
    cat denials.txt | SEPreap | SEPinject --te /dev/stdin --rom-root ./my_rom

By default every denial becomes an `allow`.  Pass -d/--dontaudit to
classify known-noise denials (ART/JIT walking apex dirs, HeapTaskDaemon
poking around, statsd chatter, generic traversal) into `dontaudit`
rules instead, so you can silence log spam without granting anything.
The noise table is a plain list you fully control (see --dontaudit-rules).

When --rom-root is given, each denial's source and target types are
cross-checked against the ROM's actual CIL policy.  Types that don't
exist get a `# WARNING` annotation (typo, wrong build, or a type that
only exists because a domain ran permissive) — the rule is still emitted,
just flagged, exactly like SEPwalk annotates its suggestions.

--domain narrows a run to denials touching a given type in EITHER the
source or the target context.  It is repeatable and accepts globs:

    SEPreap dmesg.txt --domain attestmon --rom-root ./rom
    SEPreap dmesg.txt --domain 'hal_*' --domain vold

Use --domain-src / --domain-tgt when you specifically want to pin the
side.  ('self' rules are matched on their source, since that IS the
target at runtime.)

Neverallow / mlsconstrain conflicts are NOT resolved here — that is
SEPinject's job on inject.  SEPreap only turns denials into candidate
rules; you decide which to commit.  Redundancy against the existing
policy is SEPinject's job too.

Fits alongside SEPinject / SEPwalk / SEPsani / SEPclean / SEPcheck.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


# ----------------------------------------------------------------------------
# Default noise table (only consulted when -d/--dontaudit is set).
#
# Grammar, one rule per line (also the format accepted by --dontaudit-rules):
#     tclass:perm              dir:search
#     ttype/tclass:perm        apex_art_data_file/dir:search
#     *:perm                   *:getattr
#     ttype/*:*                proc_net/*:*
# A denial permission is noise if ANY rule matches it.  Matching is
# per-permission, so a single multi-perm denial can split across the
# allow and dontaudit sections of a domain.
#
# These are the classic audit2allow-overgeneration traps.  Edit freely —
# owning the table is the whole point of owning the tool.
# ----------------------------------------------------------------------------
DEFAULT_NOISE = """
apex_art_data_file/dir:search
apex_art_data_file/dir:getattr
apex_module_data_file/dir:search
apex_module_data_file/dir:getattr
user_profile_data_file/dir:search
user_profile_data_file/dir:getattr
user_profile_data_file/file:read
user_profile_data_file/file:getattr
system_data_file/lnk_file:read
system_data_file/lnk_file:getattr
statsdw_socket/sock_file:write
statsd/unix_dgram_socket:sendto
proc_net/*:*
sysfs/dir:search
cgroup/dir:search
cgroup_v2/dir:search
"""


# ----------------------------------------------------------------------------
# ROM-root policy discovery — matches SEPwalk / SEPinject conventions.
# ----------------------------------------------------------------------------
FILE_CONTEXTS_RELATIVE = [
    "system/fs_tree/system/etc/selinux",
    "vendor/fs_tree/etc/selinux",
    "system_ext/fs_tree/etc/selinux",
]

_VERSION_SUFFIX = re.compile(r"_\d+_\d+$")


def _strip_version(name: str) -> str:
    return _VERSION_SUFFIX.sub("", name)


def _iter_cil_statements(text: str) -> Iterable[str]:
    """Yield each top-level (...) statement from CIL text."""
    depth = 0
    start = -1
    for i, c in enumerate(text):
        if c == "(":
            if depth == 0:
                start = i
            depth += 1
        elif c == ")":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    yield text[start:i + 1]
                    start = -1


class PolicyDB:
    """Lightweight CIL type/attribute index (a trimmed SEPwalk PolicyDB)."""

    def __init__(self) -> None:
        self.types: Set[str] = set()
        self.attributes: Set[str] = set()

    def load(self, rom_root: Path, verbose: bool = False) -> List[Path]:
        files: List[Path] = []
        for rel in FILE_CONTEXTS_RELATIVE:
            d = rom_root / rel
            if not d.is_dir():
                continue
            for p in d.rglob("*.cil"):
                if p.is_file():
                    files.append(p)
        for path in files:
            self._load_one(path)
            if verbose:
                print(f"[*] indexed {path}", file=sys.stderr)
        return files

    def _load_one(self, path: Path) -> None:
        text = path.read_text(errors="replace")
        for stmt in _iter_cil_statements(text):
            s = stmt.strip()
            if s.startswith("(type "):
                m = re.match(r"\(type\s+([A-Za-z0-9_\-]+)\)$", s)
                if m:
                    self.types.add(_strip_version(m.group(1)))
            elif s.startswith("(typeattribute "):
                m = re.match(r"\(typeattribute\s+([A-Za-z0-9_\-]+)\)$", s)
                if m:
                    self.attributes.add(_strip_version(m.group(1)))
            elif s.startswith("(typeattributeset "):
                m = re.match(
                    r"\(typeattributeset\s+([A-Za-z0-9_\-]+)\s+\((.*)\)\)$",
                    s, re.DOTALL)
                if m:
                    self.attributes.add(_strip_version(m.group(1)))
                    for member in m.group(2).split():
                        if member.startswith("(") or member.startswith(")"):
                            continue
                        self.types.add(_strip_version(member))

    def known(self, name: str) -> bool:
        return name in self.types or name in self.attributes


# ----------------------------------------------------------------------------
# Denial parsing
# ----------------------------------------------------------------------------
_DENIED_RE = re.compile(r"avc:\s+denied\s+\{([^}]*)\}")
_KV_RE = re.compile(r"(scontext|tcontext|tclass|ioctlcmd)=(\S+)")
_PERMISSIVE_RE = re.compile(r"permissive=(\d)")


@dataclass
class Denial:
    src: str                 # source domain (scontext type)
    tgt: str                 # target type (tcontext type), or 'self'
    tclass: str
    perms: Set[str]
    permissive: bool
    cats: str                # scontext MLS categories, for optional comment
    ioctlcmds: Set[str] = field(default_factory=set)


def _ctx_type(ctx: str) -> Tuple[str, str]:
    """u:r:foo:s0:c1,c2 -> ('foo', 's0:c1,c2').  Returns (type, categories)."""
    parts = ctx.split(":")
    if len(parts) < 3:
        return ctx, ""
    typ = parts[2]
    cats = ":".join(parts[3:]) if len(parts) > 3 else ""
    return typ, cats


def parse_denials(lines: Iterable[str]) -> List[Denial]:
    out: List[Denial] = []
    for line in lines:
        dm = _DENIED_RE.search(line)
        if not dm:
            continue
        perms = set(dm.group(1).split())
        if not perms:
            continue

        fields: Dict[str, str] = {}
        for m in _KV_RE.finditer(line):
            fields.setdefault(m.group(1), m.group(2))

        sctx = fields.get("scontext")
        tctx = fields.get("tcontext")
        tclass = fields.get("tclass")
        if not (sctx and tctx and tclass):
            continue

        src, cats = _ctx_type(sctx)
        tgt, _ = _ctx_type(tctx)
        pm = _PERMISSIVE_RE.search(line)
        permissive = bool(pm and pm.group(1) == "1")

        ioctlcmds: Set[str] = set()
        if "ioctlcmd" in fields:
            ioctlcmds.add(fields["ioctlcmd"])

        out.append(Denial(
            src=src,
            tgt="self" if src == tgt else tgt,
            tclass=tclass,
            perms=perms,
            permissive=permissive,
            cats=cats,
            ioctlcmds=ioctlcmds,
        ))
    return out


# ----------------------------------------------------------------------------
# Noise classification
# ----------------------------------------------------------------------------
class NoiseTable:
    def __init__(self, text: str) -> None:
        self.rules: List[Tuple[str, str, str]] = []  # (ttype, tclass, perm)
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            lhs, _, rhs = line.partition(":")
            if "/" in lhs:
                nt, nc = lhs.split("/", 1)
            else:
                nt, nc = "*", lhs
            self.rules.append((nt.strip(), nc.strip(), rhs.strip()))

    def is_noise(self, tgt: str, tclass: str, perm: str) -> bool:
        for nt, nc, np in self.rules:
            if np != "*" and np != perm:
                continue
            if nt != "*" and nt != tgt:
                continue
            if nc != "*" and nc != tclass:
                continue
            return True
        return False


# ----------------------------------------------------------------------------
# Domain filtering
# ----------------------------------------------------------------------------
class DomainFilter:
    """Keep only denials touching one of the given types.

    `both`  — match the type in either the source or the target context
    `src`   — match only in the source (subject) context
    `tgt`   — match only in the target (object) context

    Patterns are fnmatch globs, so 'hal_*' works.  A 'self' target is
    resolved back to the source type before matching, since at runtime
    that IS the target.
    """

    def __init__(self, both: List[str], src: List[str],
                 tgt: List[str]) -> None:
        self.both = list(both or [])
        self.src = list(src or [])
        self.tgt = list(tgt or [])

    @property
    def active(self) -> bool:
        return bool(self.both or self.src or self.tgt)

    @staticmethod
    def _hit(pats: List[str], name: str) -> bool:
        return any(fnmatch(name, p) for p in pats)

    def matches(self, d: "Denial") -> bool:
        if not self.active:
            return True
        # 'self' means the target type is the source type.
        real_tgt = d.src if d.tgt == "self" else d.tgt
        if self.both and (self._hit(self.both, d.src)
                          or self._hit(self.both, real_tgt)):
            return True
        if self.src and self._hit(self.src, d.src):
            return True
        if self.tgt and self._hit(self.tgt, real_tgt):
            return True
        return False

    def describe(self) -> str:
        bits = []
        if self.both:
            bits.append("either=" + ",".join(self.both))
        if self.src:
            bits.append("src=" + ",".join(self.src))
        if self.tgt:
            bits.append("tgt=" + ",".join(self.tgt))
        return "  ".join(bits)


# ----------------------------------------------------------------------------
# Rule aggregation
# ----------------------------------------------------------------------------
@dataclass
class Rule:
    verb: str                # 'allow' or 'dontaudit'
    src: str
    tgt: str
    tclass: str
    perms: Set[str] = field(default_factory=set)
    permissive_only: bool = True   # every contributing denial was permissive
    cats: str = ""
    ioctlcmds: Set[str] = field(default_factory=set)


def build_rules(denials: List[Denial], noise: Optional[NoiseTable]
                ) -> Dict[str, List[Rule]]:
    """Return {domain: [Rule, ...]} with perms merged per (verb,tgt,class)."""
    # key -> Rule
    table: Dict[Tuple[str, str, str, str], Rule] = {}
    for d in denials:
        for perm in d.perms:
            verb = "allow"
            if noise is not None and noise.is_noise(d.tgt, d.tclass, perm):
                verb = "dontaudit"
            key = (verb, d.src, d.tgt, d.tclass)
            r = table.get(key)
            if r is None:
                r = Rule(verb=verb, src=d.src, tgt=d.tgt,
                         tclass=d.tclass, cats=d.cats)
                table[key] = r
            r.perms.add(perm)
            r.ioctlcmds |= d.ioctlcmds
            if not d.permissive:
                r.permissive_only = False

    by_domain: Dict[str, List[Rule]] = {}
    for r in table.values():
        by_domain.setdefault(r.src, []).append(r)
    return by_domain


# ----------------------------------------------------------------------------
# Emit
# ----------------------------------------------------------------------------
def _fmt_perms(perms: Set[str]) -> str:
    ps = sorted(perms)
    return ps[0] if len(ps) == 1 else "{ " + " ".join(ps) + " }"


def _rule_sort_key(r: Rule) -> Tuple[str, str, str]:
    return (r.tgt, r.tclass, min(r.perms))


def emit(by_domain: Dict[str, List[Rule]],
         pol: Optional[PolicyDB],
         emit_cil: bool,
         keep_cats: bool,
         dontaudit_enabled: bool,
         n_denials: int,
         n_total: int = -1,
         dfilter: "Optional[DomainFilter]" = None,
         out=sys.stdout) -> None:
    domains = sorted(by_domain)
    total_rules = sum(len(v) for v in by_domain.values())

    p = lambda *a: print(*a, file=out)
    p("# " + "=" * 72)
    p("# SEPreap — AVC denials reaped into .te rules")
    p("# " + "=" * 72)
    if dfilter is not None and dfilter.active and n_total >= 0:
        p(f"# denials parsed: {n_total}    matching filter: {n_denials}"
          f"    domains: {len(domains)}    rules: {total_rules}")
        p(f"# domain filter: {dfilter.describe()}")
    else:
        p(f"# denials parsed: {n_denials}    domains: {len(domains)}"
          f"    rules: {total_rules}")
    if not dontaudit_enabled:
        p("# mode: allow-only (pass -d to classify noise into dontaudit)")
    else:
        p("# mode: allow + dontaudit (noise table active)")
    if pol is None:
        p("# rom-root: not given — type existence NOT verified")
    else:
        p(f"# rom-root: {len(pol.types)} types / "
          f"{len(pol.attributes)} attributes indexed")
    p("#")
    p("# Each rule below is a CANDIDATE.  Review before committing.  Output")
    p("# is paste-ready for SEPinject --te (pipe or file).")
    p("")

    if not domains:
        if dfilter is not None and dfilter.active and n_total > 0:
            p(f"# (no denials matched the domain filter — "
              f"{n_total} denial(s) were parsed but filtered out)")
        else:
            p("# (no avc denials found in input)")
        return

    for dom in domains:
        rules = sorted(by_domain[dom], key=_rule_sort_key)
        allows = [r for r in rules if r.verb == "allow"]
        das = [r for r in rules if r.verb == "dontaudit"]

        p("# " + "-" * 70)
        header = f"# domain: {dom}"
        if pol is not None and not pol.known(dom):
            header += "   <-- NOT in ROM CIL (typo? wrong build? permissive-only?)"
        p(header)
        # Informational: did this domain only ever hit permissive denials?
        if allows and all(r.permissive_only for r in rules):
            p("#   (all denials were permissive=1 — logged, not blocked)")
        p("# " + "-" * 70)

        for r in _ordered(allows) + _ordered(das):
            _emit_one(r, pol, emit_cil, keep_cats, out)
        p("")


def _ordered(rules: List[Rule]) -> List[Rule]:
    return sorted(rules, key=_rule_sort_key)


def _emit_one(r: Rule, pol: Optional[PolicyDB], emit_cil: bool,
              keep_cats: bool, out) -> None:
    p = lambda *a: print(*a, file=out)

    # target existence annotation
    if pol is not None and r.tgt != "self" and not pol.known(r.tgt):
        p(f"#   WARNING: target type '{r.tgt}' not found in ROM CIL")
    if keep_cats and r.cats:
        p(f"#   scontext categories: {r.cats}")
    if "ioctl" in r.perms and r.ioctlcmds:
        cmds = " ".join(sorted(r.ioctlcmds))
        p(f"#   note: ioctl denial(s) carried ioctlcmd={cmds} — "
          f"add allowxperm manually if you want to scope it")

    perms = _fmt_perms(r.perms)
    p(f"{r.verb} {r.src} {r.tgt}:{r.tclass} {perms};")

    if emit_cil:
        ctgt = r.src if r.tgt == "self" else r.tgt
        cperms = " ".join(sorted(r.perms))
        p(f"({r.verb} {r.src} {ctgt} ({r.tclass} ({cperms})))")


# ----------------------------------------------------------------------------
# Input handling
# ----------------------------------------------------------------------------
def read_inputs(paths: List[str]) -> List[str]:
    lines: List[str] = []
    if not paths:
        lines.extend(sys.stdin.read().splitlines())
        return lines
    for pth in paths:
        if pth == "-":
            lines.extend(sys.stdin.read().splitlines())
            continue
        p = Path(pth)
        if not p.is_file():
            print(f"SEPreap: warning: not a file, skipping: {pth}",
                  file=sys.stderr)
            continue
        lines.extend(p.read_text(errors="replace").splitlines())
    return lines


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="SEPreap",
        description="Reap AVC denials from logs into .te rules, grouped by "
                    "domain, paste-ready for SEPinject.",
    )
    ap.add_argument("logs", nargs="*",
                    help="dmesg / logcat / audit.log files (default: stdin). "
                         "Use '-' for stdin explicitly.")
    ap.add_argument("--rom-root", type=Path, default=None,
                    help="Root of an extracted ROM (system/fs_tree/, "
                         "vendor/fs_tree/, system_ext/fs_tree/). When given, "
                         "source/target types are checked against the ROM CIL.")
    ap.add_argument("-d", "--dontaudit", action="store_true",
                    help="Classify noise-table denials into dontaudit rules "
                         "instead of allow. OFF by default.")
    ap.add_argument("-D", "--dontaudit-rules", metavar="FILE", default=None,
                    help="Extra noise rules appended to the built-in table "
                         "(one 'ttype/tclass:perm' per line). Implies -d.")
    ap.add_argument("--domain", action="append", metavar="TYPE", default=[],
                    help="Only reap denials where TYPE appears in EITHER the "
                         "source or target context. Repeatable; accepts globs "
                         "(e.g. --domain 'hal_*'). A 'self' target counts as "
                         "its source type.")
    ap.add_argument("--domain-src", action="append", metavar="TYPE", default=[],
                    help="Like --domain but pinned to the source (subject) "
                         "context only. Repeatable; accepts globs.")
    ap.add_argument("--domain-tgt", action="append", metavar="TYPE", default=[],
                    help="Like --domain but pinned to the target (object) "
                         "context only. Repeatable; accepts globs.")
    ap.add_argument("--cil", action="store_true",
                    help="Also emit a CIL form of each rule beneath the .te "
                         "line (for direct secilc / SEPclean workflows).")
    ap.add_argument("-k", "--keep-cats", action="store_true",
                    help="Annotate each rule with its scontext MLS categories.")
    ap.add_argument("-o", "--output", default=None,
                    help="Write report here instead of stdout.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Print progress to stderr.")
    args = ap.parse_args(argv)

    # rom-root validation (match SEPwalk's strictness only when supplied)
    pol: Optional[PolicyDB] = None
    if args.rom_root is not None:
        if not args.rom_root.is_dir():
            print(f"SEPreap: error: --rom-root not a directory: "
                  f"{args.rom_root}", file=sys.stderr)
            return 2
        pol = PolicyDB()
        cil = pol.load(args.rom_root, verbose=args.verbose)
        if not cil:
            print("SEPreap: warning: no .cil files found under --rom-root; "
                  "type checks disabled.", file=sys.stderr)
            pol = None

    # noise table
    dontaudit_enabled = args.dontaudit or bool(args.dontaudit_rules)
    noise: Optional[NoiseTable] = None
    if dontaudit_enabled:
        text = DEFAULT_NOISE
        if args.dontaudit_rules:
            f = Path(args.dontaudit_rules)
            if not f.is_file():
                print(f"SEPreap: error: cannot read --dontaudit-rules: "
                      f"{f}", file=sys.stderr)
                return 2
            text = text + "\n" + f.read_text(errors="replace")
        noise = NoiseTable(text)

    dfilter = DomainFilter(args.domain, args.domain_src, args.domain_tgt)

    lines = read_inputs(args.logs)
    denials = parse_denials(lines)
    n_total = len(denials)
    if args.verbose:
        print(f"[*] parsed {n_total} denial record(s) from "
              f"{len(lines)} line(s)", file=sys.stderr)

    if dfilter.active:
        denials = [d for d in denials if dfilter.matches(d)]
        if args.verbose:
            print(f"[*] domain filter ({dfilter.describe()}) kept "
                  f"{len(denials)}/{n_total} denial(s)", file=sys.stderr)
        # Warn if a filter pattern matched nothing at all — likely a typo.
        if pol is not None:
            for pat in args.domain + args.domain_src + args.domain_tgt:
                if not any(c in pat for c in "*?[") and not pol.known(pat):
                    print(f"SEPreap: warning: --domain '{pat}' is not a type "
                          f"in the ROM CIL", file=sys.stderr)

    by_domain = build_rules(denials, noise)

    out_stream = sys.stdout
    fh = None
    if args.output:
        fh = open(args.output, "w")
        out_stream = fh
    try:
        emit(by_domain, pol, args.cil, args.keep_cats,
             dontaudit_enabled, len(denials), n_total=n_total,
             dfilter=dfilter, out=out_stream)
    finally:
        if fh:
            fh.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
