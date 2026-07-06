#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sepolwalker.py — Walk an Android SELinux policy to find prerequisite rules
for a desired .te file.

Given:
    --te FILE       A .te source file describing rules you want to add.
    --rom-root DIR  Root of an extracted ROM containing:
                        system/fs_tree/system/etc/selinux/
                        vendor/fs_tree/etc/selinux/
                        system_ext/fs_tree/etc/selinux/

the tool parses existing file_contexts, property_contexts, and CIL policy,
then for each allow rule in the .te:

  * If the target type labels a filesystem path, it finds where that type
    lives, walks every parent directory, looks up each parent's label, and
    emits the `search` (or `write add_name remove_name` when the rule
    creates/unlinks) permissions required to traverse the path.

  * If the target is a property_service, service_manager, or binder type,
    it suggests the usual companion rules (property_socket connect, init
    unix_stream_socket connectto, servicemanager binder call, etc.).

  * If the .te declares a new domain, it suggests the boilerplate the
    domain will need: an exec_type, a file_contexts entry, and an init
    transition (init_daemon_domain expansion).

Neverallow rules are ignored, by request.

Example:
    python sepolwalker.py --te mag_cal.te --rom-root ./my_rom
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


# ----------------------------------------------------------------------------
# te_macros: well-known macro expansions used by Android sepolicy.
# We only need to know *what classes & perms they imply* — not produce
# byte-for-byte equivalent output. These let us reason about a rule like
# `allow X foo_file:file rw_file_perms;` without having to invoke m4.
#
# Source of truth: AOSP system/sepolicy/public/te_macros
# ----------------------------------------------------------------------------
PERM_MACROS: Dict[str, Set[str]] = {
    # ---- file class -------------------------------------------------------
    "r_file_perms":      {"getattr", "open", "read", "ioctl", "lock", "map",
                          "watch", "watch_reads"},
    "w_file_perms":      {"open", "append", "write", "lock", "map"},
    "x_file_perms":      {"getattr", "execute", "execute_no_trans", "map"},
    "rx_file_perms":     {"getattr", "open", "read", "ioctl", "lock", "map",
                          "watch", "watch_reads",
                          "execute", "execute_no_trans"},
    "ra_file_perms":     {"getattr", "open", "read", "ioctl", "lock", "map",
                          "watch", "watch_reads", "append"},
    "rw_file_perms":     {"getattr", "open", "read", "ioctl", "lock", "map",
                          "watch", "watch_reads",
                          "append", "write"},
    "rwx_file_perms":    {"getattr", "open", "read", "ioctl", "lock", "map",
                          "watch", "watch_reads",
                          "append", "write",
                          "execute", "execute_no_trans"},
    "create_file_perms": {"getattr", "open", "read", "ioctl", "lock", "map",
                          "watch", "watch_reads",
                          "append", "write",
                          "create", "rename", "setattr", "unlink"},
    # ---- dir class --------------------------------------------------------
    "r_dir_perms":       {"open", "getattr", "read", "search", "ioctl",
                          "lock", "watch", "watch_reads"},
    "w_dir_perms":       {"open", "search", "write", "add_name", "remove_name",
                          "lock"},
    "ra_dir_perms":      {"open", "getattr", "read", "search", "ioctl",
                          "lock", "watch", "watch_reads",
                          "write", "add_name"},
    "rw_dir_perms":      {"open", "getattr", "read", "search", "ioctl",
                          "lock", "watch", "watch_reads",
                          "write", "add_name", "remove_name"},
    "create_dir_perms":  {"open", "getattr", "read", "search", "ioctl",
                          "lock", "watch", "watch_reads",
                          "write", "add_name", "remove_name",
                          "create", "reparent", "rename", "rmdir", "setattr"},
}

# Perms that imply "I am modifying the directory listing", so the parent
# dir of the target file needs add_name / remove_name not just search.
DIR_MUTATE_PERMS: Set[str] = {
    "create", "unlink", "rename", "link", "rmdir", "add_name", "remove_name",
}

# Permission sets that mean "I am only reading the file."  Used to decide
# whether we need write permission on intermediate dirs (we never do, but
# we do need add_name on the *immediate* parent when creating).
READ_ONLY_FILE_PERMS: Set[str] = {
    "getattr", "open", "read", "ioctl", "lock", "map",
    "watch", "watch_reads",
}


def expand_perms(tokens: Iterable[str]) -> Set[str]:
    """Expand permission tokens, resolving any *_perms macros."""
    out: Set[str] = set()
    for t in tokens:
        if t in PERM_MACROS:
            out |= PERM_MACROS[t]
        else:
            out.add(t)
    return out


# ----------------------------------------------------------------------------
# Data classes
# ----------------------------------------------------------------------------

@dataclass
class FileContext:
    """A single line from a *_file_contexts file or a genfscon stanza."""
    pattern: str            # raw pattern as written
    regex: re.Pattern       # compiled anchored regex
    type: str               # SELinux type
    source: str             # path of the file_contexts file
    is_genfscon: bool = False  # synthesised from a CIL genfscon entry
    _forced_dir_pattern: Optional[bool] = None  # override is_dir_pattern

    def matches(self, path: str) -> bool:
        return self.regex.fullmatch(path) is not None

    @property
    def is_dir_pattern(self) -> bool:
        """True if this pattern labels a directory tree (so the type can
        be a dir), False if it labels a single file path.

        '/mnt/vendor/nvcfg(/.*)?' → True (dir + everything inside)
        '/dev(/.*)?'              → True
        '/dev/null'               → False (one specific file)
        '/system/bin/sh'          → False
        """
        if self._forced_dir_pattern is not None:
            return self._forced_dir_pattern
        p = self.pattern.rstrip()
        # Common "directory-tree" suffixes
        if p.endswith("(/.*)?") or p.endswith("/.*") \
                or p.endswith("(/.*)") or p.endswith("(.*)?") \
                or p.endswith("(.*)") or p.endswith("/"):
            return True
        return False


@dataclass
class PropContext:
    """A single line from a *_property_contexts file."""
    prefix: str
    type: str
    source: str


@dataclass
class AllowRule:
    """An `allow s t:c { p... };` statement from a .te file."""
    source: str
    target: str
    classname: str
    perms: Set[str]
    raw: str                # original text, for echoing back


@dataclass
class TypeDecl:
    """A `type X, attr1, attr2;` statement from a .te file."""
    name: str
    attrs: List[str]


@dataclass
class MacroCall:
    """A macro invocation in a .te file, e.g. `init_daemon_domain(X)`."""
    name: str
    args: List[str]


@dataclass
class TypeTrans:
    """A `type_transition s t:c new;` statement."""
    source: str
    target: str
    classname: str
    new_type: str


@dataclass
class TEFile:
    types: List[TypeDecl] = field(default_factory=list)
    allows: List[AllowRule] = field(default_factory=list)
    macros: List[MacroCall] = field(default_factory=list)
    transitions: List[TypeTrans] = field(default_factory=list)
    # types declared in this .te (i.e. NEW to the policy)
    new_types: Set[str] = field(default_factory=set)

    def covers(self, source: str, target: str, classname: str,
               perms: Set[str]) -> bool:
        """True if an existing allow rule in this .te already grants
        (source, target, classname, perms-superset)."""
        for a in self.allows:
            if (a.source == source and a.target == target
                    and a.classname == classname
                    and perms.issubset(a.perms)):
                return True
        return False


# ----------------------------------------------------------------------------
# file_contexts loader
# ----------------------------------------------------------------------------

# Locations under --rom-root where file_contexts live (per the user's note).
FILE_CONTEXTS_RELATIVE = [
    "system/fs_tree/system/etc/selinux",
    "vendor/fs_tree/etc/selinux",
    "system_ext/fs_tree/etc/selinux",
]


def _fc_files(rom_root: Path) -> List[Path]:
    """Find every file_contexts-style file under the known locations."""
    found: List[Path] = []
    for rel in FILE_CONTEXTS_RELATIVE:
        d = rom_root / rel
        if not d.is_dir():
            continue
        for p in d.rglob("*"):
            if not p.is_file():
                continue
            name = p.name
            if name.endswith("_file_contexts") or name == "file_contexts":
                found.append(p)
    return found


def _prop_files(rom_root: Path) -> List[Path]:
    found: List[Path] = []
    for rel in FILE_CONTEXTS_RELATIVE:
        d = rom_root / rel
        if not d.is_dir():
            continue
        for p in d.rglob("*"):
            if p.is_file() and (p.name.endswith("_property_contexts")
                                or p.name == "property_contexts"):
                found.append(p)
    return found


def _service_files(rom_root: Path) -> List[Path]:
    found: List[Path] = []
    for rel in FILE_CONTEXTS_RELATIVE:
        d = rom_root / rel
        if not d.is_dir():
            continue
        for p in d.rglob("*"):
            if p.is_file() and (p.name.endswith("_service_contexts")
                                or p.name == "service_contexts"):
                found.append(p)
    return found


_CTX_TYPE_RE = re.compile(r"u:object_r:([A-Za-z0-9_\-]+):")


def _parse_fc_line(line: str) -> Optional[Tuple[str, str]]:
    """Return (pattern, type) for a file_contexts line, or None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Some lines have an optional type indicator (e.g. "--" for regular file):
    #   /vendor/bin/foo  --  u:object_r:foo_exec:s0
    # We tolerate that.
    parts = re.split(r"\s+", line)
    if len(parts) < 2:
        return None
    pattern = parts[0]
    # The context is the last token containing "u:object_r:".
    ctx = None
    for tok in reversed(parts[1:]):
        if "u:object_r:" in tok:
            ctx = tok
            break
    if ctx is None:
        return None
    m = _CTX_TYPE_RE.search(ctx)
    if not m:
        return None
    return pattern, m.group(1)


def _compile_fc_pattern(pat: str) -> Optional[re.Pattern]:
    """Compile a file_contexts pattern as an anchored regex.

    Android file_contexts patterns ARE regex (PCRE-ish).  Almost all of what
    we see in the wild is straight Python-compatible, so we just anchor it.
    """
    try:
        return re.compile(pat)
    except re.error:
        return None


# Standard mount points for genfscon-labelled filesystems.  genfscon
# entries inside a CIL file declare paths relative to the filesystem's
# root, so to turn them into something path-walkable we have to know
# where each fs is mounted.  These cover the synthetic kernel
# filesystems that have stable, well-known mount points; real
# filesystems (vfat, ext4, f2fs) are mounted at varying paths and are
# labelled via file_contexts / fs_use_*, not genfscon.
GENFS_MOUNTS: Dict[str, str] = {
    "proc":        "/proc",
    "sysfs":       "/sys",
    "cgroup":      "/sys/fs/cgroup",
    "cgroup2":     "/sys/fs/cgroup",
    "debugfs":     "/sys/kernel/debug",
    "tracefs":     "/sys/kernel/tracing",
    "selinuxfs":   "/sys/fs/selinux",
    "securityfs":  "/sys/kernel/security",
    "pstore":      "/sys/fs/pstore",
    "configfs":    "/config",
    "binder":      "/dev/binderfs",
    "binderfs":    "/dev/binderfs",
    "functionfs":  "/dev/usb-ffs/adb",
}


_GENFSCON_RE = re.compile(
    r'\(genfscon\s+([A-Za-z0-9_]+)\s+"([^"]*)"\s+'
    r'\(\s*\S+\s+\S+\s+([A-Za-z0-9_\-]+)\s+',
)


class FileContextDB:
    def __init__(self) -> None:
        self.contexts: List[FileContext] = []
        self._by_type: Dict[str, List[FileContext]] = {}

    def load(self, rom_root: Path) -> List[Path]:
        files = _fc_files(rom_root)
        for path in files:
            with path.open("r", errors="replace") as fh:
                for line in fh:
                    parsed = _parse_fc_line(line)
                    if not parsed:
                        continue
                    pattern, typ = parsed
                    rx = _compile_fc_pattern(pattern)
                    if rx is None:
                        continue
                    fc = FileContext(pattern=pattern, regex=rx, type=typ,
                                     source=str(path))
                    self.contexts.append(fc)
                    self._by_type.setdefault(typ, []).append(fc)
        return files

    def load_genfscon(self, rom_root: Path) -> int:
        """Read genfscon entries from every CIL file under the ROM and
        synthesise file_contexts-style patterns for them so path-walking
        works for /proc, /sys, /sys/fs/cgroup, etc.

        Returns the number of genfscon entries actually loaded.
        """
        cil_files: List[Path] = []
        for rel in FILE_CONTEXTS_RELATIVE:
            d = rom_root / rel
            if not d.is_dir():
                continue
            for p in d.rglob("*.cil"):
                if p.is_file():
                    cil_files.append(p)
        loaded = 0
        for path in cil_files:
            with path.open("r", errors="replace") as fh:
                for line in fh:
                    m = _GENFSCON_RE.search(line)
                    if not m:
                        continue
                    fs, sub, typ = m.group(1), m.group(2), m.group(3)
                    mount = GENFS_MOUNTS.get(fs)
                    if mount is None:
                        continue       # unknown filesystem — skip
                    # Build a path. genfscon "" / "/" both mean the fs root.
                    if sub in ("", "/"):
                        full = mount
                    else:
                        full = mount + ("" if sub.startswith("/") else "/") + sub
                    # Treat as a directory-tree pattern (most genfscon
                    # labels propagate down).  Escape regex metachars.
                    escaped = re.escape(full)
                    pattern = escaped + r"(/.*)?"
                    try:
                        rx = re.compile(pattern)
                    except re.error:
                        continue
                    typ_clean = _strip_version(typ)
                    fc = FileContext(pattern=pattern, regex=rx,
                                     type=typ_clean,
                                     source=f"{path}:genfscon",
                                     is_genfscon=True,
                                     _forced_dir_pattern=(sub in ("", "/")))
                    self.contexts.append(fc)
                    self._by_type.setdefault(typ_clean, []).append(fc)
                    loaded += 1
        return loaded

    def by_type(self, typ: str) -> List[FileContext]:
        return self._by_type.get(typ, [])

    def resolve_path(self, path: str) -> Optional[FileContext]:
        """Find the most-specific file_context for a literal path.

        SELinux semantics: longest pattern wins among matches.  We use the
        raw pattern's literal-prefix length as a proxy for specificity,
        with a small tie-breaker bump for genfscon entries (because the
        mount-point label in file_contexts is a placeholder; once the
        kernel mounts the filesystem on top, the genfscon label is what
        userspace actually sees at runtime).
        """
        best: Optional[FileContext] = None
        best_score = -1
        for fc in self.contexts:
            if not fc.matches(path):
                continue
            score = _literal_prefix_len(fc.pattern) * 2
            if fc.is_genfscon:
                score += 1
            if score > best_score:
                best, best_score = fc, score
        return best


def _literal_prefix_len(pattern: str) -> int:
    """How many leading characters are literal (no regex metachars)?"""
    meta = set(".^$*+?{}[]\\|()")
    n = 0
    for c in pattern:
        if c in meta:
            break
        n += 1
    return n


# ---- Concrete-path extraction from a regex pattern -------------------------

def extract_concrete_paths(pattern: str) -> List[str]:
    """Best-effort: turn a file_contexts regex into example concrete paths.

    Examples:
        /mnt/vendor/nvcfg(/.*)?       -> ["/mnt/vendor/nvcfg"]
        /(odm|vendor/odm)(/.*)?       -> ["/odm", "/vendor/odm"]
        /(vendor|system/vendor)/bin/sh -> ["/vendor/bin/sh", "/system/vendor/bin/sh"]
        /dev/block/by-name/nvcfg      -> ["/dev/block/by-name/nvcfg"]
    """
    p = pattern

    # Strip trailing "(/.*)?", "(/.*)" or "/.*"
    p = re.sub(r"\(\?:?/\.\*\)\??$", "", p)   # (?:/.*)?
    p = re.sub(r"\(/\.\*\)\??$", "", p)        # (/.*) or (/.*)?
    p = re.sub(r"/\.\*$", "", p)               # /.*
    p = re.sub(r"\(\.\*\)\??$", "", p)         # (.*) or (.*)?

    # Decode common backslash escapes (\. -> .)
    p = p.replace(r"\.", ".")
    # Word-boundary anchors are zero-width; drop them
    p = p.replace(r"\b", "")
    # [0-9]+ → "0"; [a-z]+ → "a"; etc.  Just pick something illustrative.
    p = re.sub(r"\[[^\]]+\]\+", "0", p)
    # [^/]+ → "X"
    p = p.replace("[^/]+", "X")
    # Single character class: [abc] -> a
    def _cc(m: re.Match) -> str:
        body = m.group(1)
        if body.startswith("^"):
            return "X"
        # take first non-range char
        return body[0] if body else ""
    p = re.sub(r"\[([^\]]+)\]", _cc, p)

    # Now expand any top-level alternations: /(a|b)/c  -> /a/c, /b/c
    return _expand_alts(p)


def _expand_alts(s: str) -> List[str]:
    """Expand top-level (a|b|c) alternations into multiple strings.

    Handles one level of nested parentheses well enough for AOSP patterns.
    """
    results = [""]
    i = 0
    while i < len(s):
        c = s[i]
        if c == "(":
            # Find matching close paren
            depth = 1
            j = i + 1
            while j < len(s) and depth > 0:
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                if depth == 0:
                    break
                j += 1
            if j >= len(s):
                # Unmatched: treat literally
                results = [r + c for r in results]
                i += 1
                continue
            inner = s[i + 1:j]
            # Strip a trailing "?" if present after the close paren
            optional = False
            after = j + 1
            if after < len(s) and s[after] == "?":
                optional = True
                after += 1
            # Split on top-level |
            alts = _split_top_level(inner, "|")
            # Recursively expand each alternative
            expanded_alts: List[str] = []
            for a in alts:
                expanded_alts.extend(_expand_alts(a))
            new_results: List[str] = []
            for r in results:
                if optional:
                    new_results.append(r)
                for a in expanded_alts:
                    new_results.append(r + a)
            results = new_results
            i = after
        else:
            results = [r + c for r in results]
            i += 1
    # De-dup and drop empties
    seen: Set[str] = set()
    out: List[str] = []
    for r in results:
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _split_top_level(s: str, sep: str) -> List[str]:
    """Split string on `sep` only at the top parenthesis depth."""
    parts: List[str] = []
    cur = []
    depth = 0
    for c in s:
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return parts


# ----------------------------------------------------------------------------
# property_contexts loader
# ----------------------------------------------------------------------------

class PropContextDB:
    def __init__(self) -> None:
        self.entries: List[PropContext] = []
        self._by_type: Dict[str, List[PropContext]] = {}

    def load(self, rom_root: Path) -> List[Path]:
        files = _prop_files(rom_root)
        for path in files:
            with path.open("r", errors="replace") as fh:
                for line in fh:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    parts = re.split(r"\s+", s, maxsplit=1)
                    if len(parts) < 2:
                        continue
                    prefix = parts[0]
                    m = _CTX_TYPE_RE.search(parts[1])
                    if not m:
                        continue
                    pc = PropContext(prefix=prefix, type=m.group(1),
                                     source=str(path))
                    self.entries.append(pc)
                    self._by_type.setdefault(m.group(1), []).append(pc)
        return files

    def by_type(self, typ: str) -> List[PropContext]:
        return self._by_type.get(typ, [])


# ----------------------------------------------------------------------------
# service_contexts loader (lightweight — used only to classify a type)
# ----------------------------------------------------------------------------

class ServiceContextDB:
    def __init__(self) -> None:
        self._types: Set[str] = set()

    def load(self, rom_root: Path) -> List[Path]:
        files = _service_files(rom_root)
        for path in files:
            with path.open("r", errors="replace") as fh:
                for line in fh:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    m = _CTX_TYPE_RE.search(s)
                    if m:
                        self._types.add(m.group(1))
        return files

    def has(self, typ: str) -> bool:
        return typ in self._types


# ----------------------------------------------------------------------------
# CIL policy loader (minimal — for type/attribute knowledge only)
# ----------------------------------------------------------------------------

# We strip the trailing "_NN_M" version suffix Android appends to platform
# types in the public/private split (e.g. "init_31_0" -> "init").
_VERSION_SUFFIX = re.compile(r"_\d+_\d+$")


def _strip_version(name: str) -> str:
    return _VERSION_SUFFIX.sub("", name)


class PolicyDB:
    def __init__(self) -> None:
        self.types: Set[str] = set()
        self.attributes: Set[str] = set()
        # type -> set of attributes it has
        self.type_attrs: Dict[str, Set[str]] = {}

    def load(self, rom_root: Path) -> List[Path]:
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
        return files

    def _load_one(self, path: Path) -> None:
        # We don't need a full CIL parser. We extract:
        #   (type NAME)
        #   (typeattribute NAME)
        #   (typeattributeset ATTR (T1 T2 ...))
        # Multi-line typeattributeset is handled by joining continuation
        # lines until parens balance.
        text = path.read_text(errors="replace")
        for stmt in _iter_cil_statements(text):
            stripped = stmt.strip()
            if stripped.startswith("(type "):
                m = re.match(r"\(type\s+([A-Za-z0-9_\-]+)\)$", stripped)
                if m:
                    self.types.add(_strip_version(m.group(1)))
            elif stripped.startswith("(typeattribute "):
                m = re.match(r"\(typeattribute\s+([A-Za-z0-9_\-]+)\)$",
                             stripped)
                if m:
                    self.attributes.add(_strip_version(m.group(1)))
            elif stripped.startswith("(typeattributeset "):
                m = re.match(
                    r"\(typeattributeset\s+([A-Za-z0-9_\-]+)\s+\((.*)\)\)$",
                    stripped, re.DOTALL)
                if m:
                    attr = _strip_version(m.group(1))
                    members = m.group(2).split()
                    self.attributes.add(attr)
                    for member in members:
                        if member.startswith("(") or member.startswith(")"):
                            continue
                        tname = _strip_version(member)
                        self.type_attrs.setdefault(tname, set()).add(attr)
                        # If a name appears as a member, it's a type
                        self.types.add(tname)

    def has_type(self, name: str) -> bool:
        return name in self.types or name in self.attributes

    def attrs_of(self, type_name: str) -> Set[str]:
        return self.type_attrs.get(type_name, set())


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
            depth -= 1
            if depth == 0 and start >= 0:
                yield text[start:i + 1]
                start = -1


# ----------------------------------------------------------------------------
# .te file parser
# ----------------------------------------------------------------------------

_IDENT = r"[A-Za-z_][A-Za-z0-9_\-]*"


def parse_te_file(path: Path) -> TEFile:
    raw = path.read_text(errors="replace")
    # Strip C-style and # comments
    raw = re.sub(r"/\*.*?\*/", "", raw, flags=re.DOTALL)
    cleaned_lines: List[str] = []
    for line in raw.splitlines():
        cleaned_lines.append(line.split("#", 1)[0])
    text = "\n".join(cleaned_lines)

    te = TEFile()

    # We split into statements.  An .te statement either ends with ';' (most
    # rules) or is a single-line macro call ending with ')' on its own line.
    # To handle both cleanly we split on ';' then also split each piece on
    # newlines to catch macro calls.
    segments: List[str] = []
    for chunk in text.split(";"):
        if not chunk.strip():
            continue
        # If the chunk has multiple non-blank lines and the last line looks
        # like a macro call, peel it off as its own segment.  Simpler: split
        # at every newline and keep non-empty trimmed lines.
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            segments.append(line)
        # Mark the final segment of this chunk as terminating with ';'
        # We treat all segments uniformly below.

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue

        # type X, attr1, attr2
        m = re.match(rf"^type\s+({_IDENT})\s*(?:,\s*(.+))?$", seg)
        if m:
            name = m.group(1)
            attrs_str = m.group(2) or ""
            attrs = [a.strip() for a in attrs_str.split(",") if a.strip()]
            te.types.append(TypeDecl(name=name, attrs=attrs))
            te.new_types.add(name)
            continue

        # typeattribute X attr
        m = re.match(rf"^typeattribute\s+({_IDENT})\s+({_IDENT})$", seg)
        if m:
            # Treat as adding an attribute to an existing type.
            for td in te.types:
                if td.name == m.group(1):
                    td.attrs.append(m.group(2))
                    break
            else:
                te.types.append(TypeDecl(name=m.group(1),
                                         attrs=[m.group(2)]))
                te.new_types.add(m.group(1))
            continue

        # allow s t:c { p1 p2 }    or    allow s t:c p1
        m = re.match(
            rf"^(?:allow|dontaudit|auditallow)\s+({_IDENT})\s+({_IDENT})\s*:\s*({_IDENT})\s+(.+)$",
            seg)
        if m and seg.startswith("allow"):
            source, target, classname, perms_str = m.groups()
            perms = _parse_perms(perms_str)
            te.allows.append(AllowRule(source=source, target=target,
                                       classname=classname,
                                       perms=perms, raw=seg))
            continue
        # Skip dontaudit/auditallow silently
        if m:
            continue

        # neverallow ... — ignored by request
        if seg.startswith("neverallow"):
            continue

        # type_transition s t:c new
        m = re.match(
            rf"^type_transition\s+({_IDENT})\s+({_IDENT})\s*:\s*({_IDENT})\s+({_IDENT})$",
            seg)
        if m:
            te.transitions.append(TypeTrans(
                source=m.group(1), target=m.group(2),
                classname=m.group(3), new_type=m.group(4)))
            continue

        # Macro call:   name(arg1, arg2)
        m = re.match(rf"^({_IDENT})\(\s*(.*?)\s*\)$", seg)
        if m:
            name = m.group(1)
            args = [a.strip() for a in m.group(2).split(",") if a.strip()]
            te.macros.append(MacroCall(name=name, args=args))
            continue

        # Unrecognized — silently skip (could be 'permissive', etc.)

    return te


def _parse_perms(s: str) -> Set[str]:
    s = s.strip()
    if s.startswith("{") and s.endswith("}"):
        s = s[1:-1]
    tokens = re.split(r"[\s,]+", s)
    tokens = [t for t in tokens if t]
    return expand_perms(tokens)


# ----------------------------------------------------------------------------
# Analyzer: produce suggestions
# ----------------------------------------------------------------------------

@dataclass
class Suggestion:
    """A single suggestion to print to the user."""
    section: str        # heading group where it FIRST surfaced
    rule: str           # the proposed .te line (or note)
    why: str            # explanation for the first emit
    also_for: List[str] = field(default_factory=list)  # additional sections
                                                       # that wanted the same
                                                       # rule


class Analyzer:
    def __init__(self, te: TEFile, fc: FileContextDB, pc: PropContextDB,
                 sc: ServiceContextDB, pol: PolicyDB) -> None:
        self.te = te
        self.fc = fc
        self.pc = pc
        self.sc = sc
        self.pol = pol
        self.suggestions: List[Suggestion] = []
        # Global dedup: rule text -> Suggestion (the first one created)
        self._by_rule: Dict[str, Suggestion] = {}

    def emit(self, section: str, rule: str, why: str) -> None:
        """Record a suggestion. Each unique rule is shown once, in the
        section where it was first needed; subsequent sections that want
        the same rule are appended to its `also_for` list.
        """
        existing = self._by_rule.get(rule)
        if existing is not None:
            if section != existing.section and section not in existing.also_for:
                existing.also_for.append(section)
            return
        s = Suggestion(section=section, rule=rule, why=why)
        self._by_rule[rule] = s
        self.suggestions.append(s)

    # ---- main entry ------------------------------------------------------
    def run(self) -> None:
        self._check_domain_setup()
        for rule in self.te.allows:
            self._check_allow(rule)
        self._check_transitions()
        self._check_macros()

    # ---- domain-transition implications ----------------------------------
    def _check_transitions(self) -> None:
        """For each `type_transition s exec:process new`, suggest the
        five 'domain_auto_trans' companion rules:

            allow s exec:file rx_file_perms;        # execute the binary
            allow s new:process transition;         # permission to transition
            allow new exec:file entrypoint+rx;      # entry on the new side
            allow new s:fd use;                     # inherit fds
            allow new s:fifo_file rw_perms;         # inherit stdio
        """
        for tt in self.te.transitions:
            if tt.classname != "process":
                continue
            src, exec_t, new_d = tt.source, tt.target, tt.new_type
            section = (f"Domain transition `{src}` → `{new_d}` via "
                       f"`{exec_t}`")

            # 1. src must be able to execute the exec_type
            if not self.te.covers(src, exec_t, "file",
                                  {"read", "execute", "open", "getattr",
                                   "map"}):
                self.emit(
                    section=section,
                    rule=f"allow {src} {exec_t}:file rx_file_perms;",
                    why=(f"`{src}` must read & execute the binary "
                         f"labelled `{exec_t}` to launch it."),
                )
            # 2. src must be allowed to transition to new domain
            if not self.te.covers(src, new_d, "process", {"transition"}):
                self.emit(
                    section=section,
                    rule=f"allow {src} {new_d}:process transition;",
                    why=(f"Without `process transition`, the kernel "
                         f"refuses the domain switch from `{src}` to "
                         f"`{new_d}`."),
                )
            # 3. new domain needs entrypoint on the exec
            if not self.te.covers(new_d, exec_t, "file", {"entrypoint"}):
                self.emit(
                    section=section,
                    rule=(f"allow {new_d} {exec_t}:file "
                          f"{{ entrypoint read execute open getattr map }};"),
                    why=(f"`{new_d}` enters its new domain via this exec; "
                         f"without `entrypoint`, the kernel falls back to "
                         f"src's domain."),
                )
            # 4. new domain inherits src's fds (commonly stdin/stdout/stderr)
            if not self.te.covers(new_d, src, "fd", {"use"}):
                self.emit(
                    section=section,
                    rule=f"allow {new_d} {src}:fd use;",
                    why=(f"After transitioning, `{new_d}` keeps the file "
                         f"descriptors it inherited from `{src}` — "
                         f"without `fd use`, every inherited fd becomes "
                         f"unusable."),
                )
            # 5. new domain reads/writes the pipes set up by src
            if not self.te.covers(new_d, src, "fifo_file",
                                  {"read", "write", "getattr"}):
                self.emit(
                    section=section,
                    rule=(f"allow {new_d} {src}:fifo_file "
                          f"{{ read write getattr }};"),
                    why=(f"stdio between `{src}` and `{new_d}` flows "
                         f"through pipes; the pipe still carries `{src}`'s "
                         f"label after the transition."),
                )
            # 6. src commonly wants to dontaudit noatsecure on new — this
            # isn't strictly necessary but is the canonical pattern.
            self.emit(
                section=section,
                rule=f"# dontaudit {src} {new_d}:process noatsecure;",
                why=("Bionic's secure-execve probe trips an audit unless "
                     "the parent is dontaudit'd here.  Optional but "
                     "expected."),
            )

    # ---- domain / new-type plumbing --------------------------------------
    def _check_domain_setup(self) -> None:
        # For each new type declared in the .te with `domain` attribute,
        # check if there's an exec_type & init transition story.
        for td in self.te.types:
            if "domain" not in td.attrs:
                continue
            domain = td.name
            # Is there already a *_exec type declared in this .te?
            exec_decls = [t for t in self.te.types
                          if "exec_type" in t.attrs]
            init_macro = any(m.name in ("init_daemon_domain",
                                        "domain_auto_trans",
                                        "domain_trans")
                             for m in self.te.macros
                             if domain in m.args)
            has_typetrans_from_init = any(
                tt.source in ("init",) and tt.new_type == domain
                for tt in self.te.transitions)

            # Pick the binary's likely install location based on the
            # exec_type's attributes.  The exec we suggest is named
            # `<domain>_exec` by convention.
            exec_attrs: Set[str] = set()
            for ed in exec_decls:
                if ed.name == f"{domain}_exec":
                    exec_attrs = set(ed.attrs)
                    break
            install_dir, fc_partition = _suggest_install_path(exec_attrs)

            if not exec_decls:
                self.emit(
                    section=f"Domain setup for `{domain}`",
                    rule=(f"type {domain}_exec, exec_type, "
                          f"vendor_file_type, file_type;"),
                    why=("A domain needs an exec_type so init can locate "
                         "and transition to it."),
                )
            if not init_macro and not has_typetrans_from_init:
                self.emit(
                    section=f"Domain setup for `{domain}`",
                    rule=f"init_daemon_domain({domain})",
                    why=("Sets up the init→domain transition, marks the "
                         "exec entrypoint, and grants the usual "
                         "domain_auto_trans permissions."),
                )
            self.emit(
                section=f"Domain setup for `{domain}`",
                rule=(f"# file_contexts entry (add to {fc_partition} "
                      f"file_contexts):\n"
                      f"# {install_dir}/{domain}    "
                      f"u:object_r:{domain}_exec:s0"),
                why=("init binds the binary to the exec_type via "
                     "file_contexts; without this entry, the executable "
                     "will be labelled with its default partition type "
                     "and the transition will fail."),
            )
            self.emit(
                section=f"Domain setup for `{domain}`",
                rule=(f"# init .rc snippet:\n"
                      f"# service {domain} {install_dir}/{domain}\n"
                      f"#     class core\n"
                      f"#     user system\n"
                      f"#     group system"),
                why="init needs an .rc service stanza or it won't be launched.",
            )

    # ---- per allow-rule analysis -----------------------------------------
    def _check_allow(self, rule: AllowRule) -> None:
        cls = rule.classname
        src = rule.source
        tgt = rule.target
        perms = rule.perms

        # `self` rules don't need path walking
        if tgt == "self":
            self._note_self_class(src, cls, perms)
            return

        # File / dir / lnk_file / fifo_file / sock_file / chr_file / blk_file
        if cls in ("file", "dir", "lnk_file", "fifo_file", "sock_file",
                   "chr_file", "blk_file"):
            self._walk_file_target(src, tgt, cls, perms)
            return

        # property_service set
        if cls == "property_service":
            self._note_property_set(src, tgt, perms)
            # Property access also requires reading the property file itself
            return

        # service_manager / hwservice_manager
        if cls in ("service_manager", "hwservice_manager",
                   "vndservice_manager"):
            self._note_service(src, tgt, cls, perms)
            return

        if cls == "binder":
            self._note_binder(src, tgt, perms)
            return

        if cls == "capability" or cls == "capability2":
            # capabilities are always on `self`; if not, just note it
            return

        if cls in ("unix_stream_socket", "unix_dgram_socket"):
            self._note_unix_socket(src, tgt, perms)
            return

        # Other classes (process, fd, fifo_file, etc.) — no path walking
        return

    # ---- file path walking (the core feature) ----------------------------
    def _walk_file_target(self, src: str, tgt: str, cls: str,
                          perms: Set[str]) -> None:
        """For a labelled file/dir type, find paths and walk parents."""
        fcs = self.fc.by_type(tgt)
        if not fcs:
            # Type isn't represented in file_contexts — probably a transient
            # type (e.g. tmpfs) or a non-fs type.  Nothing to walk.
            return

        # Decide whether this rule needs add_name/write on the parent dir.
        # That's the case if the rule creates/unlinks/renames a *file*
        # inside a dir of `tgt`'s type — but since this rule's target IS
        # tgt, we instead care about the immediate parent dirs.
        # Specifically: if cls == 'file' and perms include create/unlink
        # etc., the *immediate* parent dir needs add_name/remove_name in
        # addition to search.
        wants_mutate = bool(perms & DIR_MUTATE_PERMS) and cls != "dir"

        # We may have multiple file_contexts entries for the same type
        # (e.g. nvcfg_file exists at /mnt/vendor/nvcfg AND at /dev/block/...).
        # Walk each, but de-dup the resulting parent-dir rules at emit time.
        section = f"Path traversal for `{tgt}` (referenced by `{src}`)"
        for fc in fcs:
            paths = extract_concrete_paths(fc.pattern)
            for path in paths:
                self._walk_one_path(src, tgt, cls, path, wants_mutate,
                                    section, fc)

    def _walk_one_path(self, src: str, tgt: str, cls: str, path: str,
                       wants_mutate: bool, section: str,
                       fc: FileContext) -> None:
        # Decide where the "deepest dir labelled `tgt`" is.  This matters
        # because we may need to emit search/add_name on tgt:dir.
        #
        # If fc is a dir-tree pattern (ends with '(/.*)?', '/.*', etc.) then
        # `path` IS the deepest dir labelled `tgt` — its contents share the
        # same label.  We start walking from `path` itself.
        #
        # If fc is a single-file pattern (e.g. '/dev/null', '/system/bin/sh')
        # then `path` is a FILE, not a directory.  There is no `tgt:dir`,
        # so we do NOT emit a search-on-self rule; we walk from path's
        # PARENT.
        parents = _parent_chain(path)
        if not parents:
            return

        if fc.is_dir_pattern:
            # `path` is itself labelled `tgt` and is a directory.
            first_parent = parents[0]
            if wants_mutate:
                needed = {"search", "write", "add_name", "remove_name"}
                if not self.te.covers(src, tgt, "dir", needed):
                    self.emit(
                        section=section,
                        rule=(f"allow {src} {tgt}:dir "
                              f"{{ search write add_name remove_name }};"),
                        why=(f"`{src}` creates/unlinks/renames files of "
                             f"type `{tgt}`. The directory holding them "
                             f"({first_parent}, labelled `{tgt}`) needs "
                             f"add_name/remove_name in addition to "
                             f"search."),
                    )
            else:
                if not self.te.covers(src, tgt, "dir", {"search"}):
                    self.emit(
                        section=section,
                        rule=f"allow {src} {tgt}:dir search;",
                        why=(f"To open files of type `{tgt}` under "
                             f"{first_parent}, `{src}` must be able to "
                             f"search the enclosing directory (which is "
                             f"also labelled `{tgt}`)."),
                    )
            ancestors = parents[1:]
        else:
            # `path` is a specific file labelled `tgt`. The dir holding it
            # is NOT labelled `tgt` — we walk from path's parent.
            ancestors = parents[1:]

        # Walk *up* from the dir level: each ancestor needs search on
        # its own label.
        for ancestor in ancestors:
            label_fc = self.fc.resolve_path(ancestor)
            if not label_fc:
                # No label found — probably the rootfs catch-all or a path
                # like '/' itself.
                self.emit(
                    section=section,
                    rule=(f"# {ancestor}: no file_contexts entry found "
                          f"(likely rootfs); ensure `{src}` can search "
                          f"this path"),
                    why=f"Couldn't determine the label of {ancestor}.",
                )
                continue
            if self.te.covers(src, label_fc.type, "dir", {"search"}):
                continue
            self.emit(
                section=section,
                rule=f"allow {src} {label_fc.type}:dir search;",
                why=(f"To reach `{tgt}` at {path}, `{src}` must traverse "
                     f"{ancestor} (labelled `{label_fc.type}`)."),
            )

    # ---- companion-rule heuristics ---------------------------------------
    def _note_self_class(self, src: str, cls: str, perms: Set[str]) -> None:
        if cls in ("capability", "capability2"):
            # Capabilities are notable but don't require companion rules.
            return
        # Process-related self rules are usually fine on their own.

    def _note_property_set(self, src: str, tgt: str, perms: Set[str]) -> None:
        section = f"Property set: `{src}` → `{tgt}`"
        # set_prop(src, tgt) macro expands to roughly:
        #   allow src tgt:property_service set;
        #   allow src tgt:file r_file_perms;
        #   allow src property_socket:sock_file write;
        #   allow src init:unix_stream_socket connectto;
        # Several of these may already be in the user's .te; we emit all
        # so the user can pick.
        self.emit(section=section,
                  rule=f"allow {src} {tgt}:file r_file_perms;",
                  why=("init publishes property type info via files under "
                       "/dev/__properties__; the setter must read them to "
                       "discover the property's type."),)
        self.emit(section=section,
                  rule=f"allow {src} property_socket:sock_file write;",
                  why=("Setting a property is done by writing the request to "
                       "/dev/socket/property_service (labelled "
                       "property_socket)."),)
        self.emit(section=section,
                  rule=f"allow {src} init:unix_stream_socket connectto;",
                  why=("The property_service socket is owned by init; the "
                       "writer must be allowed to connect to init's "
                       "unix_stream_socket."),)
        self.emit(section=section,
                  rule=f"# Equivalent to: set_prop({src}, {tgt})",
                  why=("All three rules above are bundled by the standard "
                       "set_prop() macro."),)

    def _note_service(self, src: str, tgt: str, cls: str,
                      perms: Set[str]) -> None:
        section = f"Service `{tgt}` ({cls})"
        if "add" in perms:
            # The server side. Need binder transfer with servicemanager.
            self.emit(section=section,
                      rule=f"allow {src} servicemanager:binder transfer;",
                      why=("Registering a service requires a binder "
                           "transfer to servicemanager so it can hold the "
                           "service token."),)
            self.emit(section=section,
                      rule=("allow servicemanager " + src +
                            ":dir search;"),
                      why=("servicemanager opens /proc/<pid> to look up the "
                           "caller's SELinux context when add is called."),)
            self.emit(section=section,
                      rule=("allow servicemanager " + src +
                            ":file { read open };"),
                      why=("servicemanager reads /proc/<pid>/attr/current "
                           "to determine the caller's domain."),)
            self.emit(section=section,
                      rule=("allow servicemanager " + src +
                            ":process getattr;"),
                      why="servicemanager stat()s the caller's process.",)
        if "find" in perms:
            self.emit(section=section,
                      rule=f"allow {src} servicemanager:binder call;",
                      why=("Looking up a service involves a binder call to "
                           "servicemanager."),)

    def _note_binder(self, src: str, tgt: str, perms: Set[str]) -> None:
        section = f"Binder `{src}` ↔ `{tgt}`"
        if "call" in perms:
            self.emit(section=section,
                      rule=f"allow {tgt} {src}:binder transfer;",
                      why=("A binder call from `{0}` to `{1}` returns a "
                           "reply; `{1}` must be allowed to transfer the "
                           "reply binder back to `{0}`.").format(src, tgt),)
            self.emit(section=section,
                      rule=f"allow {tgt} {src}:fd use;",
                      why=("File descriptors passed across binder transfers "
                           "require `fd use` on the receiver side."),)

    def _note_unix_socket(self, src: str, tgt: str, perms: Set[str]) -> None:
        # Walking the path to the socket file (its sock_file label) is more
        # informative than commenting on the socket class itself; the
        # sock_file rule is what triggers the directory walk.
        return

    # ---- macro detection -------------------------------------------------
    def _check_macros(self) -> None:
        for m in self.te.macros:
            if m.name == "init_daemon_domain" and m.args:
                domain = m.args[0]
                exec_t = f"{domain}_exec"
                # Make sure exec_t is declared
                if not any(t.name == exec_t for t in self.te.types):
                    self.emit(
                        section=f"init_daemon_domain({domain})",
                        rule=(f"type {exec_t}, exec_type, file_type, "
                              f"vendor_file_type;"),
                        why=("init_daemon_domain expects an `<X>_exec` "
                             "type that labels the binary."),
                    )

            elif m.name == "set_prop" and len(m.args) >= 2:
                self._note_property_set(m.args[0], m.args[1], set())


def _suggest_install_path(exec_attrs: Set[str]) -> Tuple[str, str]:
    """Pick (install_dir, partition_name) from an exec_type's attributes.

    The 'system_file_type' / 'vendor_file_type' / 'system_ext_file_type'
    attributes on an exec_type are the canonical hint about which
    partition the binary lives on, which in turn dictates where
    file_contexts must label it.
    """
    if "vendor_file_type" in exec_attrs:
        return ("/vendor/bin", "vendor")
    if "system_ext_file_type" in exec_attrs:
        return ("/system_ext/bin", "system_ext")
    if "system_file_type" in exec_attrs:
        return ("/system/bin", "system (plat_file_contexts)")
    # Default — most third-party additions go to vendor
    return ("/vendor/bin", "vendor")


def _parent_chain(path: str) -> List[str]:
    """Return [path, parent, grandparent, ..., '/'] (no trailing duplicates).

    For input '/mnt/vendor/nvcfg', returns
    ['/mnt/vendor/nvcfg', '/mnt/vendor', '/mnt', '/'].
    """
    out: List[str] = []
    cur = path
    while True:
        if cur in out:
            break
        out.append(cur)
        if cur == "/" or cur == "":
            break
        parent = os.path.dirname(cur)
        if not parent:
            parent = "/"
        if parent == cur:
            break
        cur = parent
    return out


# ----------------------------------------------------------------------------
# Output formatting
# ----------------------------------------------------------------------------

def emit_report(suggestions: List[Suggestion], te: TEFile,
                fc: FileContextDB, pol: PolicyDB, out=sys.stdout) -> None:
    # Group by section, preserving insertion order
    sections: Dict[str, List[Suggestion]] = {}
    order: List[str] = []
    for s in suggestions:
        if s.section not in sections:
            sections[s.section] = []
            order.append(s.section)
        sections[s.section].append(s)

    print("# " + "=" * 72, file=out)
    print("# sepolwalker — prerequisite-rule report", file=out)
    print("# " + "=" * 72, file=out)
    print(f"# Types declared in your .te: "
          f"{', '.join(sorted(te.new_types)) or '(none)'}", file=out)
    n_allows = len(te.allows)
    n_macros = len(te.macros)
    print(f"# allow rules: {n_allows}    macro calls: {n_macros}", file=out)
    # Detect any referenced types that don't appear in the loaded policy
    referenced: Set[str] = set()
    for a in te.allows:
        if a.target != "self":
            referenced.add(a.target)
    unknown = sorted(t for t in referenced
                     if t not in te.new_types and not pol.has_type(t))
    if unknown:
        print(f"#", file=out)
        print(f"# WARNING: the following types are referenced in your .te "
              f"but were NOT", file=out)
        print(f"# found in the ROM's CIL policy — typos?  Or are they "
              f"from a", file=out)
        print(f"# different ROM build?", file=out)
        for u in unknown:
            print(f"#     {u}", file=out)
    print(f"#", file=out)
    print(f"# Below are rules the .te likely *also* needs.  Each is a",
          file=out)
    print(f"# suggestion — review each one before adding it to your .te.",
          file=out)
    print("", file=out)

    if not suggestions:
        print("# (no suggestions — your .te may already be complete, or it",
              file=out)
        print("#  doesn't reference any path-labelled types.)", file=out)
        return

    for sec in order:
        print(f"# {'-' * 70}", file=out)
        print(f"# {sec}", file=out)
        print(f"# {'-' * 70}", file=out)
        for s in sections[sec]:
            # wrap "why" to ~70 cols
            why = s.why.replace("\n", " ")
            wrapped = _wrap(why, 70, prefix="#   ")
            print(wrapped, file=out)
            if s.also_for:
                also = "; ".join(s.also_for)
                also_msg = f"Also required for: {also}."
                print(_wrap(also_msg, 70, prefix="#   "), file=out)
            print(s.rule, file=out)
            print("", file=out)


def _wrap(text: str, width: int, prefix: str = "") -> str:
    """Word-wrap `text` to `width` columns; each line begins with `prefix`."""
    words = text.split()
    if not words:
        return prefix.rstrip()
    lines: List[str] = []
    cur = prefix + words[0]
    for w in words[1:]:
        if len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = prefix + w
        else:
            cur += " " + w
    lines.append(cur)
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="sepolwalker",
        description="Walk an Android SELinux policy to find prerequisite "
                    "rules required to make a given .te file work.")
    ap.add_argument("--te", required=True, type=Path,
                    help="The .te source file describing the rules you want.")
    ap.add_argument("--rom-root", required=True, type=Path,
                    help="Root of an extracted ROM (must contain "
                         "system/fs_tree/, vendor/fs_tree/, "
                         "system_ext/fs_tree/).")
    ap.add_argument("-o", "--output", type=Path, default=None,
                    help="Write the report to this file instead of stdout.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Print extra progress info to stderr.")
    args = ap.parse_args(argv)

    if not args.te.is_file():
        print(f"error: --te file not found: {args.te}", file=sys.stderr)
        return 2
    if not args.rom_root.is_dir():
        print(f"error: --rom-root not a directory: {args.rom_root}",
              file=sys.stderr)
        return 2

    if args.verbose:
        print(f"[*] parsing TE file: {args.te}", file=sys.stderr)
    te = parse_te_file(args.te)
    if args.verbose:
        print(f"    {len(te.types)} type decls, {len(te.allows)} allows, "
              f"{len(te.macros)} macros, {len(te.transitions)} transitions",
              file=sys.stderr)

    fc = FileContextDB()
    pc = PropContextDB()
    sc = ServiceContextDB()
    pol = PolicyDB()

    if args.verbose:
        print(f"[*] loading file_contexts from {args.rom_root}",
              file=sys.stderr)
    fc_files = fc.load(args.rom_root)
    if args.verbose:
        for f in fc_files:
            print(f"    {f}", file=sys.stderr)
        print(f"    {len(fc.contexts)} file_contexts entries",
              file=sys.stderr)

    if args.verbose:
        print(f"[*] loading genfscon entries from CIL files",
              file=sys.stderr)
    n_gen = fc.load_genfscon(args.rom_root)
    if args.verbose:
        print(f"    {n_gen} genfscon entries", file=sys.stderr)

    if args.verbose:
        print(f"[*] loading property_contexts", file=sys.stderr)
    pc.load(args.rom_root)
    if args.verbose:
        print(f"    {len(pc.entries)} property_contexts entries",
              file=sys.stderr)

    if args.verbose:
        print(f"[*] loading service_contexts", file=sys.stderr)
    sc.load(args.rom_root)

    if args.verbose:
        print(f"[*] loading CIL policy", file=sys.stderr)
    pol_files = pol.load(args.rom_root)
    if args.verbose:
        for f in pol_files:
            print(f"    {f}", file=sys.stderr)
        print(f"    {len(pol.types)} types, {len(pol.attributes)} attributes",
              file=sys.stderr)

    if args.verbose:
        print(f"[*] analysing rules", file=sys.stderr)
    analyzer = Analyzer(te=te, fc=fc, pc=pc, sc=sc, pol=pol)
    analyzer.run()

    if args.output:
        with args.output.open("w") as fh:
            emit_report(analyzer.suggestions, te=te, fc=fc, pol=pol, out=fh)
        if args.verbose:
            print(f"[*] wrote {args.output}", file=sys.stderr)
    else:
        emit_report(analyzer.suggestions, te=te, fc=fc, pol=pol)

    return 0


if __name__ == "__main__":
    sys.exit(main())
