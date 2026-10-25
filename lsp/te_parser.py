#!/usr/bin/env python3
"""
te_parser.py -- Parse .te files for LSP analysis.

Provides line-level structural parsing of Android SELinux .te files to
determine what kind of statement the cursor is in and what position within
that statement the cursor occupies. Used by the LSP server to decide what
kind of completions to offer.
"""

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


class StmtKind(Enum):
    """The kind of .te statement the cursor is in."""
    ALLOW = auto()
    AUDITALLOW = auto()
    DONTAUDIT = auto()
    NEVERALLOW = auto()
    TYPE_DECL = auto()           # type name [, attr ...] ;
    ATTRIBUTE_DECL = auto()      # attribute name ;
    TYPE_TRANSITION = auto()     # type_transition src tgt:cls default [name] ;
    TYPEATTRIBUTE = auto()       # typeattribute type attr [, attr ...] ;
    PERMISSIVE = auto()          # permissive type ;
    GENFSCON = auto()            # genfscon fs "/path" context ;
    MACRO_CALL = auto()          # init_daemon_domain(type) etc.
    REMOVE_RULE = auto()         # remove_allow, remove_type, etc.
    MLSTRUSTEDSUBJECT = auto()
    MLSTRUSTEDOBJECT = auto()
    COMMENT = auto()
    UNKNOWN = auto()


class CursorPos(Enum):
    """Where within a rule statement the cursor sits."""
    KEYWORD = auto()       # At the rule keyword itself
    SOURCE = auto()        # Source type/attribute slot
    TARGET = auto()        # Target type/attribute slot
    CLASS = auto()          # Object class slot (after colon)
    PERMISSION = auto()     # Permission set (inside braces)
    TYPE_NAME = auto()     # Type name in a type/attribute declaration
    ATTR_LIST = auto()     # Attribute list after type name
    FS_TYPE = auto()       # Filesystem type in genfscon
    PATH = auto()          # Path in genfscon
    CONTEXT = auto()       # Security context
    MACRO_NAME = auto()    # Macro function name
    MACRO_ARGS = auto()    # Inside macro arguments
    DEFAULT_TYPE = auto()  # Default type in type_transition
    UNKNOWN = auto()


@dataclass
class CursorContext:
    """Describes where the cursor is within a .te file."""
    stmt_kind: StmtKind
    cursor_pos: CursorPos
    # The partial text the user has typed at the cursor position (for filtering).
    prefix: str = ''
    # For permission context: which class is specified (if any).
    current_class: Optional[str] = None
    # For rules: the source type (if already specified).
    source_type: Optional[str] = None
    # For rules: the target type (if already specified).
    target_type: Optional[str] = None
    # Line number (0-based).
    line: int = 0
    # Character offset within the line.
    character: int = 0


# Rule keywords that take the standard src tgt:cls { perms } pattern.
_ACCESS_RULES = {
    'allow': StmtKind.ALLOW,
    'auditallow': StmtKind.AUDITALLOW,
    'dontaudit': StmtKind.DONTAUDIT,
    'neverallow': StmtKind.NEVERALLOW,
}

# Remove-prefixed variants.
_REMOVE_RULES = {
    'remove_allow', 'remove_auditallow', 'remove_dontaudit',
    'remove_type', 'remove_genfscon', 'remove_permissive',
    'remove_typeattribute', 'remove_mlstrustedsubject',
    'remove_mlstrustedobject',
}

# Known te_macros function names.
_TE_MACROS = {
    'init_daemon_domain', 'domain_auto_trans', 'domain_trans',
    'set_prop', 'get_prop', 'binder_use', 'binder_call',
    'binder_service', 'unix_socket_connect',
}


def _find_statement_start(lines: list[str], line_idx: int) -> int:
    """Walk backwards to find where the current statement begins.

    Statements end with ';' in .te files. Walk backwards until either
    a semicolon, the start of the file, or a blank line is found.
    """
    for i in range(line_idx - 1, -1, -1):
        stripped = lines[i].rstrip()
        if not stripped:
            return line_idx
        if stripped.endswith(';'):
            return i + 1
    return 0


def analyze_cursor(text: str, line: int, character: int) -> CursorContext:
    """Determine what kind of completion to offer at the given cursor position.

    Args:
        text: The full .te file content.
        line: 0-based line number.
        character: 0-based character offset within the line.

    Returns:
        A CursorContext describing the statement kind and cursor position.
    """
    lines = text.splitlines()
    if not lines:
        lines = ['']
    if line >= len(lines):
        return CursorContext(StmtKind.UNKNOWN, CursorPos.KEYWORD, line=line, character=character)

    current_line = lines[line]

    # Check if inside a comment.
    line_before_cursor = current_line[:character]
    if '#' in line_before_cursor:
        hash_pos = line_before_cursor.index('#')
        # Check that the # is not inside a string.
        if line_before_cursor[:hash_pos].count('"') % 2 == 0:
            return CursorContext(StmtKind.COMMENT, CursorPos.UNKNOWN, line=line, character=character)

    # Gather the full statement text from statement start to cursor.
    stmt_start = _find_statement_start(lines, line)
    stmt_lines = lines[stmt_start:line + 1]
    if stmt_lines:
        stmt_lines[-1] = stmt_lines[-1][:character]
    # Keep unstripped version for prefix extraction (trailing space matters).
    raw_stmt_text = ' '.join(stmt_lines)
    stmt_text = raw_stmt_text.strip()

    if not stmt_text:
        return CursorContext(StmtKind.UNKNOWN, CursorPos.KEYWORD, prefix='', line=line, character=character)

    # Extract the prefix: the partial word immediately before the cursor.
    # Use the raw (unstripped) text so a trailing space yields empty prefix.
    prefix_match = re.search(r'([A-Za-z_][\w]*)$', raw_stmt_text)
    prefix = prefix_match.group(1) if prefix_match else ''

    # Check for macro call: name(...)
    macro_match = re.match(r'([A-Za-z_]\w*)\s*\(', stmt_text)
    if macro_match and macro_match.group(1) in _TE_MACROS:
        if '(' in stmt_text and ')' not in stmt_text:
            return CursorContext(
                StmtKind.MACRO_CALL, CursorPos.MACRO_ARGS,
                prefix=prefix, line=line, character=character)
        return CursorContext(
            StmtKind.MACRO_CALL, CursorPos.MACRO_NAME,
            prefix=prefix, line=line, character=character)

    # Split statement into tokens for positional analysis.
    tokens = stmt_text.split()
    if not tokens:
        return CursorContext(StmtKind.UNKNOWN, CursorPos.KEYWORD, prefix=prefix,
                             line=line, character=character)

    keyword = tokens[0].lower()

    # Determine if the cursor is at a word boundary (trailing space/punctuation).
    ends_with_separator = bool(raw_stmt_text) and not raw_stmt_text[-1].isalnum() and raw_stmt_text[-1] != '_'

    # --- Access vector rules: allow src tgt:cls { perms }; ---
    if keyword in _ACCESS_RULES:
        stmt_kind = _ACCESS_RULES[keyword]
        return _analyze_access_rule(stmt_text, tokens, stmt_kind, prefix, line, character, ends_with_separator)

    # --- Remove rules ---
    if keyword in _REMOVE_RULES:
        base = keyword.replace('remove_', '')
        if base in _ACCESS_RULES:
            stmt_kind = StmtKind.REMOVE_RULE
            return _analyze_access_rule(stmt_text, tokens, stmt_kind, prefix, line, character, ends_with_separator)
        return CursorContext(StmtKind.REMOVE_RULE, CursorPos.TYPE_NAME,
                             prefix=prefix, line=line, character=character)

    # --- type declaration ---
    if keyword == 'type':
        if len(tokens) == 1:
            return CursorContext(StmtKind.TYPE_DECL, CursorPos.TYPE_NAME,
                                 prefix=prefix, line=line, character=character)
        # After the type name, we're in the attribute list.
        if ',' in stmt_text or len(tokens) > 2:
            return CursorContext(StmtKind.TYPE_DECL, CursorPos.ATTR_LIST,
                                 prefix=prefix, line=line, character=character)
        return CursorContext(StmtKind.TYPE_DECL, CursorPos.TYPE_NAME,
                             prefix=prefix, line=line, character=character)

    # --- attribute declaration ---
    if keyword == 'attribute':
        return CursorContext(StmtKind.ATTRIBUTE_DECL, CursorPos.TYPE_NAME,
                             prefix=prefix, line=line, character=character)

    # --- typeattribute ---
    if keyword == 'typeattribute':
        if len(tokens) <= 1:
            return CursorContext(StmtKind.TYPEATTRIBUTE, CursorPos.TYPE_NAME,
                                 prefix=prefix, line=line, character=character)
        if len(tokens) == 2 and not ends_with_separator:
            return CursorContext(StmtKind.TYPEATTRIBUTE, CursorPos.TYPE_NAME,
                                 prefix=prefix, line=line, character=character)
        return CursorContext(StmtKind.TYPEATTRIBUTE, CursorPos.ATTR_LIST,
                             prefix=prefix, line=line, character=character)

    # --- type_transition ---
    if keyword == 'type_transition':
        return _analyze_type_transition(tokens, prefix, line, character)

    # --- permissive ---
    if keyword == 'permissive':
        return CursorContext(StmtKind.PERMISSIVE, CursorPos.TYPE_NAME,
                             prefix=prefix, line=line, character=character)

    # --- genfscon ---
    if keyword == 'genfscon':
        if len(tokens) <= 1:
            return CursorContext(StmtKind.GENFSCON, CursorPos.FS_TYPE,
                                 prefix=prefix, line=line, character=character)
        if len(tokens) <= 2:
            return CursorContext(StmtKind.GENFSCON, CursorPos.PATH,
                                 prefix=prefix, line=line, character=character)
        return CursorContext(StmtKind.GENFSCON, CursorPos.CONTEXT,
                             prefix=prefix, line=line, character=character)

    # --- mlstrustedsubject / mlstrustedobject ---
    if keyword == 'mlstrustedsubject':
        return CursorContext(StmtKind.MLSTRUSTEDSUBJECT, CursorPos.TYPE_NAME,
                             prefix=prefix, line=line, character=character)
    if keyword == 'mlstrustedobject':
        return CursorContext(StmtKind.MLSTRUSTEDOBJECT, CursorPos.TYPE_NAME,
                             prefix=prefix, line=line, character=character)

    # If the first token looks like it could be a macro name...
    if re.match(r'^[A-Za-z_]\w*$', keyword) and '(' not in stmt_text:
        # Could be typing a keyword or macro name.
        return CursorContext(StmtKind.UNKNOWN, CursorPos.KEYWORD,
                             prefix=prefix, line=line, character=character)

    return CursorContext(StmtKind.UNKNOWN, CursorPos.UNKNOWN,
                         prefix=prefix, line=line, character=character)


def _analyze_access_rule(stmt_text: str, tokens: list[str], stmt_kind: StmtKind,
                         prefix: str, line: int, character: int,
                         ends_with_separator: bool = False) -> CursorContext:
    """Analyze cursor position within an access vector rule.

    Pattern: allow SOURCE TARGET:CLASS { PERMS };
    """
    source_type = None
    target_type = None
    current_class = None

    # Check if inside braces (permission set).
    brace_open = stmt_text.rfind('{')
    brace_close = stmt_text.rfind('}')
    if brace_open > -1 and (brace_close == -1 or brace_close < brace_open):
        # Inside the permission braces. Find the class.
        # The class comes right before the brace, after a colon.
        pre_brace = stmt_text[:brace_open].strip()
        colon_match = re.search(r':(\S+)\s*$', pre_brace)
        if colon_match:
            current_class = colon_match.group(1)
        # Extract source and target.
        parts = pre_brace.split()
        if len(parts) >= 2:
            source_type = parts[1]  # After keyword
        if len(parts) >= 3:
            tgt_cls = parts[2]
            if ':' in tgt_cls:
                target_type = tgt_cls.split(':')[0]
            else:
                target_type = tgt_cls

        return CursorContext(
            stmt_kind, CursorPos.PERMISSION, prefix=prefix,
            current_class=current_class, source_type=source_type,
            target_type=target_type, line=line, character=character)

    # Check if after a colon (class position).
    last_colon = stmt_text.rfind(':')
    if last_colon > -1:
        # After a colon, in class position.
        parts = stmt_text[:last_colon].split()
        if len(parts) >= 2:
            source_type = parts[1]
        if len(parts) >= 3:
            target_type = parts[2]
        return CursorContext(
            stmt_kind, CursorPos.CLASS, prefix=prefix,
            source_type=source_type, target_type=target_type,
            line=line, character=character)

    # Positional: keyword src tgt
    if len(tokens) <= 1:
        return CursorContext(stmt_kind, CursorPos.SOURCE, prefix=prefix,
                             line=line, character=character)
    if len(tokens) == 2:
        source_type = tokens[1]
        # If the cursor is past the end of the second token (trailing space),
        # the user has finished typing the source and is now at the target position.
        if ends_with_separator:
            return CursorContext(stmt_kind, CursorPos.TARGET, prefix='',
                                 source_type=source_type, line=line, character=character)
        return CursorContext(stmt_kind, CursorPos.SOURCE, prefix=prefix,
                             source_type=None, line=line, character=character)
    if len(tokens) >= 3:
        source_type = tokens[1]
        target_type = tokens[2]
        if ':' in target_type:
            target_type = target_type.split(':')[0]
        if ends_with_separator or ':' in tokens[-1]:
            return CursorContext(stmt_kind, CursorPos.CLASS, prefix=prefix,
                                 source_type=source_type, target_type=target_type,
                                 line=line, character=character)
        return CursorContext(stmt_kind, CursorPos.TARGET, prefix=prefix,
                             source_type=source_type, line=line, character=character)

    return CursorContext(stmt_kind, CursorPos.UNKNOWN, prefix=prefix,
                         line=line, character=character)


def _analyze_type_transition(tokens: list[str], prefix: str,
                             line: int, character: int) -> CursorContext:
    """Analyze cursor position within a type_transition rule.

    Pattern: type_transition SOURCE TARGET:CLASS DEFAULT ["name"];
    """
    if len(tokens) <= 1:
        return CursorContext(StmtKind.TYPE_TRANSITION, CursorPos.SOURCE,
                             prefix=prefix, line=line, character=character)
    if len(tokens) == 2:
        return CursorContext(StmtKind.TYPE_TRANSITION, CursorPos.TARGET,
                             prefix=prefix, line=line, character=character)
    if len(tokens) >= 3:
        # Check if we've passed the class.
        full = ' '.join(tokens)
        if ':' in full:
            colon_pos = full.index(':')
            after_colon = full[colon_pos + 1:].split()
            if len(after_colon) >= 2:
                return CursorContext(StmtKind.TYPE_TRANSITION, CursorPos.DEFAULT_TYPE,
                                     prefix=prefix, line=line, character=character)
            return CursorContext(StmtKind.TYPE_TRANSITION, CursorPos.CLASS,
                                 prefix=prefix, line=line, character=character)
        return CursorContext(StmtKind.TYPE_TRANSITION, CursorPos.TARGET,
                             prefix=prefix, line=line, character=character)

    return CursorContext(StmtKind.TYPE_TRANSITION, CursorPos.UNKNOWN,
                         prefix=prefix, line=line, character=character)


# ---------------------------------------------------------------------------
# Diagnostic helpers: parse a complete .te file and yield structured issues.
# ---------------------------------------------------------------------------

@dataclass
class TeIssue:
    """A problem found in a .te file."""
    line: int       # 0-based
    col: int        # 0-based
    end_col: int
    message: str
    severity: str   # 'error', 'warning', 'info', 'hint'


def check_te_syntax(text: str) -> list[TeIssue]:
    """Basic syntax checks on a .te file. Returns a list of issues."""
    issues = []
    lines = text.splitlines()
    in_brace = False
    brace_line = -1

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue

        # Check for unclosed braces.
        opens = line.count('{')
        closes = line.count('}')
        if opens > closes:
            if in_brace:
                issues.append(TeIssue(i, line.index('{'), line.index('{') + 1,
                                      'Nested braces not allowed in .te rules', 'error'))
            in_brace = True
            brace_line = i
        elif closes > opens:
            if not in_brace:
                issues.append(TeIssue(i, line.index('}'), line.index('}') + 1,
                                      'Closing brace without matching open brace', 'error'))
            in_brace = False

        # Check for missing semicolons on complete-looking statements.
        if not in_brace and not line.endswith(';') and not line.endswith('{'):
            # Could be a continuation line — only flag if it looks like a
            # complete statement (starts with a keyword).
            first_word = line.split()[0].rstrip('(') if line.split() else ''
            keywords = {'allow', 'auditallow', 'dontaudit', 'neverallow',
                        'type', 'attribute', 'typeattribute', 'type_transition',
                        'permissive', 'genfscon', 'mlstrustedsubject',
                        'mlstrustedobject'}
            keywords |= _REMOVE_RULES
            if first_word in keywords and '}' in line:
                issues.append(TeIssue(i, len(raw_line.rstrip()), len(raw_line.rstrip()) + 1,
                                      'Missing semicolon at end of statement', 'error'))

    if in_brace:
        issues.append(TeIssue(brace_line, 0, 1,
                              'Unclosed brace — no matching }', 'error'))

    return issues
