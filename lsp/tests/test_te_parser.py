"""Tests for te_parser cursor analysis and lexical syntax checks."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from te_parser import CursorPos, StmtKind, analyze_cursor, check_te_syntax  # noqa: E402


def ctx_at(line_text: str):
    """Analyze a single-line .te buffer with the cursor at end of line."""
    return analyze_cursor(line_text, 0, len(line_text))


def test_source_position():
    c = ctx_at('allow ')
    assert c.stmt_kind == StmtKind.ALLOW
    assert c.cursor_pos == CursorPos.SOURCE


def test_target_position():
    c = ctx_at('allow domain_a ')
    assert c.cursor_pos == CursorPos.TARGET
    assert c.source_type == 'domain_a'


def test_class_position():
    c = ctx_at('allow domain_a file_x:')
    assert c.cursor_pos == CursorPos.CLASS


def test_permission_position_knows_class():
    c = ctx_at('allow domain_a file_x:file { ')
    assert c.cursor_pos == CursorPos.PERMISSION
    assert c.current_class == 'file'


def test_prefix_extraction():
    c = ctx_at('allow dom')
    assert c.prefix == 'dom'
    assert c.cursor_pos == CursorPos.SOURCE


def test_comment_suppresses_completion():
    c = ctx_at('# allow something')
    assert c.stmt_kind == StmtKind.COMMENT


def test_type_declaration_name():
    c = ctx_at('type ')
    assert c.stmt_kind == StmtKind.TYPE_DECL
    assert c.cursor_pos == CursorPos.TYPE_NAME


def test_typeattribute_attr_list():
    c = ctx_at('typeattribute domain_a ')
    assert c.stmt_kind == StmtKind.TYPEATTRIBUTE
    assert c.cursor_pos == CursorPos.ATTR_LIST


def test_syntax_clean_rule_has_no_issues():
    issues = check_te_syntax('allow domain_a file_x:file { read write };\n')
    assert issues == []


def test_syntax_unclosed_brace_flagged():
    issues = check_te_syntax('allow domain_a file_x:file { read write\n')
    assert any('Unclosed brace' in i.message for i in issues)
