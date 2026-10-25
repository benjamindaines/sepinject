#!/usr/bin/env python3
"""
sepolicy_lsp.py -- SELinux .te file Language Server Protocol implementation.

Provides context-aware completions, diagnostics, and code actions for
Android SELinux .te policy files. Backed by a PolicyUniverse loaded from
the device's CIL policy files and sepinject's neverallow/mlsconstrain
resolution logic.

Usage:
    python sepolicy_lsp.py --rom-root /path/to/extracted/rom
    python sepolicy_lsp.py --cil /path/to/plat_sepolicy.cil [...]
    python sepolicy_lsp.py  # (configure via LSP initializationOptions)

Kate configuration (~/.config/kate/lspclient/settings.json):
    {
        "servers": {
            "te": {
                "command": ["python3", "/path/to/sepolicy_lsp.py", "--cil", "/path/to/plat_sepolicy.cil"],
                "highlightingModeRegex": "^(SELinux|te)$"
            }
        }
    }
"""

import argparse
import contextlib
import io
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlparse

from lsprotocol import types as lsp
from pygls.lsp.server import LanguageServer

from policy_universe import PolicyUniverse, load_from_cil_paths, load_from_rom
from session import GitomicSession, SessionConfig
from te_parser import (
    CursorPos,
    StmtKind,
    analyze_cursor,
    check_te_syntax,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename='/tmp/sepolicy-lsp.log',
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
log = logging.getLogger('sepolicy-lsp')

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

server = LanguageServer('sepolicy-lsp', 'v0.1.0',
                        text_document_sync_kind=lsp.TextDocumentSyncKind.Full)

# The loaded policy universe. Populated before server start or via initializationOptions.
_universe: Optional[PolicyUniverse] = None

# Path to sepinject.py for neverallow/mlsconstrain resolution.
_sepinject_path: Optional[Path] = None

# secilc binary path for compilation checks.
_secilc_path: Optional[str] = None

# Policy version passed to secilc (-c). Defaults to 30: the BenOS MediaTek target (MT6789/Helio G99) loads
# policy version 30, while secilc's own default is higher; a mismatch produces spurious failures.
_secilc_policyvers: int = 30

# CIL file paths loaded into the universe (for secilc and sepinject). Populated from --cil, or from the
# files discovered under --rom-root so neverallow/secilc features work in either launch mode.
_cil_paths: list[str] = []

# gitomic-backed editing session (one per server process). Configured in main() / on initialize.
_session: Optional[GitomicSession] = None


def _uri_to_path(uri: str) -> Optional[Path]:
    """Convert a file:// document URI to a local filesystem path, or None for a non-file URI."""
    parsed = urlparse(uri)
    if parsed.scheme != 'file':
        return None
    return Path(unquote(parsed.path))


def _notify(message: Optional[str], kind: lsp.MessageType = lsp.MessageType.Info) -> None:
    """Send a window/showMessage, tolerating a None/empty message."""
    if message:
        server.window_show_message(lsp.ShowMessageParams(type=kind, message=message))


def _find_secilc() -> Optional[str]:
    """Locate a secilc binary, preferring a bundled static build over the system one.

    Order: the SEPOLICY_LSP_SECILC environment variable, the bundled lsp/bin/secilc (a version-pinned static
    binary, immune to system libsepol drift), then PATH and standard locations. An explicit --secilc on the
    command line is honored earlier in main() and takes precedence over all of these.
    """
    import shutil
    env = os.environ.get('SEPOLICY_LSP_SECILC')
    if env and Path(env).is_file():
        return env
    bundled = Path(__file__).resolve().parent / 'bin' / 'secilc'
    if bundled.is_file() and os.access(bundled, os.X_OK):
        return str(bundled)
    found = shutil.which('secilc')
    if found:
        return found
    for candidate in ('/usr/bin/secilc', '/usr/local/bin/secilc'):
        if Path(candidate).is_file():
            return candidate
    return None


def _find_sepinject() -> Optional[Path]:
    """Locate sepinject.py by checking common paths."""
    candidates = [
        Path(__file__).parent / 'sepinject.py',
        Path(__file__).parent.parent / 'sepinject.py',
        Path(__file__).parent.parent / 'sepinject' / 'sepinject.py',
        Path.home() / 'sepinject' / 'sepinject.py',
        Path.home() / 'sepinject-checkout' / 'sepinject.py',
    ]
    env_path = os.environ.get('SEPINJECT_PATH')
    if env_path:
        candidates.insert(0, Path(env_path))
    for p in candidates:
        if p.is_file():
            return p
    return None


# Cached sepinject module handle. None before first attempt; False if an attempt failed.
_sepinject_mod = None


def _import_sepinject():
    """Import sepinject.py as a module and return it, or None if unavailable.

    sepinject is imported in-process (rather than shelled out to) because its neverallow logic is exposed as
    functions, not a CLI subcommand. Its module-level code is guarded by `if __name__ == '__main__'`, so the
    import has no side effects beyond defining functions and constants. Callers that invoke sepinject
    functions must still capture stdout/stderr: several parsing helpers print progress, which would corrupt
    the JSON-RPC stream in stdio mode.
    """
    global _sepinject_mod
    if _sepinject_mod is not None:
        return _sepinject_mod or None
    if _sepinject_path is None or not Path(_sepinject_path).is_file():
        _sepinject_mod = False
        return None
    import importlib.util
    try:
        sep_dir = str(Path(_sepinject_path).parent)
        if sep_dir not in sys.path:
            sys.path.insert(0, sep_dir)
        spec = importlib.util.spec_from_file_location('sepinject', str(_sepinject_path))
        mod = importlib.util.module_from_spec(spec)
        # Register before executing: sepinject defines dataclasses with string forward-reference annotations
        # (e.g. `rule: 'TeRule'`), and dataclass field-type resolution looks the module up in sys.modules by
        # name. Executing an unregistered module raises AttributeError from dataclasses._is_type.
        sys.modules['sepinject'] = mod
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            spec.loader.exec_module(mod)
        _sepinject_mod = mod
        return mod
    except Exception:
        log.exception('sepinject import failed')
        _sepinject_mod = False
        return None


# ---------------------------------------------------------------------------
# Initialization callback
# ---------------------------------------------------------------------------

@server.feature(lsp.INITIALIZED)
def on_initialized(params: lsp.InitializedParams):
    """Post-initialization setup: locate tools, load universe if not already loaded."""
    global _sepinject_path, _secilc_path

    # Autodetect only what was not already provided on the command line.
    if _secilc_path is None:
        _secilc_path = _find_secilc()
    if _sepinject_path is None:
        _sepinject_path = _find_sepinject()

    log.info('secilc: %s', _secilc_path)
    log.info('sepinject: %s', _sepinject_path)

    if _universe:
        log.info(
            'Universe loaded: %d types, %d attributes, %d classes',
            len(_universe.types), len(_universe.attributes), len(_universe.classes))
    else:
        log.warning('No policy universe loaded — completions will be limited')


# ---------------------------------------------------------------------------
# Document tracking
# ---------------------------------------------------------------------------

_documents: dict[str, str] = {}


@server.feature(lsp.TEXT_DOCUMENT_DID_OPEN)
def on_did_open(params: lsp.DidOpenTextDocumentParams):
    uri = params.text_document.uri
    _documents[uri] = params.text_document.text
    if _session is not None:
        _notify(_session.note_open(uri, _uri_to_path(uri)))
    _publish_diagnostics(uri, params.text_document.text)


@server.feature(lsp.TEXT_DOCUMENT_DID_CHANGE)
def on_did_change(params: lsp.DidChangeTextDocumentParams):
    uri = params.text_document.uri
    for change in params.content_changes:
        _documents[uri] = change.text
    _publish_diagnostics(uri, _documents.get(uri, ''))


@server.feature(lsp.TEXT_DOCUMENT_DID_SAVE)
def on_did_save(params: lsp.DidSaveTextDocumentParams):
    uri = params.text_document.uri
    text = params.text if params.text else _documents.get(uri, '')
    if params.text:
        _documents[uri] = text
    # A save is the point at which a real compilation check is worthwhile; keystroke-time checks stay
    # lexical to keep editing responsive.
    _publish_diagnostics(uri, text, run_compile=True)


@server.feature(lsp.TEXT_DOCUMENT_DID_CLOSE)
def on_did_close(params: lsp.DidCloseTextDocumentParams):
    uri = params.text_document.uri
    _documents.pop(uri, None)
    if _session is not None:
        _notify(_session.note_close(uri))
    server.text_document_publish_diagnostics(lsp.PublishDiagnosticsParams(
        uri=uri, diagnostics=[]))


@server.feature(lsp.SHUTDOWN)
def on_shutdown(*_args):
    """Stop the gitomic watcher on editor shutdown. The recorded commits are preserved; the batch is never
    finalized or discarded automatically."""
    if _session is not None:
        _notify(_session.shutdown())


# ---------------------------------------------------------------------------
# Completions
# ---------------------------------------------------------------------------

_KEYWORDS = [
    ('allow', 'Access vector allow rule'),
    ('auditallow', 'Audit matching access attempts'),
    ('dontaudit', 'Suppress audit for matching access'),
    ('neverallow', 'Compile-time policy constraint'),
    ('type', 'Declare a new type'),
    ('attribute', 'Declare a new attribute'),
    ('typeattribute', 'Assign a type to attributes'),
    ('type_transition', 'Automatic type transition'),
    ('permissive', 'Make a domain permissive'),
    ('genfscon', 'Filesystem context label'),
    ('mlstrustedsubject', 'MLS trusted subject'),
    ('mlstrustedobject', 'MLS trusted object'),
]


def _filter(items: list[lsp.CompletionItem], prefix: str) -> list[lsp.CompletionItem]:
    """Filter completion items by prefix, case-insensitive."""
    if not prefix:
        return items
    lower = prefix.lower()
    return [i for i in items if i.label.lower().startswith(lower)]


@server.feature(
    lsp.TEXT_DOCUMENT_COMPLETION,
    lsp.CompletionOptions(trigger_characters=[' ', ':', '{', '(', ','])
)
def on_completion(params: lsp.CompletionParams) -> lsp.CompletionList:
    uri = params.text_document.uri
    text = _documents.get(uri, '')
    line = params.position.line
    char = params.position.character

    ctx = analyze_cursor(text, line, char)
    items: list[lsp.CompletionItem] = []

    if ctx.stmt_kind == StmtKind.COMMENT:
        return lsp.CompletionList(is_incomplete=False, items=[])

    # --- Keyword position ---
    if ctx.cursor_pos == CursorPos.KEYWORD:
        for kw, doc in _KEYWORDS:
            items.append(lsp.CompletionItem(
                label=kw,
                kind=lsp.CompletionItemKind.Keyword,
                detail=doc,
                insert_text=kw + ' ',
            ))
        if _universe:
            for macro in _universe.te_macros:
                items.append(lsp.CompletionItem(
                    label=macro,
                    kind=lsp.CompletionItemKind.Function,
                    detail='TE macro',
                    insert_text=macro + '(',
                ))
        return lsp.CompletionList(is_incomplete=False, items=_filter(items, ctx.prefix))

    if not _universe:
        return lsp.CompletionList(is_incomplete=False, items=[])

    # --- Source / Target type position ---
    if ctx.cursor_pos in (CursorPos.SOURCE, CursorPos.TARGET):
        for name in sorted(_universe.types):
            attrs = _universe.attributes_for_type(name)
            detail = ', '.join(sorted(attrs)[:3])
            if len(attrs) > 3:
                detail += f' (+{len(attrs) - 3})'
            items.append(lsp.CompletionItem(
                label=name,
                kind=lsp.CompletionItemKind.Class,
                detail=detail or 'type',
                sort_text=f'0_{name}',
            ))
        for name in sorted(_universe.attributes):
            count = len(_universe.types_in_attribute(name))
            items.append(lsp.CompletionItem(
                label=name,
                kind=lsp.CompletionItemKind.Interface,
                detail=f'attribute ({count} types)',
                sort_text=f'1_{name}',
            ))
        if ctx.cursor_pos == CursorPos.TARGET:
            items.insert(0, lsp.CompletionItem(
                label='self',
                kind=lsp.CompletionItemKind.Keyword,
                detail='same as source type',
                sort_text='0__self',
            ))
        return lsp.CompletionList(is_incomplete=True, items=_filter(items, ctx.prefix))

    # --- Class position (after colon) ---
    if ctx.cursor_pos == CursorPos.CLASS:
        for name in sorted(_universe.classes):
            perms = _universe.permissions_for_class(name)
            items.append(lsp.CompletionItem(
                label=name,
                kind=lsp.CompletionItemKind.Enum,
                detail=f'{len(perms)} permissions',
            ))
        for macro, expansion in _universe.class_macros.items():
            items.append(lsp.CompletionItem(
                label=macro,
                kind=lsp.CompletionItemKind.Reference,
                detail=f'-> {expansion}',
            ))
        return lsp.CompletionList(is_incomplete=False, items=_filter(items, ctx.prefix))

    # --- Permission position (inside braces) ---
    if ctx.cursor_pos == CursorPos.PERMISSION:
        if ctx.current_class:
            perms = _universe.permissions_for_class(ctx.current_class)
            for p in sorted(perms):
                items.append(lsp.CompletionItem(
                    label=p,
                    kind=lsp.CompletionItemKind.Value,
                    detail=f'{ctx.current_class} permission',
                    sort_text=f'0_{p}',
                ))
        else:
            for p in sorted(_universe.all_permissions()):
                items.append(lsp.CompletionItem(
                    label=p,
                    kind=lsp.CompletionItemKind.Value,
                    sort_text=f'1_{p}',
                ))

        for macro, expansion in _universe.perm_macros.items():
            items.append(lsp.CompletionItem(
                label=macro,
                kind=lsp.CompletionItemKind.Reference,
                detail=f'-> {expansion}',
                sort_text=f'2_{macro}',
            ))
        return lsp.CompletionList(is_incomplete=False, items=_filter(items, ctx.prefix))

    # --- Type name in declarations ---
    if ctx.cursor_pos == CursorPos.TYPE_NAME:
        if ctx.stmt_kind in (StmtKind.TYPEATTRIBUTE, StmtKind.PERMISSIVE,
                             StmtKind.MLSTRUSTEDSUBJECT, StmtKind.MLSTRUSTEDOBJECT,
                             StmtKind.MACRO_CALL):
            for name in sorted(_universe.types):
                items.append(lsp.CompletionItem(
                    label=name,
                    kind=lsp.CompletionItemKind.Class,
                ))
        return lsp.CompletionList(is_incomplete=True, items=_filter(items, ctx.prefix))

    # --- Attribute list (in type or typeattribute declarations) ---
    if ctx.cursor_pos == CursorPos.ATTR_LIST:
        for name in sorted(_universe.attributes):
            count = len(_universe.types_in_attribute(name))
            items.append(lsp.CompletionItem(
                label=name,
                kind=lsp.CompletionItemKind.Interface,
                detail=f'attribute ({count} types)',
            ))
        return lsp.CompletionList(is_incomplete=False, items=_filter(items, ctx.prefix))

    # --- Macro arguments ---
    if ctx.cursor_pos == CursorPos.MACRO_ARGS:
        for name in sorted(_universe.types):
            items.append(lsp.CompletionItem(
                label=name,
                kind=lsp.CompletionItemKind.Class,
            ))
        return lsp.CompletionList(is_incomplete=True, items=_filter(items, ctx.prefix))

    # --- Default type in type_transition ---
    if ctx.cursor_pos == CursorPos.DEFAULT_TYPE:
        for name in sorted(_universe.types):
            items.append(lsp.CompletionItem(
                label=name,
                kind=lsp.CompletionItemKind.Class,
            ))
        return lsp.CompletionList(is_incomplete=True, items=_filter(items, ctx.prefix))

    # --- Filesystem type in genfscon ---
    if ctx.cursor_pos == CursorPos.FS_TYPE:
        seen_fs = set()
        for fs_type, _, _ in _universe.genfscons:
            seen_fs.add(fs_type)
        for fs in sorted(seen_fs):
            items.append(lsp.CompletionItem(
                label=fs,
                kind=lsp.CompletionItemKind.Module,
                detail='filesystem type',
            ))
        return lsp.CompletionList(is_incomplete=False, items=_filter(items, ctx.prefix))

    return lsp.CompletionList(is_incomplete=False, items=items)


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def _publish_diagnostics(uri: str, text: str, run_compile: bool = False):
    """Run syntax checks and publish diagnostics. When `run_compile` is set and secilc is configured, also run
    a real compilation check (see `_secilc_check`)."""
    diagnostics: list[lsp.Diagnostic] = []

    issues = check_te_syntax(text)
    for issue in issues:
        severity_map = {
            'error': lsp.DiagnosticSeverity.Error,
            'warning': lsp.DiagnosticSeverity.Warning,
            'info': lsp.DiagnosticSeverity.Information,
            'hint': lsp.DiagnosticSeverity.Hint,
        }
        diagnostics.append(lsp.Diagnostic(
            range=lsp.Range(
                start=lsp.Position(line=issue.line, character=issue.col),
                end=lsp.Position(line=issue.line, character=issue.end_col),
            ),
            severity=severity_map.get(issue.severity, lsp.DiagnosticSeverity.Error),
            source='sepolicy-lsp',
            message=issue.message,
        ))

    if _universe:
        diagnostics.extend(_check_semantics(text))

    if run_compile and _secilc_path and _cil_paths:
        diagnostics.extend(_secilc_check(text))

    server.text_document_publish_diagnostics(lsp.PublishDiagnosticsParams(
        uri=uri, diagnostics=diagnostics))


def _secilc_check(text: str) -> list[lsp.Diagnostic]:
    """Compile the buffer against the loaded base policy with secilc and surface resolution/syntax errors.

    secilc consumes CIL, not .te. sepinject already converts .te rules to CIL (`rules_to_cil`), so the check
    reuses that path: the buffer is parsed to rules, converted to a CIL fragment written to its own file, and
    compiled alongside the loaded base CIL files. The invocation mirrors the project's sepcheck.sh Pass 1:

        secilc -M true -G -N -c <policyvers> <base CILs...> <fragment.cil> -o <tmp> -f /dev/null

    `-N` disables neverallow checking so intentional carve-outs in the base policy do not abort the syntax and
    resolution check; neverallow conflicts are handled separately by sepolicy.checkNeverallow. secilc reports
    errors against the CIL inputs with CIL line numbers, which do not map one-to-one onto the .te buffer, so
    the result is reported as one file-level diagnostic carrying the compiler output.

    Resolution requires the full CIL set (plat + system_ext + vendor + plat_pub_versioned); run the server with
    --rom-root or all four --cil files, or this check will report resolution noise. It is strictly
    best-effort: any missing tool or conversion failure yields no diagnostics, so a save is never blocked.
    """
    sep = _import_sepinject()
    if sep is None:
        return []

    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.te', delete=False, prefix='sepolicy_lsp_') as f:
            f.write(text)
            te_path = f.name

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rules = sep.parse_te_file(te_path)
            fragment = sep.rules_to_cil(rules)
        Path(te_path).unlink(missing_ok=True)

        if not fragment.strip():
            return []

        tmp = tempfile.mkdtemp(prefix='sepolicy_lsp_secilc_')
        fragment_cil = Path(tmp) / 'buffer.cil'
        fragment_cil.write_text(fragment)
        out_bin = Path(tmp) / 'out.bin'

        base_cils = [c for c in _cil_paths if Path(c).exists()]
        cmd = [_secilc_path, '-M', 'true', '-G', '-N', '-c', str(_secilc_policyvers),
               *base_cils, str(fragment_cil), '-o', str(out_bin), '-f', '/dev/null']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return []
        msg = (result.stderr or result.stdout).strip()
        return [lsp.Diagnostic(
            range=lsp.Range(start=lsp.Position(line=0, character=0),
                            end=lsp.Position(line=0, character=1)),
            severity=lsp.DiagnosticSeverity.Error,
            source='sepolicy-lsp/secilc',
            message=f'secilc rejected the buffer compiled against the base policy '
                    f'(policyvers {_secilc_policyvers}):\n{msg[:1500]}',
        )]
    except Exception as e:
        log.debug('secilc check skipped: %s', e)
        return []
    finally:
        if tmp:
            import shutil as _shutil
            _shutil.rmtree(tmp, ignore_errors=True)


def _check_semantics(text: str) -> list[lsp.Diagnostic]:
    """Check for unknown types, classes, and permissions in .te rules."""
    diagnostics = []
    lines = text.splitlines()

    av_pattern = re.compile(
        r'^\s*(allow|auditallow|dontaudit|neverallow)\s+'
        r'(\S+)\s+'
        r'(\S+):(\S+)\s+'
        r'\{([^}]*)\}'
    )

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        m = av_pattern.match(stripped)
        if not m:
            continue

        source = m.group(2)
        target = m.group(3)
        cls = m.group(4)
        perms_str = m.group(5)

        # Check source type/attribute.
        if source != 'self' and source not in _universe.all_names:
            col = line.index(source)
            diagnostics.append(lsp.Diagnostic(
                range=lsp.Range(
                    start=lsp.Position(line=i, character=col),
                    end=lsp.Position(line=i, character=col + len(source)),
                ),
                severity=lsp.DiagnosticSeverity.Warning,
                source='sepolicy-lsp',
                message=f'Unknown type or attribute: {source}',
            ))

        # Check target type/attribute.
        if target != 'self' and target not in _universe.all_names:
            try:
                col = line.index(target, line.index(source) + len(source))
            except ValueError:
                col = 0
            diagnostics.append(lsp.Diagnostic(
                range=lsp.Range(
                    start=lsp.Position(line=i, character=col),
                    end=lsp.Position(line=i, character=col + len(target)),
                ),
                severity=lsp.DiagnosticSeverity.Warning,
                source='sepolicy-lsp',
                message=f'Unknown type or attribute: {target}',
            ))

        # Check class (with macro expansion).
        valid_classes = _universe.class_names()
        expanded_classes = set()
        if cls in _universe.class_macros:
            for c in _universe.class_macros[cls].split():
                if c in _universe.class_macros:
                    expanded_classes.update(_universe.class_macros[c].split())
                else:
                    expanded_classes.add(c)
        else:
            expanded_classes.add(cls)

        for ec in expanded_classes:
            if ec not in valid_classes and ec not in _universe.class_macros:
                try:
                    col = line.index(cls)
                except ValueError:
                    col = 0
                diagnostics.append(lsp.Diagnostic(
                    range=lsp.Range(
                        start=lsp.Position(line=i, character=col),
                        end=lsp.Position(line=i, character=col + len(cls)),
                    ),
                    severity=lsp.DiagnosticSeverity.Warning,
                    source='sepolicy-lsp',
                    message=f'Unknown class: {ec}',
                ))
                break

        # Check permissions.
        all_valid_perms = set()
        for ec in expanded_classes:
            all_valid_perms |= _universe.permissions_for_class(ec)
        all_perm_macros = set(_universe.perm_macros.keys())

        perms = perms_str.split()
        try:
            perm_start = line.index('{') + 1
        except ValueError:
            perm_start = 0
        for perm in perms:
            if perm in all_perm_macros:
                continue
            if perm not in all_valid_perms:
                try:
                    perm_col = line.index(perm, perm_start)
                except ValueError:
                    continue
                diagnostics.append(lsp.Diagnostic(
                    range=lsp.Range(
                        start=lsp.Position(line=i, character=perm_col),
                        end=lsp.Position(line=i, character=perm_col + len(perm)),
                    ),
                    severity=lsp.DiagnosticSeverity.Warning,
                    source='sepolicy-lsp',
                    message=f'Unknown permission "{perm}" for class {cls}',
                ))

    return diagnostics


# ---------------------------------------------------------------------------
# Code Actions
# ---------------------------------------------------------------------------

@server.feature(
    lsp.TEXT_DOCUMENT_CODE_ACTION,
    lsp.CodeActionOptions(code_action_kinds=[lsp.CodeActionKind.QuickFix])
)
def on_code_action(params: lsp.CodeActionParams) -> list[lsp.CodeAction]:
    """Offer quick-fix code actions for diagnostics."""
    actions: list[lsp.CodeAction] = []
    uri = params.text_document.uri
    text = _documents.get(uri, '')

    for diag in params.context.diagnostics:
        if diag.source != 'sepolicy-lsp':
            continue

        if 'Missing semicolon' in diag.message:
            line = diag.range.end.line
            col = diag.range.end.character
            actions.append(lsp.CodeAction(
                title='Add missing semicolon',
                kind=lsp.CodeActionKind.QuickFix,
                diagnostics=[diag],
                edit=lsp.WorkspaceEdit(
                    changes={
                        uri: [lsp.TextEdit(
                            range=lsp.Range(
                                start=lsp.Position(line=line, character=col),
                                end=lsp.Position(line=line, character=col),
                            ),
                            new_text=';',
                        )]
                    }
                ),
            ))

        if diag.message.startswith('Unknown type or attribute:'):
            unknown_name = diag.message.split(': ', 1)[1]
            actions.append(lsp.CodeAction(
                title=f'Declare type {unknown_name}',
                kind=lsp.CodeActionKind.QuickFix,
                diagnostics=[diag],
                edit=lsp.WorkspaceEdit(
                    changes={
                        uri: [lsp.TextEdit(
                            range=lsp.Range(
                                start=lsp.Position(line=0, character=0),
                                end=lsp.Position(line=0, character=0),
                            ),
                            new_text=f'type {unknown_name};\n',
                        )]
                    }
                ),
            ))

    if _sepinject_path and _universe and _cil_paths:
        actions.extend(_neverallow_code_actions(uri, text, params))

    return actions
# (gating uses _sepinject_path as a cheap presence check; the command itself imports sepinject lazily.)


def _neverallow_code_actions(
    uri: str, text: str, params: lsp.CodeActionParams
) -> list[lsp.CodeAction]:
    """Offer neverallow conflict check for allow rules under the cursor."""
    actions = []

    start_line = params.range.start.line
    end_line = params.range.end.line
    lines = text.splitlines()

    for i in range(start_line, min(end_line + 1, len(lines))):
        line = lines[i].strip()
        if not line.startswith('allow '):
            continue
        actions.append(lsp.CodeAction(
            title=f'Check neverallow conflicts (line {i + 1})',
            kind=lsp.CodeActionKind.QuickFix,
            command=lsp.Command(
                title='Check neverallow conflicts',
                command='sepolicy.checkNeverallow',
                arguments=[uri, i],
            ),
        ))

    return actions


# ---------------------------------------------------------------------------
# Custom commands
# ---------------------------------------------------------------------------

@server.command('sepolicy.checkNeverallow')
def cmd_check_neverallow(params: list):
    """Check whether the allow rule on a given line conflicts with any neverallow in the loaded CIL.

    sepinject's neverallow logic is invoked in-process: the rule text is parsed with `parse_te_file`, then
    `find_neverallow_conflicts` scans the CIL files. Both helpers print progress, so their output is captured
    to keep the JSON-RPC channel clean in stdio mode.
    """
    if len(params) < 2:
        return
    uri = params[0]
    line_num = params[1]
    text = _documents.get(uri, '')
    lines = text.splitlines()

    if line_num >= len(lines):
        return

    rule_line = lines[line_num].strip()
    sep = _import_sepinject()
    if sep is None or not _cil_paths:
        _notify('sepolicy-lsp: sepinject or CIL files not configured for neverallow checks.',
                lsp.MessageType.Warning)
        return

    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.te', delete=False, prefix='sepolicy_lsp_'
    ) as f:
        f.write(rule_line + '\n')
        te_path = f.name

    try:
        cil_paths = [(f'cil{i}', Path(p)) for i, p in enumerate(_cil_paths)]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rules = sep.parse_te_file(te_path)
            allow_rules = [r for r in rules if getattr(r, 'op', '') == 'allow']
            conflicts, _attr_map, _all_types = sep.find_neverallow_conflicts(allow_rules, cil_paths)

        if not allow_rules:
            _notify(f'Line {line_num + 1} is not an allow rule; nothing to check.')
            return
        if not conflicts:
            _notify(f'No neverallow conflicts for line {line_num + 1}.')
            return

        report_lines = [f'{len(conflicts)} neverallow conflict(s) for line {line_num + 1}:']
        for c in conflicts[:10]:
            na = c.neverallow
            where = f'{Path(na.cil_path).name}:{na.line_no}'
            perms = ' '.join(sorted(c.matched_perms)) or '(class-wide)'
            report_lines.append(f'  • {c.rule.src} {c.rule.tgt}:{c.rule.cls} {{ {perms} }} vs {where}')
        _notify('\n'.join(report_lines), lsp.MessageType.Warning)
    except Exception as e:
        log.exception('neverallow check failed')
        _notify(f'sepolicy-lsp: neverallow check failed: {e}', lsp.MessageType.Error)
    finally:
        Path(te_path).unlink(missing_ok=True)


# --- gitomic session commands ---------------------------------------------

@server.command('sepolicy.session.status')
def cmd_session_status(params: list):
    if _session is not None:
        _notify(_session.status())


@server.command('sepolicy.session.diff')
def cmd_session_diff(params: list):
    if _session is not None:
        _notify(_session.diff())


@server.command('sepolicy.session.finish')
def cmd_session_finish(params: list):
    message = params[0] if params else None
    if _session is not None:
        _notify(_session.finish(message))


@server.command('sepolicy.session.abort')
def cmd_session_abort(params: list):
    if _session is not None:
        _notify(_session.abort(), lsp.MessageType.Warning)


@server.command('sepolicy.reloadUniverse')
def cmd_reload_universe(params: list):
    """Reload the policy universe from CIL files."""
    global _universe
    if _cil_paths:
        _universe = load_from_cil_paths(_cil_paths)
        server.window_show_message(lsp.ShowMessageParams(
            type=lsp.MessageType.Info,
            message=(
                f'Reloaded: {len(_universe.types)} types, '
                f'{len(_universe.attributes)} attributes, '
                f'{len(_universe.classes)} classes')))
    else:
        server.window_show_message(lsp.ShowMessageParams(
            type=lsp.MessageType.Warning,
            message='No CIL paths configured'))


# ---------------------------------------------------------------------------
# Hover
# ---------------------------------------------------------------------------

@server.feature(lsp.TEXT_DOCUMENT_HOVER)
def on_hover(params: lsp.HoverParams) -> Optional[lsp.Hover]:
    """Show type/attribute/class info on hover."""
    if not _universe:
        return None

    uri = params.text_document.uri
    text = _documents.get(uri, '')
    lines = text.splitlines()
    line = params.position.line
    char = params.position.character

    if line >= len(lines):
        return None

    current_line = lines[line]

    # Extract the word under the cursor.
    word_start = char
    word_end = char
    while word_start > 0 and re.match(r'[\w]', current_line[word_start - 1]):
        word_start -= 1
    while word_end < len(current_line) and re.match(r'[\w]', current_line[word_end]):
        word_end += 1
    word = current_line[word_start:word_end]

    if not word:
        return None

    parts = []

    if word in _universe.types:
        ti = _universe.types[word]
        attrs = sorted(ti.attributes)
        parts.append(f'**Type**: `{word}`')
        if attrs:
            parts.append(f'Attributes: {", ".join(f"`{a}`" for a in attrs[:10])}')
            if len(attrs) > 10:
                parts.append(f'... and {len(attrs) - 10} more')

    if word in _universe.attributes:
        ai = _universe.attributes[word]
        members = sorted(ai.members)
        parts.append(f'**Attribute**: `{word}` ({len(members)} types)')
        if members:
            parts.append(f'Members: {", ".join(f"`{m}`" for m in members[:10])}')
            if len(members) > 10:
                parts.append(f'... and {len(members) - 10} more')

    if word in _universe.classes:
        perms = sorted(_universe.permissions_for_class(word))
        parts.append(f'**Class**: `{word}` ({len(perms)} permissions)')
        if perms:
            parts.append(f'Permissions: {", ".join(f"`{p}`" for p in perms[:15])}')
            if len(perms) > 15:
                parts.append(f'... and {len(perms) - 15} more')

    if word in _universe.perm_macros:
        exp = _universe.perm_macros[word]
        parts.append(f'**Permission macro**: `{word}`')
        parts.append(f'Expands to: `{exp}`')

    if word in _universe.class_macros:
        exp = _universe.class_macros[word]
        parts.append(f'**Class macro**: `{word}`')
        parts.append(f'Expands to: `{exp}`')

    if word in _universe.te_macros:
        parts.append(f'**TE macro**: `{word}(domain)`')

    if not parts:
        return None

    return lsp.Hover(
        contents=lsp.MarkupContent(
            kind=lsp.MarkupKind.Markdown,
            value='\n\n'.join(parts),
        ),
        range=lsp.Range(
            start=lsp.Position(line=line, character=word_start),
            end=lsp.Position(line=line, character=word_end),
        ),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    global _universe, _cil_paths, _sepinject_path, _secilc_path, _secilc_policyvers, _session

    parser = argparse.ArgumentParser(
        description='SEPolicy LSP server for .te files')
    parser.add_argument(
        '--rom-root', type=str,
        help='Path to extracted Android ROM root for CIL discovery')
    parser.add_argument(
        '--cil', type=str, nargs='+', dest='cil_files',
        help='Explicit CIL file paths to load')
    parser.add_argument(
        '--sepinject', type=str,
        help='Path to sepinject.py')
    parser.add_argument(
        '--secilc', type=str, default=None,
        help='Path to the secilc binary (default: bundled static build, then PATH)')
    parser.add_argument(
        '--secilc-policyvers', type=int, default=30,
        help='Policy version passed to secilc -c (default: 30, the BenOS MediaTek target)')
    parser.add_argument(
        '--stdio', action='store_true', default=True,
        help='Use stdio transport (default)')
    parser.add_argument(
        '--tcp', type=int, default=None,
        help='Use TCP transport on given port')
    # gitomic-backed session options.
    parser.add_argument(
        '--no-git-session', action='store_true',
        help='Disable the per-session gitomic branch/commit recording')
    parser.add_argument(
        '--gitomic', type=str, default='gitomic',
        help='Path to the gitomic binary (default: gitomic on PATH)')
    parser.add_argument(
        '--session-debounce-ms', type=int, default=5000,
        help='Quiescence window per atomic commit, in ms (default: 5000)')
    parser.add_argument(
        '--session-branch-prefix', type=str, default='sepolicy-lsp',
        help='Prefix for the per-session branch name (default: sepolicy-lsp)')
    parser.add_argument(
        '--session-stop-on-last-close', action='store_true',
        help='Stop recording when the last .te document closes, not only at server exit')
    args = parser.parse_args()

    if args.sepinject:
        _sepinject_path = Path(args.sepinject)

    if args.secilc:
        _secilc_path = args.secilc
    _secilc_policyvers = args.secilc_policyvers

    if args.rom_root:
        log.info('Loading universe from ROM root: %s', args.rom_root)
        _universe = load_from_rom(args.rom_root)
        # Populate the CIL path list from what was discovered so neverallow/secilc features are available in
        # --rom-root mode, not only when --cil is passed explicitly.
        _cil_paths = list(_universe.cil_files)
    elif args.cil_files:
        log.info('Loading universe from CIL files: %s', args.cil_files)
        _cil_paths = list(args.cil_files)
        _universe = load_from_cil_paths(args.cil_files)

    if _universe:
        log.info(
            'Universe ready: %d types, %d attrs, %d classes',
            len(_universe.types), len(_universe.attributes), len(_universe.classes))

    _session = GitomicSession(SessionConfig(
        enabled=not args.no_git_session,
        gitomic_bin=args.gitomic,
        debounce_ms=args.session_debounce_ms,
        coalesce_same_file=False,
        branch_prefix=args.session_branch_prefix,
        stop_on_last_close=args.session_stop_on_last_close,
    ))

    if args.tcp:
        server.start_tcp('127.0.0.1', args.tcp)
    else:
        server.start_io()


if __name__ == '__main__':
    main()
