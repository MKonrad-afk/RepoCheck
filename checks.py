"""Selectable check definitions and execution; no unselected check is invoked."""
from pathlib import Path
import shutil
import tempfile
from core import Result, IMAGES, MAX_FILE, text_findings, syntax_check, scan_image, stage_files
from runner import python_executable, command_result, gitleaks_files, gitleaks_history
import sys

CHECKS = {
    'secrets': ('Secrets and personal data', 'Added text files', 'files'),
    'syntax': ('File syntax', 'JSON, XML, YAML, Python', 'files'),
    'metadata': ('Image metadata', 'Added images', 'files'),
    'ocr': ('Screenshot OCR', 'Requires Tesseract', 'files'),
    'gitleaks': ('Gitleaks file scan', 'Repository + added files', 'repository'),
    'history': ('Remote Git history', 'All remote refs · slower', 'repository'),
    'repo_secrets': ('Repository secret rules', 'sanitize_export.py', 'code'),
    'repo_images': ('Repository image rules', 'check_images.py + OCR', 'code'),
    'repo_syntax': ('Repository syntax rules', 'validate_syntax.py', 'code'),
    'unit': ('Unit tests', 'unittest · tests/', 'code'),
}
SCRIPTS = {
    'repo_secrets': ('scripts/sanitize_export.py', ['--check', '.']),
    'repo_images': ('scripts/check_images.py', ['--ocr', '--require-ocr', '.']),
    'repo_syntax': ('scripts/validate_syntax.py', []),
}
DEFAULT_CHECKS = ['secrets', 'syntax', 'metadata']


def tool_status():
    return {name: bool(shutil.which(name)) for name in ('git', 'gitleaks', 'tesseract')}


def unavailable(key, snapshot, trusted, tools):
    missing = []
    required = {'ocr': ['tesseract'], 'gitleaks': ['gitleaks'],
                'repo_images': ['tesseract'], 'history': ['git', 'gitleaks']}.get(key, [])
    absent = [name for name in required if not tools.get(name)]
    if absent:
        missing.append('Install ' + ' + '.join(absent) + ' (Tools & setup)')
    if CHECKS[key][2] in {'repository', 'code'} and snapshot is None:
        missing.append('Connect a repository')
    if CHECKS[key][2] == 'code':
        if not trusted:
            missing.append('Allow scripts in Repository settings')
        if snapshot is not None:
            required_path = SCRIPTS[key][0] if key in SCRIPTS else 'tests'
            if not (snapshot / required_path).exists():
                missing.append(f'Not found: {required_path}')
    return '; '.join(missing)


def local_check(key, entries):
    applicable = 0
    for source, target in entries:
        source = Path(source)
        is_image = source.suffix.lower() in IMAGES
        if key in {'metadata', 'ocr'} and not is_image:
            continue
        if key in {'secrets', 'syntax'} and is_image:
            continue
        if key == 'syntax' and source.suffix.lower() not in {'.json','.xml','.yaml','.yml','.py'}:
            continue
        applicable += 1
        name = CHECKS[key][0]
        try:
            if source.is_symlink() or source.stat().st_size > MAX_FILE:
                yield Result(name, 'BLOCKED', 'File is a symlink or exceeds the 12 MiB scan limit.', target)
                continue
            if is_image:
                for result in scan_image(source, target, metadata=key == 'metadata', ocr=key == 'ocr'):
                    if result.status == 'SKIP': result.status = 'BLOCKED'
                    yield result
            else:
                try:
                    text = source.read_bytes().decode('utf-8-sig')
                    if '\x00' in text: raise UnicodeError()
                except UnicodeError:
                    yield Result(name, 'BLOCKED', 'Binary or non-UTF-8 file is not inspected.', target)
                    continue
                results = syntax_check(text, target) if key == 'syntax' else text_findings(text, target)
                yield from results or [Result(name, 'PASS', 'No built-in pattern matches.', target)]
        except OSError:
            yield Result(name, 'ERROR', 'Could not read this file. Check that it still exists and is accessible.', target)
    if not applicable:
        yield Result(CHECKS[key][0], 'N/A', 'No applicable files in this selection.')


def execute(selected, snapshot, entries, repo, trusted, emit):
    """Run only selected checks. Repository trust is supplied from saved user settings."""
    unknown = set(selected) - CHECKS.keys()
    if unknown: raise ValueError('Unknown check selection.')
    tools = tool_status()
    with tempfile.TemporaryDirectory(prefix='repocheck-stage-') as tmp:
        root = Path(tmp) / 'repo'
        if entries or any(k != 'history' for k in selected):
            if snapshot is None:
                empty = Path(tmp) / 'empty'; empty.mkdir()
                stage_files(empty, entries, root)
            else:
                stage_files(snapshot, entries, root)
        staged = [(root / target, target) for _, target in entries]
        for key in selected:
            reason = unavailable(key, snapshot, trusted, tools)
            if reason:
                emit(Result(CHECKS[key][0], 'BLOCKED', reason))
                continue
            if CHECKS[key][2] == 'files':
                for result in local_check(key, staged): emit(result)
            elif key == 'gitleaks':
                result = gitleaks_files(root)
                if result.status == 'SKIP': result.status = 'BLOCKED'
                emit(result)
            elif key == 'history':
                result = gitleaks_history(repo)
                if result.status == 'SKIP': result.status = 'BLOCKED'
                emit(result)
            elif key in SCRIPTS:
                script, args = SCRIPTS[key]
                # A staged file can replace a script or tests, so trust covers both sources.
                emit(command_result(CHECKS[key][0], [python_executable(), script, *args], root))
            elif key == 'unit':
                emit(command_result('Unit tests', [python_executable(), '-m', 'unittest', 'discover', '-s', 'tests', '-v'], root))
