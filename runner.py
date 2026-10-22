"""Explicitly opted-in repository checks and optional installed gitleaks."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
from core import Result


def command_result(name, args, cwd, timeout=180):
    try:
        # Output from repository scripts can contain real secrets, so never put it in the UI/report.
        process = subprocess.run(args, cwd=cwd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=timeout)
        return Result(name, 'PASS' if process.returncode == 0 else 'FAIL',
                      'Completed successfully.' if process.returncode == 0 else f'Exited with code {process.returncode}. Raw output hidden to protect sensitive values; see README for the command.')
    except subprocess.TimeoutExpired:
        return Result(name, 'ERROR', f'Timed out after {timeout} seconds.')
    except OSError:
        return Result(name, 'ERROR', 'Could not start the required executable.')


def python_executable():
    if not getattr(sys, "frozen", False):
        return sys.executable
    from PySide6.QtCore import QStandardPaths
    prefix = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppConfigLocation)) / "runtime" / "environment-v1"
    return str(prefix / ("python.exe" if sys.platform == "win32" else "bin/python"))


def repo_checks(root: Path):
    checks = [
        ('Repository: secrets & personal data', 'scripts/sanitize_export.py', ['--check', '.']),
        ('Repository: screenshots + required OCR', 'scripts/check_images.py', ['--ocr', '--require-ocr', '.']),
        ('Repository: syntax', 'scripts/validate_syntax.py', []),
    ]
    for name, script, arguments in checks:
        if (root / script).is_file():
            yield command_result(name, [python_executable(), script, *arguments], root)
        else:
            yield Result(name, 'SKIP', f'{script} does not exist in this repository.')
    if (root / 'tests').is_dir():
        yield command_result('Repository: unit tests', [python_executable(), '-m', 'unittest', 'discover', '-s', 'tests', '-v'], root)
    else:
        yield Result('Repository: unit tests', 'SKIP', 'No tests directory. Automatic runner supports unittest only.')


def gitleaks_files(root):
    exe = shutil.which('gitleaks')
    if not exe:
        return Result('Gitleaks: staged files', 'SKIP', 'Install Gitleaks 8.24+ and add it to PATH.')
    # Empty environment config override: use installed default rules, not repository allowlists.
    with tempfile.TemporaryDirectory(prefix='repocheck-gitleaks-') as tmp:
        config = Path(tmp) / 'defaults.toml'
        config.write_text('[extend]\nuseDefault = true\n', encoding='utf-8')
        args = [exe, 'dir', '--config', str(config), '--redact', '--no-banner', str(root)]
        return command_result('Gitleaks: staged files', args, Path(tmp))


def gitleaks_history(repo):
    git, leaks = shutil.which('git'), shutil.which('gitleaks')
    if not git or not leaks:
        return Result('Gitleaks: remote history', 'SKIP', 'Git and Gitleaks 8.24+ are required on PATH.')
    with tempfile.TemporaryDirectory(prefix='repocheck-history-') as tmp:
        root = Path(tmp)
        mirror = root / 'history.git'
        result = command_result('Download remote history',
            [git, '-c', 'core.hooksPath=', 'clone', '--mirror', '--', f'https://github.com/{repo}.git', str(mirror)], root, 300)
        if result.status != 'PASS':
            return result
        return command_result('Gitleaks: remote history',
            [leaks, 'git', '--redact', '--no-banner', '--log-opts=--all', str(mirror)], root, 300)
