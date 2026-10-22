"""Local checks and read-only GitHub snapshots. No repository code runs here."""
from __future__ import annotations
import ast
import hashlib
import io
import ipaddress
import json
import re
import shutil
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET

MAX_FILE = 12 * 1024 * 1024
MAX_ARCHIVE = 80 * 1024 * 1024
MAX_EXPANDED = 250 * 1024 * 1024
IMAGES = {'.png', '.jpg', '.jpeg', '.webp', '.bmp', '.tif', '.tiff'}
IGNORED = {'.git', '.venv', 'venv', '__pycache__', 'node_modules', '.idea'}

@dataclass
class Result:
    check: str
    status: str
    detail: str
    path: str = ''
    line: int = 0

    def dictionary(self):
        return asdict(self)


def repo_name(value: str) -> str:
    value = value.strip().rstrip('/')
    if value.startswith('https://github.com/'):
        value = value[len('https://github.com/'):]
    if value.endswith('.git'):
        value = value[:-4]
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value):
        raise ValueError('Use owner/repository or https://github.com/owner/repository.')
    if any(x in {'.', '..'} for x in value.split('/')):
        raise ValueError('Invalid repository name.')
    return value


def safe_relative(value: str) -> str:
    value = value.replace('\\', '/')
    p = PurePosixPath(value)
    if not value or p.is_absolute() or any(x in {'..', '.git'} for x in p.parts) or ':' in value:
        raise ValueError('Target must be a relative repository path without .. or .git.')
    if str(p) == '.':
        raise ValueError('A file path is required.')
    return str(p)


def request_bytes(url: str, limit=MAX_ARCHIVE) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': 'RepoCheck/1.0', 'Accept': 'application/vnd.github+json'})
    try:
        with urllib.request.urlopen(req, timeout=40) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        message = {404: 'Repository or branch not found (public repositories only).',
                   403: 'GitHub denied the request or the anonymous rate limit was reached.',
                   429: 'GitHub rate limit reached. Try again later.'}.get(exc.code, f'GitHub HTTP {exc.code}.')
        raise ValueError(message) from None
    if len(data) > limit:
        raise ValueError('Repository exceeds the download limit (80 MiB).')
    return data


def extract_snapshot(data: bytes, root: Path):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if len(members) > 30000 or sum(x.file_size for x in members) > MAX_EXPANDED:
            raise ValueError('Repository exceeds extraction limits (30,000 entries / 250 MiB).')
        for member in members:
            parts = PurePosixPath(member.filename).parts
            if len(parts) < 2:
                continue
            rel = safe_relative('/'.join(parts[1:]))
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError('Snapshot contains symlinks; this version does not import them.')
            target = root / rel
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, target.open('wb') as out:
                    shutil.copyfileobj(src, out)


def download_snapshot(repo: str, ref: str, destination: Path):
    repo = repo_name(repo)
    metadata = json.loads(request_bytes(f'https://api.github.com/repos/{repo}', 2_000_000))
    ref = ref.strip() or metadata['default_branch']
    commit = json.loads(request_bytes(f'https://api.github.com/repos/{repo}/commits/{urllib.parse.quote(ref, safe="")}', 8_000_000))
    sha = commit['sha']
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('Invalid commit returned by GitHub.')
    extract_snapshot(request_bytes(f'https://api.github.com/repos/{repo}/zipball/{sha}'), destination)
    return {'repo': repo, 'ref': ref, 'sha': sha}


PATTERNS = [
    ('Private key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ('GitHub token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b')),
    ('AWS access key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('Credential assignment', re.compile(r'''(?i)["']?(?:api[_-]?key|password|passwd|secret|access[_-]?token|authorization)["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']''')),
    ('Webhook URL', re.compile(r'https?://[^\s"<>]*?(?:webhook|hooks/)[^\s"<>]*', re.I)),
    ('Email address', re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    ('Personal home path', re.compile(r'(?:/Users/|/home/|[A-Za-z]:\\Users\\)[^\s/\\"\']+')),
]
PLACEHOLDERS = ('example', 'placeholder', 'redacted', 'changeme', 'your_', '${', '<', 'dummy', 'test_')


def text_findings(text: str, path: str, check='Secrets & personal data'):
    results = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for label, pattern in PATTERNS:
            for match in pattern.finditer(line):
                if label == 'Credential assignment' and any(x in match.group(1).lower() for x in PLACEHOLDERS):
                    continue
                results.append(Result(check, 'WARN' if label in {'Email address', 'Personal home path'} else 'FAIL',
                                      f'{label} detected; value hidden. Review this location.', path, line_no))
                break
        for raw in set(re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', line)):
            try:
                if ipaddress.ip_address(raw).is_global:
                    results.append(Result(check, 'WARN', 'Public IPv4 address detected; value hidden.', path, line_no))
            except ValueError:
                pass
    return results


def syntax_check(text, path):
    suffix = Path(path).suffix.lower()
    if suffix not in {'.json', '.xml', '.yaml', '.yml', '.py'}:
        return []
    try:
        if suffix == '.json':
            json.loads(text)
        elif suffix == '.xml':
            ET.fromstring(text)
        elif suffix == '.py':
            ast.parse(text)
        else:
            import yaml
            list(yaml.safe_load_all(text))
    except Exception as exc:
        # Do not include parser snippets, which can contain credentials.
        return [Result('Syntax', 'FAIL', f'Invalid {suffix[1:].upper()} ({type(exc).__name__}); content hidden.', path,
                       int(getattr(exc, 'lineno', 0) or 0))]
    return [Result('Syntax', 'PASS', 'Syntax is valid.', path)]


def scan_file(source: Path, target: str):
    if source.is_symlink():
        return [Result('File coverage', 'SKIP', 'Symlinks are not scanned.', target)]
    if source.stat().st_size > MAX_FILE:
        return [Result('File coverage', 'SKIP', 'File exceeds the 12 MiB per-file limit.', target)]
    if source.suffix.lower() in IMAGES:
        return scan_image(source, target)
    data = source.read_bytes()
    try:
        text = data.decode('utf-8-sig')
        if '\x00' in text:
            raise UnicodeError()
    except UnicodeError:
        return [Result('File coverage', 'SKIP', 'Binary or non-UTF-8 file; not inspected.', target)]
    findings = text_findings(text, target)
    return findings + ([] if findings else [Result('Secrets & personal data', 'PASS', 'No built-in pattern matches.', target)]) + syntax_check(text, target)


def scan_image(source, target, *, metadata=True, ocr=True):
    from PIL import Image
    result = []
    try:
        with Image.open(source) as image:
            image.verify()
        with Image.open(source) as image:
            has_metadata = bool(image.getexif()) or bool(set(image.info) - {'dpi', 'gamma', 'srgb', 'transparency', 'icc_profile'})
        if metadata:
            result.append(Result('Image metadata', 'WARN' if has_metadata else 'PASS',
                                 'Embedded metadata needs review.' if has_metadata else 'No reviewed metadata fields detected.', target))
    except Exception:
        return [Result('Images', 'FAIL', 'Image is invalid or exceeds decoder limits.', target)]
    if not ocr:
        return result
    executable = shutil.which('tesseract')
    if not executable:
        return result + [Result('Screenshot OCR', 'SKIP', 'Install Tesseract and add it to PATH to enable OCR.', target)]
    try:
        process = subprocess.run([executable, str(source), 'stdout'], capture_output=True, timeout=45)
        if process.returncode:
            return result + [Result('Screenshot OCR', 'ERROR', 'Tesseract could not read this image.', target)]
        findings = text_findings(process.stdout.decode('utf-8', errors='replace'), target, 'Screenshot OCR')
        result += findings or [Result('Screenshot OCR', 'PASS', 'No OCR pattern matches. Visual review is still needed.', target)]
    except subprocess.TimeoutExpired:
        result.append(Result('Screenshot OCR', 'ERROR', 'OCR timed out after 45 seconds.', target))
    return result


def change_kind(source: Path, destination: Path):
    if not destination.exists():
        return 'NEW'
    if not destination.is_file():
        return 'CONFLICT'
    def digest(path):
        h = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(65536), b''):
                h.update(block)
        return h.digest()
    return 'UNCHANGED' if digest(source) == digest(destination) else 'MODIFIED'


def stage_files(snapshot: Path, entries, output: Path):
    shutil.copytree(snapshot, output, dirs_exist_ok=True)
    seen = set()
    for source, target in entries:
        rel = safe_relative(target)
        # Use casefold to avoid silent overwrites on Windows/macOS.
        if rel.casefold() in seen:
            raise ValueError('Duplicate target paths. Give every file a distinct target.')
        seen.add(rel.casefold())
        source = Path(source)
        if source.is_symlink() or not source.is_file():
            raise ValueError('Only regular local files can be staged.')
        destination = output / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def summary(results):
    states = {r.status for r in results}
    if 'FAIL' in states or 'ERROR' in states:
        return 'Changes need attention'
    if 'SKIP' in states or 'WARN' in states or 'BLOCKED' in states:
        return 'Review required — checks incomplete or warnings found'
    if states == {'N/A'}:
        return 'No applicable files for the selected checks'
    return 'All selected checks passed' if results else 'Ready to check'
