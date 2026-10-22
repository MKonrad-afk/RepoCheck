"""One-click SOC Automation Lab checks in a private Git checkout and managed runtime."""
from __future__ import annotations
from pathlib import Path
import json
import re
import shutil
import subprocess
import tempfile
import yaml
from core import Result, safe_relative
from managed_runtime import prepare

REQUIRED_SCRIPTS=['scripts/sanitize_export.py','scripts/check_images.py','scripts/validate_syntax.py']
EXPECTED=['Secrets and personal data','New changes','Screenshots and OCR','Syntax','Unit tests','Gitleaks: all history']


def git(runtime,root,*args,timeout=300):
    command=runtime.command('git','-c','core.hooksPath=','-c','init.templateDir=','-c','commit.gpgsign=false',*args)
    result=subprocess.run(command,cwd=root,env=runtime.environment(),capture_output=True,timeout=timeout)
    if result.returncode:
        raise ValueError('Could not prepare the temporary Git checkout. Check internet access and the selected branch; originals were not modified.')
    return result.stdout.decode('utf-8',errors='replace').strip()


def safe_diagnostics(output,root):
    """Return locations/categories only, never raw lines containing matched secrets."""
    findings=[]
    for relative in sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and '.git' not in p.parts):
        if relative in output:
            findings.append(relative)
            if len(findings)>=8:break
    parts=[]
    if findings:parts.append('Review: '+', '.join(findings)+'.')
    missing=re.search(r"ModuleNotFoundError: No module named ['\"]([A-Za-z0-9_.-]+)",output)
    if missing:parts.append('Missing test dependency: '+missing.group(1)+'.')
    test_result=re.search(r'Ran (\d+) tests? in',output)
    if test_result:parts.append(test_result.group(1)+' unit test(s) ran.')
    return ' '.join(parts)


def check_command(runtime,name,args,root,timeout=600,success_codes=(0,)):
    try:
        # Bound retained output and keep raw content out of UI/report.
        with tempfile.TemporaryFile() as output:
            result=subprocess.run(args,cwd=root,env=runtime.environment(),stdout=output,stderr=subprocess.STDOUT,timeout=timeout)
            output.seek(0);text=output.read(4*1024*1024).decode('utf-8',errors='replace')
        if result.returncode in success_codes:
            if name=='Unit tests' and not re.search(r'Ran [1-9]\d* tests? in',text):
                return Result(name,'ERROR','No unit tests ran; this is not a pass.')
            count=re.search(r'Ran (\d+) tests? in',text) if name=='Unit tests' else None
            return Result(name,'PASS',f'{count.group(1)} unit tests passed.' if count else 'Completed successfully.')
        infrastructure=bool(re.search(r'ModuleNotFoundError|ImportError|Traceback \(most recent call last\)',text))
        status='ERROR' if infrastructure or result.returncode not in (1,) else 'FAIL'
        detail=('Test execution failed. ' if status=='ERROR' else 'Check reported a problem. ')+safe_diagnostics(text,root)
        return Result(name,status,detail.strip() or 'Check failed; no pass was issued.')
    except subprocess.TimeoutExpired:
        return Result(name,'ERROR',f'Check exceeded its {timeout}-second timeout.')
    except OSError:
        return Result(name,'ERROR','Could not start the managed test tool.')


def validate_recipe(root):
    """This adapter explicitly covers the lab recipe, not arbitrary GitHub Actions."""
    missing=[p for p in REQUIRED_SCRIPTS if not (root/p).is_file()]
    if not (root/'tests').is_dir():missing.append('tests/')
    if missing:
        raise ValueError('Full-check adapter is not configured for this repository. Missing: '+', '.join(missing)+'. Use Advanced for generic scans; no ready-to-push verdict can be issued.')
    workflow=root/'.github/workflows/checks.yml'
    if not workflow.is_file():raise ValueError('The expected checks.yml workflow is missing. Full CI coverage cannot be confirmed.')
    text=workflow.read_text(encoding='utf-8')
    workflow_data=yaml.safe_load(text)
    known_jobs={'secret-scan','leak-check','image-check','syntax-and-tests'}
    if not isinstance(workflow_data,dict) or set(workflow_data.get('jobs',{}))!=known_jobs:
        raise ValueError('CI jobs changed. The full-check adapter must be reviewed before issuing a ready-to-push verdict.')
    required=['sanitize_export.py --check .','sanitize_export.py --check-commits','check_images.py --ocr --require-ocr .','validate_syntax.py','unittest discover -s tests','gitleaks']
    if any(token not in text for token in required):
        raise ValueError('The repository workflow has changed or is unsupported. No ready-to-push verdict was issued; review the adapter.')


def run_full(info,entries,runtime_root,emit,progress):
    if not entries:raise ValueError('Add at least one file to check.')
    paths=[safe_relative(target) for _,target in entries]
    if len(set(p.casefold() for p in paths))!=len(paths):raise ValueError('Duplicate repository paths; edit the file destinations.')
    runtime=prepare(Path(runtime_root),progress)
    emit(Result('Test environment','PASS','Private Python, Git, Gitleaks and OCR verified.'))
    with tempfile.TemporaryDirectory(prefix='repocheck-full-') as tmp:
        parent=Path(tmp);root=parent/'repo'
        progress('Downloading repository history…')
        git(runtime,parent,'clone','--no-checkout','--',f"https://github.com/{info['repo']}.git",str(root),timeout=600)
        git(runtime,root,'checkout','--detach',info['sha'])
        # The application already promises not to follow repository symlinks during staging.
        if any(p.is_symlink() for p in root.rglob('*') if '.git' not in p.parts):
            raise ValueError('This repository contains symlinks; the full-check adapter does not support them.')
        # Validate original adapter before overlay, so uploaded workflow deletion cannot make it disappear silently.
        validate_recipe(root)
        for (source,_),target in zip(entries,paths):
            source=Path(source)
            if not source.is_file() or source.is_symlink():raise ValueError('An input is missing or is a symlink.')
            destination=root/target;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination)
        validate_recipe(root)
        progress('Staging your files in a temporary local commit…')
        git(runtime,root,'add','--force','--',*paths)
        base=git(runtime,root,'rev-parse','HEAD')
        changed=bool(git(runtime,root,'diff','--cached','--name-only'))
        if changed:
            git(runtime,root,'-c','user.name=RepoCheck','-c','user.email=checks@example.invalid','commit','--no-verify','-m','Local RepoCheck validation')
        commands=[
            ('Secrets and personal data',runtime.command('python','scripts/sanitize_export.py','--check','.')),
            ('New changes',runtime.command('python','scripts/sanitize_export.py','--check-commits',f'{base}..HEAD')),
            ('Screenshots and OCR',runtime.command('python','scripts/check_images.py','--ocr','--require-ocr','.')),
            ('Syntax',runtime.command('python','scripts/validate_syntax.py')),
            ('Unit tests',runtime.command('python','-m','unittest','discover','-s','tests','-v')),
        ]
        for name,command in commands:
            progress('Running: '+name+'…')
            emit(check_command(runtime,name,command,root))
        progress('Scanning all fetched Git history, including your temporary commit…')
        config=root/'.gitleaks.toml'
        args=[str(runtime.leaks),'git','--redact','--no-banner','--log-opts=--all']
        if config.is_file():args+=['--config',str(config)]
        args+=[str(root)]
        emit(check_command(runtime,'Gitleaks: all history',args,root))
    progress('All required local checks finished.')


def full_verdict(results):
    by_name={r.check:r for r in results}
    if any(name not in by_name for name in EXPECTED) or any(r.status in {'ERROR','BLOCKED','SKIP'} for r in results):
        return 'Check incomplete — do not push yet'
    if any(r.status!='PASS' for r in results):return 'Changes need fixing — do not push yet'
    return 'Ready to push — required local checks passed'
