"""Private, automatically provisioned test environment. Never uses system pip/brew/sudo."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import hashlib
import io
import json
import os
import platform
import shutil
import ssl
import subprocess
import tarfile
import time
import urllib.request
import zipfile

MAMBA_VERSION='2.9.0-0'
MAMBA={
 'linux-64':('micromamba-linux-64','366cd9cd8be14df1ab8ed50352a82111082a36686b2d389fdb79a92c3fafb3e3'),
 'linux-aarch64':('micromamba-linux-aarch64','9f93b974adcb4d166996af969b6cd371287d1a3e52733704727884d9b74cb7a7'),
 'osx-64':('micromamba-osx-64','1e71054bb3ac9a076e21f7ec48acfef536f9b3f1408f371a942784bf5ef83d8a'),
 'osx-arm64':('micromamba-osx-arm64','ec2a072f028e1a7cf20f3e2e74d5a8127cf5a5f27636375b5359811565f4e5be'),
 'win-64':('micromamba-win-64.exe','a6d804394b2418991c4e29562853eaace2f2ce9d9da661a98e74e02e8dbb44b0'),
}
LEAKS_VERSION='8.24.2'
LEAKS={
 'linux-64':('linux_x64.tar.gz','fa0500f6b7e41d28791ebc680f5dd9899cd42b58629218a5f041efa899151a8e'),
 'linux-aarch64':('linux_arm64.tar.gz','574a6d52573c61173add7ddb5e3cc68c0e82cb0735818a1eeb9a0a2de1643fbc'),
 'osx-64':('darwin_x64.tar.gz','bc3c46f8039ba716ba8461fa6745c9d1cfb90ca2f5f881d8d0cf66b7ba7b742c'),
 'osx-arm64':('darwin_arm64.tar.gz','90d13686937ac7429b97a3acbf1e1d0ce90d92ae2d0cf46a690bd8ae5230bea0'),
 'win-64':('windows_x64.zip','cc47fdc0364964e2d346fbbcbe4cc87f34d490b2647508fb05930d0ec2fbff07'),
}
PACKAGES=['python=3.12','pillow','pyyaml','jsonschema','tesseract=5.5.3','git']


def platform_key():
    machine=platform.machine().lower(); system=platform.system()
    x64=machine in {'x86_64','amd64'}; arm=machine in {'aarch64','arm64'}
    if system=='Darwin' and (x64 or arm):return 'osx-64' if x64 else 'osx-arm64'
    if system=='Linux' and (x64 or arm):return 'linux-64' if x64 else 'linux-aarch64'
    if system=='Windows' and x64:return 'win-64'
    raise ValueError('Automatic setup supports macOS Intel/Apple Silicon, Linux x64/arm64 and Windows x64.')


def verified_download(url, expected, destination):
    request=urllib.request.Request(url,headers={'User-Agent':'RepoCheck/1.2'})
    hasher=hashlib.sha256(); size=0; partial=destination.with_suffix('.download')
    try:
        with urllib.request.urlopen(request,timeout=60) as response, partial.open('wb') as output:
            while True:
                block=response.read(1024*1024)
                if not block:break
                size+=len(block)
                if size>100*1024*1024:raise ValueError('Tool download exceeded its size limit.')
                hasher.update(block);output.write(block)
        if hasher.hexdigest()!=expected:raise ValueError('Tool checksum mismatch. Setup stopped without executing it.')
        partial.replace(destination)
    finally:partial.unlink(missing_ok=True)


@dataclass
class Runtime:
    root: Path
    prefix: Path
    mamba: Path
    leaks: Path

    def environment(self):
        env=os.environ.copy()
        for name in ['PYTHONHOME','PYTHONPATH','GITLEAKS_CONFIG','GITLEAKS_CONFIG_TOML','GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_CONFIG_COUNT']:
            env.pop(name,None)
        paths=[self.prefix/'bin',self.prefix,self.prefix/'Library/bin',self.prefix/'Library/usr/bin',self.prefix/'Scripts',self.leaks.parent]
        env['PATH']=os.pathsep.join(map(str,paths))+os.pathsep+env.get('PATH','')
        env['MAMBA_ROOT_PREFIX']=str(self.root/'mamba-root')
        env['PYTHONNOUSERSITE']='1'; env['GIT_TERMINAL_PROMPT']='0'; env['GIT_CONFIG_NOSYSTEM']='1';env['GIT_CONFIG_GLOBAL']=os.devnull
        env['GIT_LFS_SKIP_SMUDGE']='1'
        # Reuse the host Python's trusted CA bundle (including legitimate enterprise roots).
        # Verification stays enabled; never bypass certificate checks.
        host_ca=ssl.get_default_verify_paths().cafile
        if 'GIT_SSL_CAINFO' not in env and host_ca and Path(host_ca).is_file():
            env['GIT_SSL_CAINFO']=host_ca
        for folder in [self.prefix/'share/tessdata',self.prefix/'Library/share/tessdata']:
            if (folder/'eng.traineddata').exists():env['TESSDATA_PREFIX']=str(folder);break
        return env

    def command(self,*args):
        return [str(self.mamba),'run','-p',str(self.prefix),*map(str,args)]

    def probe(self):
        # Probe actual binaries and imports, not just a stale "installed" marker.
        for args in [('python','-c','import PIL, yaml, jsonschema'),('git','--version'),('tesseract','--list-langs')]:
            result=subprocess.run(self.command(*args),env=self.environment(),capture_output=True,timeout=60)
            if result.returncode:return False
            if args[0]=='tesseract' and b'eng' not in result.stdout:return False
        result=subprocess.run([str(self.leaks),'version'],capture_output=True,timeout=20)
        return result.returncode==0 and LEAKS_VERSION.encode() in result.stdout


def prepare(root: Path, progress=lambda text:None):
    key=platform_key();root=Path(root);root.mkdir(parents=True,exist_ok=True)
    mamba=root/('micromamba.exe' if key=='win-64' else 'micromamba')
    prefix=root/'environment-v1';leaks=root/'tools'/('gitleaks.exe' if key=='win-64' else 'gitleaks')
    runtime=Runtime(root,prefix,mamba,leaks)
    lock=root/'setup.lock'
    try:fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY)
    except FileExistsError:
        raise ValueError('Another setup may be running. Close other RepoCheck windows; if a previous setup crashed, remove setup.lock from the runtime folder.') from None
    os.close(fd)
    try:
        progress('Checking the private test environment…')
        if mamba.is_file() and leaks.is_file() and prefix.is_dir():
            try:
                if runtime.probe():return runtime
            except (OSError,subprocess.TimeoutExpired):pass
        progress('First-time setup: downloading verified test tools…')
        asset,digest=MAMBA[key]
        if not mamba.exists() or hashlib.sha256(mamba.read_bytes()).hexdigest()!=digest:
            verified_download(f'https://github.com/mamba-org/micromamba-releases/releases/download/{MAMBA_VERSION}/{asset}',digest,mamba)
        mamba.chmod(0o755)
        if not leaks.exists():
            leaks.parent.mkdir(exist_ok=True);suffix,digest=LEAKS[key];archive=root/('gitleaks-'+suffix)
            verified_download(f'https://github.com/gitleaks/gitleaks/releases/download/v{LEAKS_VERSION}/gitleaks_{LEAKS_VERSION}_{suffix}',digest,archive)
            if suffix.endswith('.zip'):
                with zipfile.ZipFile(archive) as z:data=z.read('gitleaks.exe')
            else:
                with tarfile.open(archive,'r:gz') as tar:
                    member=tar.getmember('gitleaks')
                    if not member.isfile() or member.size>100*1024*1024:raise ValueError('Invalid Gitleaks binary archive.')
                    data=tar.extractfile(member).read()
            leaks.write_bytes(data);leaks.chmod(0o755);archive.unlink()
        progress('Installing Python, Git, OCR and test dependencies. First setup can take several minutes…')
        action='install' if (prefix/'conda-meta/history').exists() else 'create'
        env=runtime.environment()
        # Ignore user conda configuration; package metadata includes package hashes.
        command=[str(mamba),action,'--no-rc','--yes','--prefix',str(prefix),'--override-channels','--channel','conda-forge',*PACKAGES]
        with (root/'setup.log').open('wb') as log:
            try:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
            except subprocess.TimeoutExpired:raise ValueError('Environment setup timed out. Check connectivity and retry Check.') from None
        if result.returncode:
            raise ValueError('Automatic environment setup failed. Retry with internet access and free disk space; details are in the runtime setup.log. No checks passed.')
        progress('Verifying Python imports, Git, Gitleaks and English OCR…')
        if not runtime.probe():raise ValueError('Installed test tools failed verification. No checks were treated as passed.')
        (root/'runtime.json').write_text(json.dumps({'schema':1,'platform':key,'packages':PACKAGES,'gitleaks':LEAKS_VERSION}),encoding='utf-8')
        return runtime
    finally:lock.unlink(missing_ok=True)
