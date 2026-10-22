"""Build a standalone app on its target OS. Run: python build_app.py.

Uses a separate build virtual environment. Internet access is needed once.
macOS: dist/RepoCheck.app; Windows: dist/RepoCheck/RepoCheck.exe.
The resulting app provisions its test tools on first Check.
"""
from pathlib import Path
import subprocess
import sys
import venv


def main():
    root=Path(__file__).resolve().parent
    build_env=root/'build'/'packaging-env'
    if not build_env.exists():venv.EnvBuilder(with_pip=True).create(build_env)
    python=build_env/('Scripts/python.exe' if sys.platform=='win32' else 'bin/python')
    subprocess.run([str(python),'-m','pip','install','-r',str(root/'requirements.txt'),'pyinstaller>=6,<7'],check=True)
    subprocess.run([str(python),'-m','PyInstaller','--noconfirm','--clean','--windowed','--name','RepoCheck',
                    '--paths',str(root),'--distpath',str(root/'dist'),'--workpath',str(root/'build'/'pyinstaller'),
                    '--specpath',str(root/'build'),str(root/'main.py')],cwd=root,check=True)
    print('Build finished. Distribute the entire app/folder in:',root/'dist')
    print('Test it on the target OS. macOS signing/notarization and Windows signing are not configured.')

if __name__=='__main__':main()
