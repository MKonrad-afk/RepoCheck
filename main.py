"""RepoCheck desktop application. Run this file in PyCharm."""
from __future__ import annotations
import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QStandardPaths, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QLineEdit, QFileDialog, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QProgressBar, QInputDialog, QSplitter, QDialog, QDialogButtonBox, QFormLayout, QScrollArea, QTextBrowser)
from core import (Result, repo_name, safe_relative, download_snapshot, scan_file, stage_files,
                  change_kind, summary, IGNORED)
from full_check import run_full, full_verdict
from checks import CHECKS, DEFAULT_CHECKS, execute, tool_status, unavailable
import os
import uuid

STYLE = '''
QWidget { background:#0d1117; color:#e6edf3; font-size:13px; }
QMainWindow { background:#0d1117; }
QLabel {background:transparent;}
QLabel#brand {font-size:22px; font-weight:700;} QLabel#title {font-size:25px; font-weight:700;}
QLabel#muted {color:#8b949e;} QLabel#eyebrow {color:#7ee787; font-size:11px; font-weight:700;}
QWidget#sidebar {background:#010409; border-right:1px solid #30363d;}
QPushButton {background:#21262d; border:1px solid #30363d; padding:9px 15px; border-radius:6px; font-weight:600;}
QPushButton:hover {background:#30363d; border-color:#8b949e;} QPushButton:disabled {color:#484f58;}
QPushButton#primary {background:#238636; border-color:#2ea043; color:white;} QPushButton#primary:hover {background:#2ea043;}
QLineEdit,QComboBox {background:#010409; border:1px solid #30363d; padding:8px; border-radius:6px;}
QTableWidget {background:#010409; border:1px solid #30363d; border-radius:6px; gridline-color:#21262d; selection-background-color:#1c3553;}
QHeaderView::section {background:#161b22; color:#8b949e; padding:9px; border:0; border-bottom:1px solid #30363d;}
QTableWidget::item {padding:7px;} QCheckBox {padding:5px 0;}
QProgressBar {border:0; background:#21262d; max-height:4px;} QProgressBar::chunk {background:#3fb950;}
QLabel#banner {background:#161b22; border:1px solid #30363d; border-radius:7px; padding:13px; font-size:17px; font-weight:600;}
'''
COLORS = {'PASS':'#3fb950','FAIL':'#f85149','ERROR':'#f85149','WARN':'#d29922','SKIP':'#d29922','BLOCKED':'#d29922','N/A':'#8b949e'}


class Worker(QThread):
    event = Signal(object)
    progress = Signal(str)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, function):
        super().__init__()
        self.function = function

    def run(self):
        try:
            self.done.emit(self.function(self.event.emit))
        except Exception as exc:
            # Filesystem and network error text may include sensitive local paths.
            message = str(exc) if isinstance(exc, ValueError) else f'{type(exc).__name__}: operation failed. Check connectivity, permissions and dependencies.'
            self.failed.emit(message)


class DropTable(QTableWidget):
    dropped = Signal(list)

    def __init__(self):
        super().__init__(0, 3)
        self.setAcceptDrops(True)
        self.setHorizontalHeaderLabels(['Local file', 'Repository path · double-click to edit', 'Change'])
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.setColumnWidth(2, 120)
        self.verticalHeader().hide()
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        self.dropped.emit([u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()])
        event.acceptProposedAction()


TERMS = '''<h2>Usage and repository execution</h2>
<p>RepoCheck reads public GitHub repositories and checks local copies. It does not push or upload your added files.</p>
<h3>Check files: required checks</h3><p>Clicking Check files authorizes running the selected repository’s validation scripts and tests on a temporary copy with your added files. RepoCheck downloads its own Python, Git, Gitleaks and OCR tools on first use; internet access and about 2 GB of free disk space are required. No per-run confirmation appears. Only use this with code you trust. Ready to push means the supported local checks passed, not that GitHub has approved the merge.</p><h3>Advanced checks: saved script permission</h3>
<p>When you enable <b>Allow repository scripts</b> for a repository, you authorize future runs of selected Python scripts and unit tests from that repository, including later branches/commits and your staged additions. This permission is saved for that exact owner/repository, across profiles. There is no confirmation on each Run.</p>
<p>Scripts run with your user permissions and can access your files, environment and network. A temporary copy is not a security sandbox. Enable this only for code you trust; review new code before running it. Turn permission off in Repository settings at any time. For stronger isolation, use a disposable VM.</p>
<h3>What results mean</h3>
<p><b>PASS</b>: the selected check completed without reported findings. <b>WARN</b>: review a finding. <b>FAIL / ERROR</b>: a finding or execution problem. <b>BLOCKED</b>: a selected check could not run; the reason is shown. <b>N/A</b>: no applicable files. Unselected checks do not run and do not create skipped rows.</p>
<p>Scans are heuristic and do not guarantee that files contain no secrets. OCR can miss text. GitHub CI and human review remain necessary. Commit-range validation is left to GitHub CI because added local files are not commits.</p>
<p>Matched secret values are hidden from reports; repository names and target paths remain visible. Review those before sharing reports.</p>'''


def configure_tool_path():
    """Include standard Homebrew locations when launched from a macOS GUI."""
    if sys.platform == 'darwin':
        current = os.environ.get('PATH', '').split(os.pathsep)
        os.environ['PATH'] = os.pathsep.join(current + [p for p in ('/opt/homebrew/bin', '/usr/local/bin') if p not in current and Path(p).is_dir()])


class RepositoryDialog(QDialog):
    def __init__(self, parent, profile=None, name='', trusted=False):
        super().__init__(parent)
        self.setWindowTitle('Repository settings'); self.resize(600, 370)
        layout=QVBoxLayout(self); layout.setSpacing(14)
        title=QLabel('Connect a public repository'); title.setObjectName('title'); layout.addWidget(title)
        description=QLabel('Paste a GitHub URL. No account or token is needed.'); description.setObjectName('muted'); layout.addWidget(description)
        form=QFormLayout(); form.setSpacing(12)
        profile=profile or {}
        self.name=QLineEdit(name); self.name.setPlaceholderText('Optional · defaults to owner/repository')
        self.repo=QLineEdit(profile.get('repo','')); self.repo.setPlaceholderText('https://github.com/owner/repository')
        self.branch=QLineEdit(profile.get('ref','')); self.branch.setPlaceholderText('Default branch')
        form.addRow('GitHub repository',self.repo); form.addRow('Branch or tag',self.branch); form.addRow('Profile name',self.name); layout.addLayout(form)
        self.trust=QCheckBox('Allow repository scripts for this repository'); self.trust.setChecked(trusted); self.trust.setVisible(not parent.simple); layout.addWidget(self.trust)
        note=QLabel('Saved permission covers future code from this repository and your added files.\nCode runs with your user permissions. Enable only for code you trust.'); note.setWordWrap(True); note.setObjectName('muted'); layout.addWidget(note)
        if parent.simple:note.setText('Check files runs this repository’s validation code on a temporary local copy. Only connect code you trust. Tools are prepared automatically.')
        terms=QPushButton('Read usage terms'); terms.clicked.connect(parent.show_terms); layout.addWidget(terms,alignment=Qt.AlignmentFlag.AlignLeft)
        self.error_label=QLabel(''); self.error_label.setStyleSheet('color:#f85149'); layout.addWidget(self.error_label)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Save|QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText('Save and connect'); buttons.accepted.connect(self.validate); buttons.rejected.connect(self.reject); layout.addWidget(buttons)
        original=profile.get('repo','').lower()
        def changed():
            try: same=repo_name(self.repo.text()).lower()==original
            except ValueError: same=False
            # Never transfer permission silently to another repository.
            if not same:self.trust.setChecked(False)
        self.repo.textChanged.connect(changed)

    def validate(self):
        try:self.canonical=repo_name(self.repo.text())
        except ValueError as exc:self.error_label.setText(str(exc)); return
        self.accept()


class Window(QMainWindow):
    def __init__(self, *, auto_connect=True, config_dir=None, simple=True):
        super().__init__(); configure_tool_path()
        self.setWindowTitle('RepoCheck 1.2'); self.simple=simple; self.resize(1240,860); self.setMinimumSize(1000,720)
        self.workspace=tempfile.TemporaryDirectory(prefix='repocheck-')
        self.snapshot=None; self.connected=None; self.results=[]; self.report_context=None
        self.worker=None; self.busy=False; self.active_profile=''; self.tool_state=tool_status()
        self.config=Path(config_dir or QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppConfigLocation))/'profiles.json'
        self.profile_data=self.load_profiles(); self.settings=self.load_settings()
        self.check_boxes={}; self.check_notes={}; self._loading=False
        central=QWidget(); outer=QHBoxLayout(central); outer.setContentsMargins(0,0,0,0); outer.setSpacing(0)
        sidebar=QWidget(); self.sidebar=sidebar; sidebar.setObjectName('sidebar'); sidebar.setFixedWidth(285)
        left=QVBoxLayout(sidebar); left.setContentsMargins(20,22,18,18); left.setSpacing(10)
        left.addWidget(self.label('✓  RepoCheck','brand')); left.addSpacing(12)
        left.addWidget(self.label('Choose checks','title'))
        presets=QHBoxLayout(); self.recommended_btn=self.button('Basic',lambda:self.preset('basic'),presets)
        self.all_btn=self.button('All',lambda:self.preset('all'),presets); self.none_btn=self.button('None',lambda:self.preset('none'),presets); left.addLayout(presets)
        scroll=QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        check_content=QWidget(); choices=QVBoxLayout(check_content); choices.setContentsMargins(0,0,5,0); choices.setSpacing(7)
        group=None
        for key,(name,description,scope) in CHECKS.items():
            category='ADDED FILES' if scope=='files' else ('REPOSITORY SCRIPTS' if scope=='code' else 'REPOSITORY SCANS')
            if category!=group:
                choices.addSpacing(6); choices.addWidget(self.label(category,'eyebrow')); group=category
            check=QCheckBox(name); check.setChecked(key in DEFAULT_CHECKS); check.toggled.connect(self.selection_changed)
            choices.addWidget(check); self.check_boxes[key]=check
            note=self.label(description,'muted'); note.setWordWrap(True); note.setContentsMargins(23,0,0,3); choices.addWidget(note); self.check_notes[key]=note
        choices.addStretch(); scroll.setWidget(check_content); left.addWidget(scroll,1)
        self.tools_btn=self.button('Tools and setup',self.show_tools,left)
        self.terms_btn=self.button('Usage terms',self.show_terms,left)
        left.addWidget(self.label('Local files stay on your computer.','muted')); outer.addWidget(sidebar); sidebar.setVisible(not self.simple)
        body=QWidget(); right=QVBoxLayout(body); right.setContentsMargins(24,22,24,18); right.setSpacing(12)
        heading=QHBoxLayout(); heading.addWidget(self.label('RepoCheck','title')); heading.addStretch(); self.advanced=QCheckBox('Advanced'); self.advanced.setChecked(not self.simple); self.advanced.toggled.connect(self.toggle_advanced); heading.addWidget(self.advanced); self.result_count=self.label('','muted'); heading.addWidget(self.result_count); right.addLayout(heading)
        # Connection controls are separate from file checks and always visible at the top.
        repo_card=QWidget(); repo_layout=QVBoxLayout(repo_card); repo_layout.setContentsMargins(0,0,0,0); repo_layout.setSpacing(7)
        repo_line=QHBoxLayout(); repo_line.addWidget(self.label('Repository','muted'))
        self.profiles=QComboBox(); self.profiles.setMinimumWidth(200); repo_line.addWidget(self.profiles,1)
        self.connect_btn=self.button('Connect',self.connect_repo,repo_line,True)
        self.edit_btn=self.button('Settings',self.edit_profile,repo_line)
        self.new_btn=self.button('+ Add',lambda:self.edit_profile(new=True),repo_line)
        self.delete_btn=self.button('Remove',self.delete_profile,repo_line)
        self.usage_btn=self.button('Usage terms',self.show_terms,repo_line)
        repo_layout.addLayout(repo_line)
        self.connection=self.label('Not connected · local file checks are available.','muted'); self.connection.setWordWrap(True); repo_layout.addWidget(self.connection)
        right.addWidget(repo_card)
        self.banner=self.label('Add files, then click Check.','banner'); self.banner.setWordWrap(True); right.addWidget(self.banner)
        self.progress=QProgressBar(); self.progress.setTextVisible(False); self.progress.setRange(0,1); self.progress.setValue(0); self.progress.hide(); right.addWidget(self.progress)
        files_panel=QWidget(); file_layout=QVBoxLayout(files_panel); file_layout.setContentsMargins(0,0,0,0); file_layout.setSpacing(8)
        file_bar=QHBoxLayout(); self.add_btn=self.button('+ Add files',self.pick_files,file_bar); self.folder_btn=self.button('Add folder',self.pick_folder,file_bar)
        self.remove_btn=self.button('Remove selected',self.remove_files,file_bar); file_bar.addStretch(); self.file_count=self.label('0 files','muted'); file_bar.addWidget(self.file_count); file_layout.addLayout(file_bar)
        self.files=DropTable(); self.files.setMinimumHeight(130); self.files.dropped.connect(self.add_paths); self.files.itemChanged.connect(self.file_edited); file_layout.addWidget(self.files)
        self.file_hint=self.label('Drop files here. Folder contents keep their relative paths.','muted'); file_layout.addWidget(self.file_hint)
        results_panel=QWidget(); results_layout=QVBoxLayout(results_panel); results_layout.setContentsMargins(0,0,0,0)
        results_layout.addWidget(self.label('Results','eyebrow'))
        self.checks=QTableWidget(0,3); self.checks.setHorizontalHeaderLabels(['Status','Check / file','Details'])
        self.checks.verticalHeader().hide(); self.checks.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.checks.setColumnWidth(0,85); self.checks.setColumnWidth(1,235); self.checks.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeMode.Stretch); results_layout.addWidget(self.checks)
        split=QSplitter(Qt.Orientation.Vertical); split.addWidget(files_panel); split.addWidget(results_panel); split.setSizes([260,340]); right.addWidget(split,1)
        self.preflight=self.label('','muted'); self.preflight.setWordWrap(True); right.addWidget(self.preflight)
        bottom=QHBoxLayout(); self.run_btn=self.button('Run selected checks',self.run_checks,bottom,True); bottom.addStretch(); self.export_btn=self.button('Export report',self.export_report,bottom); self.export_btn.setEnabled(False); right.addLayout(bottom)
        outer.addWidget(body,1); self.setCentralWidget(central)
        self.profiles.currentIndexChanged.connect(self.select_profile)
        self.refresh_profiles(self.settings.get('last_profile'))
        if auto_connect and self.settings.get('auto_connect') and self.active_profile:
            QTimer.singleShot(0,self.connect_repo)

    def label(self,text,kind):
        widget=QLabel(text); widget.setObjectName(kind); return widget

    def button(self,text,callback,layout,primary=False):
        widget=QPushButton(text); widget.clicked.connect(callback)
        if primary:widget.setObjectName('primary')
        layout.addWidget(widget); return widget

    def load_profiles(self):
        try:
            data=json.loads(self.config.read_text(encoding='utf-8'))
            if not isinstance(data,dict) or not all(isinstance(k,str) and isinstance(v,dict) and isinstance(v.get('repo'),str) and isinstance(v.get('ref',''),str) for k,v in data.items()):raise ValueError()
            return data
        except (OSError,ValueError):return {'SOC Automation Lab':{'repo':'Solivagantaeon/soc-automation-lab','ref':''}}

    def load_settings(self):
        try:
            data=json.loads(self.config.with_name('settings.json').read_text(encoding='utf-8'))
            if not isinstance(data,dict):raise ValueError()
            if not isinstance(data.get('trusted_repos',{}),dict):raise ValueError()
            return data
        except (OSError,ValueError):return {'trusted_repos':{},'auto_connect':False}

    def persist(self):
        self.config.parent.mkdir(parents=True,exist_ok=True)
        for path,data in [(self.config,self.profile_data),(self.config.with_name('settings.json'),self.settings)]:
            tmp=path.with_suffix('.tmp'); tmp.write_text(json.dumps(data,indent=2),encoding='utf-8'); tmp.replace(path)

    def save_quietly(self):
        try:self.persist()
        except OSError:self.connection.setText('Settings could not be saved. Check configuration-folder permissions.')

    def current_repo(self):
        return self.profile_data.get(self.active_profile,{}).get('repo','')

    def is_trusted(self):
        return self.settings.get('trusted_repos',{}).get(self.current_repo().lower(),False) is True

    def refresh_profiles(self,selected=None):
        self.profiles.blockSignals(True); self.profiles.clear(); self.profiles.addItems(list(self.profile_data))
        if selected in self.profile_data:self.profiles.setCurrentText(selected)
        self.profiles.blockSignals(False); self.select_profile(connect=False)

    def select_profile(self,*_,connect=True):
        if self.busy:return
        self.active_profile=self.profiles.currentText(); self.snapshot=None; self.connected=None
        self.connect_btn.setText('Connect'); self.connection.setText(f"{self.current_repo() or 'No repository selected'} · Not connected")
        data=self.profile_data.get(self.active_profile,{})
        selected=data.get('checks',DEFAULT_CHECKS)
        if not isinstance(selected,list):selected=DEFAULT_CHECKS
        self._loading=True
        for key,box in self.check_boxes.items():box.setChecked(key in selected)
        self._loading=False; self.settings['last_profile']=self.active_profile; self.save_quietly()
        self.clear_results(); self.update_changes(); self.refresh_availability()
        if connect and self.active_profile:self.connect_repo()

    def edit_profile(self,*_,new=False):
        old_name='' if new else self.active_profile
        dialog=RepositoryDialog(self, self.profile_data.get(old_name,{}),old_name,False if new else self.is_trusted())
        if dialog.exec()!=QDialog.DialogCode.Accepted:return
        name=dialog.name.text().strip() or dialog.canonical
        if name!=old_name and name in self.profile_data:
            self.error('That profile name already exists. Choose another name.');return
        existing=self.profile_data.get(old_name,{})
        self.profile_data[name]={'repo':dialog.canonical,'ref':dialog.branch.text().strip(),'checks':existing.get('checks',DEFAULT_CHECKS)}
        if old_name and old_name!=name:self.profile_data.pop(old_name,None)
        self.settings.setdefault('trusted_repos',{})[dialog.canonical.lower()]=dialog.trust.isChecked()
        self.settings['terms_version']='1.2'
        self.settings['last_profile']=name
        try:self.persist()
        except OSError:self.error('Could not save settings.');return
        self.refresh_profiles(name); self.connect_repo()

    def delete_profile(self):
        if not self.active_profile:return
        if QMessageBox.question(self,'Remove profile',f'Remove “{self.active_profile}”?')!=QMessageBox.StandardButton.Yes:return
        repo=self.current_repo().lower(); self.profile_data.pop(self.active_profile,None)
        if not any(x['repo'].lower()==repo for x in self.profile_data.values()):self.settings.get('trusted_repos',{}).pop(repo,None)
        self.save_quietly(); self.refresh_profiles()

    def show_terms(self):
        dialog=QDialog(self); dialog.setWindowTitle('Usage terms'); dialog.resize(640,530)
        layout=QVBoxLayout(dialog); text=QTextBrowser(); text.setHtml(TERMS); layout.addWidget(text)
        close=QDialogButtonBox(QDialogButtonBox.StandardButton.Close); close.rejected.connect(dialog.reject); layout.addWidget(close); dialog.exec()

    def show_tools(self):
        configure_tool_path(); self.tool_state=tool_status(); self.refresh_availability()
        dialog=QDialog(self); dialog.setWindowTitle('Tools and setup'); dialog.resize(620,460)
        layout=QVBoxLayout(dialog); text=QTextBrowser(); text.setOpenExternalLinks(True)
        items=''.join(f'<li><b>{name}</b>: {"Available" if ok else "Not found"}</li>' for name,ok in self.tool_state.items())
        text.setHtml(f'''<h2>Optional tools</h2><ul>{items}</ul>
        <p>Only checks that use a missing tool are blocked. Built-in text, syntax and metadata checks work without these command-line tools.</p>
        <h3>macOS · Homebrew</h3><pre>brew install gitleaks tesseract git</pre>
        <p>Use Gitleaks 8.24 or later. On Windows/Linux, follow the official installation instructions and add the executable to PATH:</p>
        <p><a href="https://github.com/gitleaks/gitleaks">Gitleaks</a> · <a href="https://github.com/tesseract-ocr/tesseract">Tesseract</a> · <a href="https://git-scm.com/">Git</a></p>
        <p>Restart PyCharm if PATH changed. On macOS, RepoCheck also looks in standard Homebrew folders. Tools are not installed automatically.</p>'''); layout.addWidget(text)
        buttons=QHBoxLayout(); self.button('Refresh tools',lambda:(configure_tool_path(),dialog.accept()),buttons); self.button('Close',dialog.reject,buttons); layout.addLayout(buttons); dialog.exec()
        self.tool_state=tool_status(); self.refresh_availability()

    def selected_checks(self):return [key for key,box in self.check_boxes.items() if box.isChecked()]

    def preset(self,kind):
        self._loading=True
        for key,box in self.check_boxes.items():box.setChecked(kind=='all' or (kind=='basic' and key in DEFAULT_CHECKS))
        self._loading=False; self.selection_changed()

    def selection_changed(self,*_):
        if self._loading:return
        if self.active_profile in self.profile_data:
            self.profile_data[self.active_profile]['checks']=self.selected_checks(); self.save_quietly()
        self.clear_results(); self.refresh_availability()

    def refresh_availability(self):
        blocked=0
        for key,(_,description,_) in CHECKS.items():
            reason=unavailable(key,self.snapshot,self.is_trusted(),self.tool_state)
            self.check_notes[key].setText(reason or description)
            self.check_notes[key].setToolTip(reason or description)
            self.check_notes[key].setStyleSheet('color:#d29922;' if reason else 'color:#8b949e;')
            if reason and self.check_boxes[key].isChecked():blocked+=1
        if self.simple:
            self.run_btn.setText('Check files'); self.run_btn.setEnabled(not self.busy)
            self.preflight.setText('Check runs this repository’s validation code locally. Tools are prepared automatically on first use. Usage terms apply.')
            return
        count=len(self.selected_checks()); self.run_btn.setText(f'Run {count} selected check'+('s' if count!=1 else ''))
        self.run_btn.setEnabled(not self.busy and count>0)
        self.preflight.setText(f'{blocked} selected check(s) blocked — see the reasons on the left.' if blocked else ('Only selected checks will run.' if count else 'Select at least one check.'))

    def clear_results(self,*_):
        self.results=[]; self.report_context=None; self.checks.setRowCount(0); self.export_btn.setEnabled(False); self.result_count.setText('')
        self.banner.setText(('Ready to check your files.' if self.simple else 'Ready to run selected checks.') if self.files.rowCount() else 'Add files to begin.')
        self.file_count.setText(f'{self.files.rowCount()} file(s)')

    def set_busy(self,busy):
        self.busy=busy
        for widget in [self.profiles,self.connect_btn,self.edit_btn,self.new_btn,self.delete_btn,self.add_btn,self.folder_btn,self.remove_btn,self.files,self.run_btn,self.tools_btn,self.recommended_btn,self.all_btn,self.none_btn,*self.check_boxes.values()]:widget.setEnabled(not busy)
        self.progress.setVisible(busy); self.progress.setRange(0,0 if busy else 1)
        self.advanced.setEnabled(not busy); self.export_btn.setEnabled(not busy and bool(self.report_context)); self.refresh_availability()

    def start(self,function,completed):
        self.set_busy(True); self.worker=Worker(function); self.worker.event.connect(self.add_result)
        self.worker.done.connect(completed); self.worker.failed.connect(self.worker_failed); self.worker.progress.connect(self.banner.setText)
        self.worker.finished.connect(lambda:self.set_busy(False)); self.worker.start()

    def worker_failed(self,message):
        self.add_result(Result('Operation','ERROR',message)); self.banner.setText('Check incomplete — do not push yet' if self.simple else 'Operation failed — see details below.')
        if self.simple:self.report_context={'app_version':'1.2','mode':'required','repository':self.connected or self.profile_data.get(self.active_profile),'completed':False}
        if not self.connected:self.connection.setText('Connection failed. Check the repository and branch, then retry.')

    def connect_repo(self):
        if self.busy:return
        if not self.active_profile:return self.edit_profile(new=True)
        data=dict(self.profile_data[self.active_profile])
        try:repo=repo_name(data['repo'])
        except ValueError as exc:return self.error(str(exc))
        self.snapshot=None; self.connected=None; self.clear_results(); self.update_changes()
        self.connection.setText(f'Connecting to {repo}…'); self.banner.setText('Downloading repository snapshot…')
        destination=Path(self.workspace.name)/uuid.uuid4().hex; destination.mkdir()
        def download(emit):return download_snapshot(repo,data.get('ref',''),destination)
        def ready(info):
            self.connected=info; self.snapshot=destination; self.connect_btn.setText('Refresh')
            self.connection.setText(f"Connected · {info['repo']} · {info['ref']} · {info['sha'][:10]}")
            self.settings['auto_connect']=True; self.save_quietly(); self.banner.setText('Repository connected. Ready to check.'); self.update_changes(); self.refresh_availability()
        self.start(download,ready)

    def pick_files(self):
        paths,_=QFileDialog.getOpenFileNames(self,'Choose files'); self.add_paths(paths)

    def pick_folder(self):
        folder=QFileDialog.getExistingDirectory(self,'Choose folder · contents map to repository root')
        if folder:self.add_paths([folder])

    def add_paths(self,paths):
        if self.busy:return
        entries=[]
        for raw in paths:
            path=Path(raw)
            if path.is_symlink():continue
            if path.is_dir():
                entries.extend((p,p.relative_to(path).as_posix()) for p in path.rglob('*') if p.is_file() and not p.is_symlink() and not any(x in IGNORED for x in p.relative_to(path).parts))
            elif path.is_file():
                matches=[p.relative_to(self.snapshot).as_posix() for p in self.snapshot.rglob('*') if p.is_file() and p.name==path.name] if self.snapshot else []
                entries.append((path,matches[0] if len(matches)==1 else path.name))
        if len(entries)+self.files.rowCount()>2000:return self.error('Add at most 2,000 files per scan.')
        self.files.blockSignals(True)
        existing={self.files.item(i,0).data(Qt.ItemDataRole.UserRole) for i in range(self.files.rowCount())}
        for path,target in entries:
            source=str(path.absolute())
            if source in existing:continue
            existing.add(source); row=self.files.rowCount(); self.files.insertRow(row)
            item=QTableWidgetItem(path.name); item.setToolTip(source); item.setData(Qt.ItemDataRole.UserRole,source); item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.files.setItem(row,0,item); self.files.setItem(row,1,QTableWidgetItem(target))
            state=QTableWidgetItem('—'); state.setFlags(state.flags() & ~Qt.ItemFlag.ItemIsEditable); self.files.setItem(row,2,state)
        self.files.blockSignals(False); self.clear_results(); self.update_changes()

    def file_edited(self,item):
        if item.column()==1:self.clear_results(); self.update_changes()

    def remove_files(self):
        for row in sorted({i.row() for i in self.files.selectedIndexes()},reverse=True):self.files.removeRow(row)
        self.clear_results()

    def entries(self):
        return [(self.files.item(i,0).data(Qt.ItemDataRole.UserRole),safe_relative(self.files.item(i,1).text())) for i in range(self.files.rowCount())]

    def update_changes(self):
        self.files.blockSignals(True)
        for i in range(self.files.rowCount()):
            try:
                target=safe_relative(self.files.item(i,1).text())
                state=change_kind(Path(self.files.item(i,0).data(Qt.ItemDataRole.UserRole)),self.snapshot/target) if self.snapshot else 'LOCAL'
            except (ValueError,OSError):state='INVALID'
            self.files.item(i,2).setText(state)
        self.files.blockSignals(False)

    def add_result(self,result):
        self.results.append(result); row=self.checks.rowCount(); self.checks.insertRow(row)
        name=result.check+(f'\n{result.path}' if result.path else '')
        detail=result.detail+(f' (line {result.line})' if result.line else '')
        for col,value in enumerate([result.status,name,detail]):
            item=QTableWidgetItem(value); item.setToolTip(value); self.checks.setItem(row,col,item)
        self.checks.item(row,0).setForeground(QColor(COLORS.get(result.status,'#8b949e'))); self.checks.resizeRowToContents(row); self.checks.scrollToBottom()
        counts={status:sum(r.status==status for r in self.results) for status in ('PASS','WARN','FAIL','ERROR','BLOCKED','N/A')}
        self.result_count.setText(' · '.join(f'{n} {s.lower()}' for s,n in counts.items() if n))

    def run_checks(self):
        if self.simple:return self.run_required_checks()
        selected=self.selected_checks()
        if not selected or self.busy:return
        try:entries=self.entries()
        except ValueError as exc:return self.error(str(exc))
        if not entries and all(CHECKS[k][2]=='files' for k in selected):
            self.banner.setText('Add files to run the selected file checks.');return
        if len({t.casefold() for _,t in entries})!=len(entries):return self.error('Duplicate target paths. Edit the target column before running.')
        info=dict(self.connected) if self.connected else None; snapshot=self.snapshot; trusted=self.is_trusted()
        self.clear_results(); self.banner.setText('Running selected checks…')
        context={'app_version':'1.2','repository':info,'started_at':datetime.now(timezone.utc).isoformat(),'selected_checks':selected,'repository_code_allowed':trusted,'files':[t for _,t in entries]}
        def check(emit):
            execute(selected,snapshot,entries,info['repo'] if info else '',trusted,emit); return context
        def complete(ctx):self.report_context=ctx; self.banner.setText(summary(self.results))
        self.start(check,complete)

    def toggle_advanced(self, enabled):
        self.simple=not enabled; self.sidebar.setVisible(enabled); self.clear_results(); self.refresh_availability()

    def run_required_checks(self):
        if self.busy:return
        if not self.active_profile:return self.edit_profile(new=True)
        try:entries=self.entries()
        except ValueError as exc:return self.error(str(exc))
        if not entries:
            self.banner.setText('Add at least one file, then click Check.');return
        profile=dict(self.profile_data[self.active_profile])
        self.clear_results(); self.banner.setText('Preparing required checks…')
        runtime_root=self.config.parent/'runtime'
        def work(emit):
            progress=self.worker.progress.emit
            progress('Refreshing the selected repository…')
            snapshot=Path(self.workspace.name)/uuid.uuid4().hex;snapshot.mkdir()
            info=download_snapshot(repo_name(profile['repo']),profile.get('ref',''),snapshot)
            mapped=[]
            for source,target in entries:
                if target==Path(source).name:
                    matches=[p.relative_to(snapshot).as_posix() for p in snapshot.rglob('*') if p.is_file() and p.name==target]
                    if len(matches)==1:target=matches[0]
                    elif len(matches)>1:raise ValueError('More than one repository file has this name. Set its exact target path in the file table.')
                mapped.append((source,target))
            run_full(info,mapped,runtime_root,emit,progress)
            return {'app_version':'1.2','mode':'required','repository':info,'snapshot':str(snapshot),
                    'files':[target for _,target in mapped],'checked_at':datetime.now(timezone.utc).isoformat()}
        def done(context):
            self.connected=context['repository']; self.snapshot=Path(context.pop('snapshot'));self.report_context=context
            for i,target in enumerate(context['files']):
                self.files.blockSignals(True);self.files.item(i,1).setText(target);self.files.blockSignals(False)
            self.connect_btn.setText('Refresh');self.connection.setText(f"Connected · {self.connected['repo']} · {self.connected['ref']} · {self.connected['sha'][:10]}")
            self.banner.setText(full_verdict(self.results));self.update_changes()
        self.start(work,done)

    def export_report(self):
        if not self.report_context:return
        target,_=QFileDialog.getSaveFileName(self,'Export report','repocheck-report.json','JSON (*.json)')
        if target:
            try:Path(target).write_text(json.dumps({**self.report_context,'summary':full_verdict(self.results) if self.report_context.get('mode')=='required' else summary(self.results),'results':[r.dictionary() for r in self.results]},indent=2),encoding='utf-8')
            except OSError:self.error('Could not write the report.')

    def error(self,text):QMessageBox.warning(self,'RepoCheck',text)

    def closeEvent(self,event):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self,'Checks running','Wait for the current operation to finish before closing.'); event.ignore(); return
        self.workspace.cleanup(); event.accept()


def main():
    app=QApplication(sys.argv); app.setApplicationName('RepoCheck'); app.setOrganizationName('RepoCheck'); app.setStyle('Fusion'); app.setStyleSheet(STYLE)
    window=Window(); window.show(); sys.exit(app.exec())

if __name__=='__main__':main()
