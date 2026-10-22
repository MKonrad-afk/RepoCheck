"""Offscreen UI regression tests; no remote repository code is executed."""
import os
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication
from main import Window, RepositoryDialog
from core import Result

APP=QApplication.instance() or QApplication([])

class GuiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.window=Window(auto_connect=False,simple=False,config_dir=self.root/'config')

    def tearDown(self):
        self.wait_idle();self.window.close();self.window.deleteLater();QCoreApplication.sendPostedEvents(None,QEvent.Type.DeferredDelete);self.tmp.cleanup()

    def wait_idle(self):
        deadline=time.monotonic()+8
        while self.window.busy and time.monotonic()<deadline:
            APP.processEvents();time.sleep(.005)
        self.assertFalse(self.window.busy)

    def test_local_scan_no_repo_and_no_popup(self):
        source=self.root/'a.json';source.write_text('{}')
        self.window.add_paths([str(source)])
        self.window.preset('none');self.window.check_boxes['syntax'].setChecked(True)
        with patch('main.QMessageBox.warning',side_effect=AssertionError('Unexpected popup')):
            self.window.run_checks();self.wait_idle()
        self.assertEqual(len(self.window.results),1)
        self.assertEqual(self.window.results[0].status,'PASS')
        self.assertTrue(self.window.export_btn.isEnabled())
        self.window.check_boxes['secrets'].setChecked(True)
        self.assertIsNone(self.window.report_context)

    def test_trust_persisted_and_repeated_run_has_no_confirmation(self):
        snapshot=self.root/'snapshot';snapshot.mkdir();(snapshot/'scripts').mkdir();(snapshot/'scripts/validate_syntax.py').write_text('pass')
        w=self.window;repo=w.current_repo()
        w.settings['trusted_repos'][repo.lower()]=True;w.persist()
        w.snapshot=snapshot;w.connected={'repo':repo,'ref':'main','sha':'0'*40}
        w.preset('none');w.check_boxes['repo_syntax'].setChecked(True)
        with patch('checks.command_result',return_value=Result('Repository syntax rules','PASS','Completed')) as run, patch('main.QMessageBox.warning',side_effect=AssertionError('Unexpected confirmation')):
            for _ in range(2):w.run_checks();self.wait_idle()
            self.assertEqual(run.call_count,2)
        second=Window(auto_connect=False,simple=False,config_dir=self.root/'config')
        self.assertTrue(second.is_trusted());self.assertEqual(second.selected_checks(),['repo_syntax']);second.close();second.deleteLater();QCoreApplication.sendPostedEvents(None,QEvent.Type.DeferredDelete)

    def test_trust_cannot_transfer_to_different_repo(self):
        dialog=RepositoryDialog(self.window,{'repo':'org/first'},'First',True)
        self.assertTrue(dialog.trust.isChecked())
        dialog.repo.setText('org/second')
        self.assertFalse(dialog.trust.isChecked());dialog.close();dialog.deleteLater();QCoreApplication.sendPostedEvents(None,QEvent.Type.DeferredDelete)

    def test_simple_check_needs_no_saved_permission(self):
        from full_check import EXPECTED
        w=self.window;w.simple=True;w.refresh_availability()
        source=self.root/'a.txt';source.write_text('safe text');w.add_paths([str(source)])
        info={'repo':w.current_repo(),'ref':'main','sha':'0'*40}
        def full(info, entries, runtime, emit, progress):
            for name in EXPECTED:emit(Result(name,'PASS','Completed'))
        with patch('main.download_snapshot',return_value=info),patch('main.run_full',side_effect=full) as run,patch('main.QMessageBox.warning',side_effect=AssertionError('Unexpected popup')):
            w.run_checks();self.wait_idle();run.assert_called_once()
        self.assertIn('Ready to push',w.banner.text())
        self.assertEqual(w.report_context['mode'],'required')

    def test_none_disables_run(self):
        self.window.preset('none');self.assertFalse(self.window.run_btn.isEnabled())

    def test_select_profile_connects_automatically(self):
        w=self.window;w.profile_data['Other']={'repo':'org/other','ref':'main'};w.refresh_profiles()
        with patch.object(w,'connect_repo') as connect:
            w.profiles.setCurrentText('Other');self.assertEqual(connect.call_count,1)

if __name__=='__main__':unittest.main()
