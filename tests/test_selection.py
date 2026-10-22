import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from checks import execute, unavailable, local_check
from core import Result, summary

class SelectionTests(unittest.TestCase):
    def test_only_selected_syntax_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'a.json';p.write_text('{"ok":true}')
            output=[]
            with patch('checks.gitleaks_files') as leaks, patch('checks.gitleaks_history') as history, patch('checks.command_result') as code, patch('checks.text_findings') as secrets:
                execute(['syntax'],None,[(p,'a.json')],'',False,output.append)
                for fn in [leaks,history,code,secrets]:fn.assert_not_called()
            self.assertEqual([r.status for r in output],['PASS'])
            self.assertEqual(summary(output),'All selected checks passed')

    def test_no_applicable_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'a.txt';p.write_text('ok')
            output=list(local_check('metadata',[(p,'a.txt')]))
            self.assertEqual(output[0].status,'N/A')
            self.assertNotIn('passed',summary(output))

    def test_metadata_does_not_invoke_ocr(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'a.png';Image.new('RGB',(10,10)).save(p)
            with patch('core.subprocess.run') as run:
                output=list(local_check('metadata',[(p,'a.png')]))
                run.assert_not_called()
            self.assertEqual(len(output),1);self.assertEqual(output[0].check,'Image metadata')

    def test_missing_tools_reported_before_run(self):
        reason=unavailable('history',Path('/tmp'),False,{'git':True,'gitleaks':False})
        self.assertIn('gitleaks',reason)

    def test_repo_code_denied_without_saved_permission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'scripts').mkdir();(root/'scripts/validate_syntax.py').write_text('pass')
            output=[]
            with patch('checks.command_result') as run:
                execute(['repo_syntax'],root,[],'org/repo',False,output.append);run.assert_not_called()
            self.assertEqual(output[0].status,'BLOCKED')
            self.assertIn('Allow scripts',output[0].detail)

    def test_allowed_repo_check_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'scripts').mkdir();(root/'scripts/validate_syntax.py').write_text('pass')
            output=[]
            with patch('checks.command_result',return_value=Result('Repository syntax rules','PASS','OK')) as run:
                execute(['repo_syntax'],root,[],'org/repo',True,output.append)
                self.assertEqual(run.call_count,1)
                self.assertIn('scripts/validate_syntax.py',run.call_args.args[1])
            self.assertEqual(len(output),1)

    def test_unselected_history_and_commit_check_absent(self):
        output=[]
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'a.txt';p.write_text('hello')
            execute(['secrets'],None,[(p,'a.txt')],'',False,output.append)
        self.assertEqual(len(output),1);self.assertEqual(output[0].status,'PASS')

    def test_all_na_not_pass(self):
        self.assertEqual(summary([Result('Syntax','N/A','No files')]),'No applicable files for the selected checks')

    def test_blocked_prevents_pass(self):
        self.assertIn('incomplete',summary([Result('History','BLOCKED','Missing Git')]))

if __name__=='__main__':unittest.main()
