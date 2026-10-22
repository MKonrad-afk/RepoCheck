import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from core import (repo_name, safe_relative, extract_snapshot, text_findings, syntax_check,
                  stage_files, change_kind, scan_file, summary, Result)


class CoreTests(unittest.TestCase):
    def test_repository_url(self):
        self.assertEqual(repo_name('https://github.com/org/repo.git/'),'org/repo')

    def test_repository_rejection(self):
        for value in ['http://evil.test/a/b','a/b/tree/main','../repo','a/b?token=foo']:
            with self.assertRaises(ValueError):repo_name(value)

    def test_target_paths(self):
        self.assertEqual(safe_relative('docs\\test.md'),'docs/test.md')
        for value in ['../escape','/tmp/escape','C:\\escape','.git/config','docs/../../escape','']:
            with self.assertRaises(ValueError):safe_relative(value)

    def test_zip_traversal(self):
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w') as z:z.writestr('root/../../escape','bad')
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):extract_snapshot(data.getvalue(),Path(tmp))

    def test_zip_extract(self):
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w') as z:z.writestr('root/docs/file.txt','hello')
        with tempfile.TemporaryDirectory() as tmp:
            extract_snapshot(data.getvalue(),Path(tmp))
            self.assertEqual((Path(tmp)/'docs/file.txt').read_text(),'hello')

    def test_zip_symlink(self):
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w') as z:
            info=zipfile.ZipInfo('root/link'); info.external_attr=0o120777<<16; z.writestr(info,'/etc/passwd')
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):extract_snapshot(data.getvalue(),Path(tmp))

    def test_redaction(self):
        token='ghp_'+'A'*32
        results=text_findings(token,'example.txt')
        self.assertTrue(any(x.status=='FAIL' for x in results))
        self.assertNotIn(token,str([r.dictionary() for r in results]))

    def test_personal_data(self):
        results=text_findings('a.person@company.test 8.8.8.8 /Users/alice/file','example.txt')
        self.assertEqual(len(results),3)

    def test_placeholder(self):
        self.assertEqual(text_findings('api_key = "YOUR_API_KEY"','example.txt'),[])

    def test_syntax_no_secret_in_error(self):
        results=syntax_check('{"secret":"sensitive-value",','example.json')
        self.assertEqual(results[0].status,'FAIL'); self.assertNotIn('sensitive-value',str(results))

    def test_python_not_executed(self):
        self.assertEqual(syntax_check('raise RuntimeError("must not execute")','script.py')[0].status,'PASS')

    def test_staging_preserves_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); snapshot=root/'snapshot'; snapshot.mkdir(); (snapshot/'a.txt').write_text('old')
            source=root/'input.txt';source.write_text('new')
            stage_files(snapshot,[(source,'a.txt')],root/'stage')
            self.assertEqual((snapshot/'a.txt').read_text(),'old')
            self.assertEqual((root/'stage/a.txt').read_text(),'new')
            self.assertEqual(change_kind(source,snapshot/'a.txt'),'MODIFIED')
            self.assertEqual(change_kind(source,root/'stage/a.txt'),'UNCHANGED')
            self.assertEqual(change_kind(source,snapshot/'new.txt'),'NEW')

    def test_duplicate_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); snapshot=root/'snapshot';snapshot.mkdir(); source=root/'source';source.write_text('ok')
            with self.assertRaises(ValueError):stage_files(snapshot,[(source,'a.txt'),(source,'A.txt')],root/'stage')

    def test_binary_is_not_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'binary';source.write_bytes(b'\x00\xff')
            self.assertEqual(scan_file(source,'binary')[0].status,'SKIP')

    def test_missing_ocr_is_skipped(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'image.png';Image.new('RGB',(20,20)).save(source)
            with patch('core.shutil.which',return_value=None):
                self.assertTrue(any(x.status=='SKIP' for x in scan_file(source,'image.png')))

    def test_incomplete_is_not_green(self):
        self.assertIn('incomplete',summary([Result('OCR','SKIP','Missing')]))
        self.assertIn('attention',summary([Result('OCR','FAIL','Leak')]))

if __name__=='__main__':unittest.main()
