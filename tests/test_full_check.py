import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from core import Result
from full_check import EXPECTED, full_verdict, validate_recipe, safe_diagnostics
from managed_runtime import verified_download, platform_key

class RequiredChecksTests(unittest.TestCase):
    def test_incomplete_cannot_be_ready(self):
        results=[Result(name,'PASS','ok') for name in EXPECTED[:-1]]
        self.assertNotIn('Ready to push',full_verdict(results))

    def test_failed_cannot_be_ready(self):
        results=[Result(name,'PASS','ok') for name in EXPECTED]
        results[0].status='FAIL'
        self.assertIn('do not push',full_verdict(results))

    def test_all_required_pass(self):
        results=[Result(name,'PASS','ok') for name in EXPECTED]
        self.assertEqual(full_verdict(results),'Ready to push — required local checks passed')

    def test_unknown_recipe_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):validate_recipe(Path(tmp))

    def test_redacted_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'a.json').write_text('{}')
            out=safe_diagnostics('a.json: secret=really-sensitive-secret\n',root)
            self.assertIn('a.json',out);self.assertNotIn('really-sensitive-secret',out)

    def test_bad_binary_hash_never_installed(self):
        import io
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'tool'
            with patch('managed_runtime.urllib.request.urlopen',return_value=io.BytesIO(b'wrong')):
                with self.assertRaises(ValueError):verified_download('https://example.invalid/tool','0'*64,target)
            self.assertFalse(target.exists());self.assertFalse(target.with_suffix('.download').exists())

    def test_mac_architectures(self):
        for arch,wanted in [('arm64','osx-arm64'),('x86_64','osx-64')]:
            with patch('managed_runtime.platform.system',return_value='Darwin'),patch('managed_runtime.platform.machine',return_value=arch):
                self.assertEqual(platform_key(),wanted)

if __name__=='__main__':unittest.main()
