import subprocess
import sys
import unittest
from pathlib import Path


ADVARCHIVER_ROOT = Path(__file__).resolve().parents[1]
WORKTREE_ROOT = ADVARCHIVER_ROOT.parent
BUILD_SCRIPT = ADVARCHIVER_ROOT / "scripts" / "build_single_file.py"
DIST_SCRIPT = ADVARCHIVER_ROOT / "dist" / "advArchiver.py"
README_PATH = ADVARCHIVER_ROOT / "README.md"


class TestBuildSingleFile(unittest.TestCase):
    def run_build_once(self):
        result = subprocess.run(
            [sys.executable, str(BUILD_SCRIPT)],
            cwd=str(WORKTREE_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertTrue(DIST_SCRIPT.exists())
        return DIST_SCRIPT.read_text(encoding="utf-8")

    def test_generated_script_has_do_not_edit_header(self):
        text = self.run_build_once()
        self.assertIn("AUTO-GENERATED, DO NOT EDIT", text)

    def test_generated_script_excludes_deprecated_sources(self):
        text = self.run_build_once()
        self.assertNotIn("deprecated/adv7z.py", text)
        self.assertNotIn("deprecated/advRar.py", text)
        self.assertNotIn("deprecated/advZip.py", text)

    def test_repeated_build_is_deterministic(self):
        first_build = self.run_build_once()
        second_build = self.run_build_once()
        self.assertEqual(first_build, second_build)

    def test_readme_documents_build_and_guardrails_entrypoints(self):
        content = README_PATH.read_text(encoding="utf-8")
        self.assertIn("advArchiver/scripts/build_single_file.py", content)
        self.assertIn("advArchiver/tests/test_real_cli_guardrails.py", content)
        self.assertIn(".github/workflows/advarchiver-integration.yml", content)
