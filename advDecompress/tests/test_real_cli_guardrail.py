from pathlib import Path
import tempfile
import unittest

import real_cli_guardrail


class TestRealCliGuardrail(unittest.TestCase):
    def test_collect_metadata_backend_diagnostics_contract(self):
        diagnostics_fn = getattr(
            real_cli_guardrail,
            "_collect_metadata_backend_diagnostics",
            None,
        )
        self.assertTrue(callable(diagnostics_fn))

        with tempfile.TemporaryDirectory() as temp_dir:
            work_base = Path(temp_dir)
            diagnostics = diagnostics_fn(
                work_base,
                metadata_db_path=work_base / "metadata.sqlite",
            )

        self.assertIsInstance(diagnostics, dict)
        self.assertIn("backend_marker", diagnostics)
        self.assertIn("sqlite_metadata", diagnostics)


if __name__ == "__main__":
    unittest.main()
