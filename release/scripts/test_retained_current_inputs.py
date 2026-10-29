"""Non-admission controls for the current retained-driver input contract.

The genuine positive is the Actions-built native invocation, not a fabricated
receipt. These malformed/stale input controls never execute a compiler/product.
"""

import argparse
import json
from pathlib import Path
import tempfile
import unittest

import test_code_analysis_installed as installed


class CurrentInputRefusals(unittest.TestCase):
    def test_wrong_receipt_hash_is_refused_before_any_build_or_native_query(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text('{"schema":"installed-current-inputs/v1"}\n')
            args = argparse.Namespace(
                ci_input_record=path, ci_input_record_sha256="0" * 64
            )
            with self.assertRaisesRegex(installed.Setup, "explicit SHA256"):
                installed.current_input_gate(args, None, Path(directory))

    def test_wrong_schema_is_not_admitted_by_a_matching_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text('{"schema":"labels-only","outcome":"PASS"}\n')
            args = argparse.Namespace(
                ci_input_record=path, ci_input_record_sha256=installed.digest(path)
            )
            with self.assertRaisesRegex(installed.Setup, "schema"):
                installed.current_input_gate(args, None, Path(directory))

    def test_equivalent_but_unbound_lock_bytes_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = installed.ROOT / "release/source-lock.json"
            stale = root / "unbound-source-lock.json"
            stale.write_text(
                json.dumps(installed.read_json(actual), separators=(",", ":"))
            )
            analysis = installed.ROOT / "release/analysis-tools.lock.json"
            record = {
                "schema": "installed-current-inputs/v1",
                "source_lock": {"path": str(stale), **installed.file_record(stale)},
                "analysis_lock": {
                    "path": str(analysis),
                    **installed.file_record(analysis),
                },
            }
            path = root / "record.json"
            path.write_text(json.dumps(record))
            args = argparse.Namespace(
                ci_input_record=path, ci_input_record_sha256=installed.digest(path)
            )
            with self.assertRaisesRegex(installed.Setup, "lock differs"):
                installed.current_input_gate(args, None, root)


if __name__ == "__main__":
    unittest.main()
