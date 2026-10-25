"""Regression controls for exact scoped checkout publication; Actions only."""

import hashlib
import json
import re
import unittest
from pathlib import Path

from resolve_source import resolve


class SourceBindingContracts(unittest.TestCase):
    def setUp(self):
        self.current = "c01f87b15cbda1b0468e7ba4887251858a845c64"
        self.stale = "88e2d5d70eb7f90afc56c8e9dd4aae8f6bd9cd9f"
        self.tree = "5d6e5ce68461f81061e0c89b74dba6c158d12944"

    def inputs(self, lock_commit=None, export_commit=None):
        lock = json.dumps(
            {
                "firmware_mcp": {
                    "repository": "JasonPeng2019/BYO-Firmware-MCP",
                    "branch": "validation/example",
                    "commit": lock_commit or self.current,
                }
            }
        ).encode()
        index = json.dumps(
            {
                "files": {
                    "release/source-lock.json": {
                        "bytes": len(lock),
                        "sha256": hashlib.sha256(lock).hexdigest(),
                    }
                },
                "firmware_export": {
                    "commit": export_commit or self.current,
                    "tree": self.tree,
                },
            }
        ).encode()
        return index, lock, hashlib.sha256(index).hexdigest()

    def test_exact_export_is_the_checkout(self):
        result = resolve(*self.inputs())
        self.assertEqual(result["firmware"], self.current)
        self.assertEqual(result["firmware_tree"], self.tree)

    def test_same_tree_stale_commit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "commits differ"):
            resolve(*self.inputs(lock_commit=self.stale))

    def test_mutated_lock_is_rejected(self):
        index, lock, digest = self.inputs()
        with self.assertRaisesRegex(ValueError, "lock bytes differ"):
            resolve(index, lock + b" ", digest)

    def test_mutated_input_index_is_rejected(self):
        index, lock, digest = self.inputs()
        with self.assertRaisesRegex(ValueError, "index SHA256 mismatch"):
            resolve(index + b" ", lock, digest)

    def test_both_scoped_workflows_derive_checkout_from_resolver(self):
        workflow = Path(__file__).with_name("build-and-native.yml").read_text(encoding="utf-8")
        for job in ("fr13-native", "fr13-linux"):
            with self.subTest(job=job):
                section = re.split(
                    r"\n  [a-zA-Z0-9_-]+:",
                    workflow.split("\n  " + job + ":", 1)[1],
                    maxsplit=1,
                )[0]
                self.assertIn("id: frozen-source", section)
                self.assertIn("resolve_source.py --github-output", section)
                self.assertIn("ref: ${{ steps.frozen-source.outputs.firmware }}", section)
                self.assertNotIn("ref: " + self.stale, section)


if __name__ == "__main__":
    unittest.main()
