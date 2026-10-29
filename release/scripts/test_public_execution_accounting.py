"""Accounting controls only; no MCP, model, client, store or target execution."""

import copy
import unittest

from final_public_mcp import LOCAL_CASES, execution_accounting


class ExecutionAccounting(unittest.TestCase):
    def records(self):
        return [
            {
                "case": name,
                "outcome": status,
                "execution_scope": "LOCAL",
                "mandatory_local_acceptance": True,
            }
            for name, status in LOCAL_CASES.items()
        ]

    def test_local_raw_nonpasses_remain_open_with_nonempty_ci_pass(self):
        records = self.records() + [{"case": "deterministic", "outcome": "PASS"}]
        before = copy.deepcopy(records)
        result = execution_accounting(records)
        self.assertEqual(result["applicable_ci_outcome"], "PASS")
        self.assertEqual(result["applicable_ci_count"], 1)
        self.assertFalse(result["mandatory_local_acceptance_complete"])
        self.assertEqual(records, before)
        self.assertEqual(
            [item["raw_outcome"] for item in result["mandatory_local_cases"]],
            list(LOCAL_CASES.values()),
        )

    def test_unexpected_nonpass_is_never_exempted(self):
        for status in (
            "FAIL",
            "ERROR",
            "BLOCKED",
            "SKIP",
            "UNRUN",
            "UNVERIFIED",
            "UNKNOWN",
        ):
            for scope in ("CI", "LOCAL"):
                with self.subTest(status=status, scope=scope):
                    records = self.records() + [
                        {
                            "case": "unexpected",
                            "outcome": status,
                            "execution_scope": scope,
                        }
                    ]
                    self.assertEqual(
                        execution_accounting(records)["applicable_ci_outcome"], "FAIL"
                    )

    def test_empty_partial_and_unqualified_local_sets_fail(self):
        valid = self.records() + [{"case": "deterministic", "outcome": "PASS"}]
        variants = [
            [],
            self.records(),
            valid[1:],
            [*valid, valid[-1]],
            [{**record, "mandatory_local_acceptance": False} for record in valid],
        ]
        for records in variants:
            with self.subTest(records=records):
                self.assertEqual(
                    execution_accounting(records)["applicable_ci_outcome"], "FAIL"
                )
        for name in LOCAL_CASES:
            records = copy.deepcopy(valid)
            next(record for record in records if record["case"] == name)["outcome"] = (
                "PASS"
            )
            self.assertEqual(
                execution_accounting(records)["applicable_ci_outcome"], "FAIL"
            )


if __name__ == "__main__":
    unittest.main()
