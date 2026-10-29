"""Exact fixture byte transformations; no build or installed product invocation."""

from pathlib import Path
import tempfile
import unittest

from build_installed_profile_fixture import change


class ProfileFixtureBytes(unittest.TestCase):
    def test_lf_and_crlf_preserve_every_other_byte(self):
        for newline in (b"\n", b"\r\n"):
            with (
                self.subTest(newline=newline),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "lock"
                before = (
                    b"prefix\x00"
                    + b'name = "package"\nversion = "0.1.12"'.replace(b"\n", newline)
                    + b"\xffsuffix"
                )
                path.write_bytes(before)
                change(
                    path,
                    b'name = "package"\nversion = "0.1.12"',
                    b'name = "package"\nversion = "0.1.13"',
                )
                self.assertEqual(
                    path.read_bytes(), before.replace(b"0.1.12", b"0.1.13")
                )

    def test_absent_repeated_or_mixed_matches_refuse_without_writes(self):
        old = b"first\nsecond"
        for data in (b"absent", old + b"\n" + old, old + b"\nfirst\r\nsecond"):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "lock"
                path.write_bytes(data)
                with self.assertRaisesRegex(RuntimeError, "uniquely match"):
                    change(path, old, b"first\nchanged")
                self.assertEqual(path.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
