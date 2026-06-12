"""Tests for secure temp viewing: overwrite-wipe, temp lifecycle, verifier fallback."""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import secure_open


class TestWipe(unittest.TestCase):
    def test_overwrite_changes_content(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.bin")
            original = b"A" * 4096
            open(p, "wb").write(original)
            secure_open._overwrite_file(p)
            after = open(p, "rb").read()
            self.assertEqual(len(after), len(original))
            self.assertNotEqual(after, original)

    def test_wipe_directory_removes_everything(self):
        d = tempfile.mkdtemp()
        sub = os.path.join(d, "sub")
        os.makedirs(sub)
        open(os.path.join(d, "a.txt"), "wb").write(b"secret")
        open(os.path.join(sub, "b.txt"), "wb").write(b"secret2")
        self.assertTrue(secure_open.wipe_directory(d))
        self.assertFalse(os.path.exists(d))

    def test_wipe_directory_gives_up_after_retries(self):
        d = tempfile.mkdtemp()
        open(os.path.join(d, "a.txt"), "wb").write(b"x")
        with mock.patch.object(secure_open, "_overwrite_file", side_effect=OSError("locked")):
            self.assertFalse(secure_open.wipe_directory(d, retries=2, delay=0))
        secure_open.wipe_directory(d)


class TestViewTemp(unittest.TestCase):
    def test_view_without_launch_writes_then_wipes(self):
        captured = {}

        def fake_input(prompt=""):
            # Grab the temp path while the file exists, before wipe runs.
            return ""

        real_mkdtemp = tempfile.mkdtemp

        def spy_mkdtemp(*a, **kw):
            captured["dir"] = real_mkdtemp(*a, **kw)
            return captured["dir"]

        with mock.patch.object(tempfile, "mkdtemp", side_effect=spy_mkdtemp), \
             mock.patch("builtins.input", side_effect=fake_input):
            secure_open.view_file_temp(b"top secret", "doc.txt", launch=False)
        self.assertFalse(os.path.exists(captured["dir"]))

    def test_view_launch_calls_default_app_opener(self):
        with mock.patch.object(secure_open, "_open_with_default_app") as opener, \
             mock.patch("builtins.input", return_value=""):
            secure_open.view_file_temp(b"data", "a.txt", launch=True)
        opener.assert_called_once()

    def test_temp_file_not_world_readable(self):
        if os.name == "nt":
            self.skipTest("POSIX permissions not applicable on Windows")
        seen = {}

        def check_input(prompt=""):
            return ""

        real_mkdtemp = tempfile.mkdtemp

        def spy_mkdtemp(*a, **kw):
            seen["dir"] = real_mkdtemp(*a, **kw)
            return seen["dir"]

        real_fdopen = os.fdopen

        def spy_fdopen(fd, *a, **kw):
            f = real_fdopen(fd, *a, **kw)
            seen["mode"] = os.fstat(f.fileno()).st_mode & 0o777
            return f

        with mock.patch.object(tempfile, "mkdtemp", side_effect=spy_mkdtemp), \
             mock.patch.object(os, "fdopen", side_effect=spy_fdopen), \
             mock.patch("builtins.input", side_effect=check_input):
            secure_open.view_file_temp(b"x", "f.txt", launch=False)
        self.assertEqual(seen["mode"], 0o600)


class TestVerifierChain(unittest.TestCase):
    def test_first_available_provider_decides(self):
        providers = [
            ("unavailable", lambda: None),
            ("yes", lambda: True),
            ("never reached", lambda: (_ for _ in ()).throw(AssertionError)),
        ]
        with mock.patch.object(secure_open, "_PROVIDERS", providers):
            self.assertTrue(secure_open.verify_device_identity())

    def test_failed_verification_blocks(self):
        providers = [("denies", lambda: False)]
        with mock.patch.object(secure_open, "_PROVIDERS", providers):
            self.assertFalse(secure_open.verify_device_identity())

    def test_no_provider_asks_user(self):
        providers = [("unavailable", lambda: None)]
        with mock.patch.object(secure_open, "_PROVIDERS", providers), \
             mock.patch("builtins.input", return_value="n"):
            self.assertFalse(secure_open.verify_device_identity())
        with mock.patch.object(secure_open, "_PROVIDERS", providers), \
             mock.patch("builtins.input", return_value="y"):
            self.assertTrue(secure_open.verify_device_identity())


if __name__ == "__main__":
    unittest.main()
