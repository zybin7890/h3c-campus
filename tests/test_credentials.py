"""Credential persistence, permissions, and authenticated data checks."""

import stat
import sys
import tempfile
import unittest
from pathlib import Path
from cryptography.exceptions import InvalidTag

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "usr/lib/h3c-campus"))
from h3c_credentials import CredentialStore


class CredentialsTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory(prefix="h3c-credentials-test-")
        self.store = CredentialStore(self.home.name)

    def tearDown(self):
        self.home.cleanup()

    def test_save_reopen_and_clear(self):
        self.assertIsNone(self.store.load())
        self.store.save("sample-user", "sample-password")
        reopened = CredentialStore(self.home.name)
        self.assertEqual(reopened.load(), {"username": "sample-user", "password": "sample-password"})
        ciphertext = self.store.secret.read_bytes()
        self.assertNotIn(b"sample-user", ciphertext)
        self.assertNotIn(b"sample-password", ciphertext)
        for path in (self.store.secret, self.store.key):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for path in (self.store.directory, self.store.key_directory):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.store.clear()
        self.assertIsNone(reopened.load())
        self.assertFalse(self.store.key.exists())

    def test_tampered_ciphertext_is_rejected(self):
        self.store.save("sample-user", "sample-password")
        data = bytearray(self.store.secret.read_bytes())
        data[-1] ^= 1
        self.store.secret.write_bytes(data)
        with self.assertRaises(InvalidTag):
            self.store.load()

    def test_secret_with_broad_permissions_is_rejected(self):
        self.store.save("sample-user", "sample-password")
        self.store.secret.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.store.load()

    def test_symlinked_config_directory_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="h3c-symlink-target-") as outside:
            Path(self.home.name, ".config").symlink_to(outside, target_is_directory=True)
            with self.assertRaises((OSError, ValueError)):
                self.store.save("sample-user", "sample-password")
            self.assertFalse(Path(outside, "h3c-campus/credentials.enc").exists())


if __name__ == "__main__":
    unittest.main()
