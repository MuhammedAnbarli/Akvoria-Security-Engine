"""Signed threat feed tests. Ed25519 paths skip when the optional package is absent."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from core.exceptions import ASEThreatFeedError
from modules.antivirus import ASEAntivirus
from modules.threat_feed import ASEThreatFeed

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    CRYPTO = True
except ImportError:  # pragma: no cover - optional dependency
    CRYPTO = False


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.av = ASEAntivirus(self.root / "av")
        self.av.start()
        self.feed = ASEThreatFeed(self.av, self.root / "state.json")

    def tearDown(self):
        self.av.stop()
        self.temp.cleanup()

    def _signed(self, payload, private):
        envelope = {"payload": payload,
                    "signature": base64.b64encode(private.sign(_canonical(payload))).decode()}
        path = self.root / "feed.json"
        path.write_text(json.dumps(envelope), "utf-8")
        return path

    def test_invalid_signature_rejected(self):
        path = self.root / "bad.json"
        path.write_text(json.dumps({"payload": {"version": 1, "sha256": []},
                                    "signature": "not-base64!!"}), "utf-8")
        with self.assertRaises(ASEThreatFeedError):
            self.feed.import_signed(path, "00" * 32)

    def test_unsigned_feed_rejected(self):
        path = self.root / "unsigned.json"
        path.write_text(json.dumps({"version": 1, "sha256": ["a" * 64]}), "utf-8")
        with self.assertRaises(ASEThreatFeedError):
            self.feed.import_signed(path, "00" * 32)

    def test_malformed_key_rejected(self):
        path = self.root / "x.json"
        path.write_text(json.dumps({"payload": {"version": 1, "sha256": []},
                                    "signature": base64.b64encode(b"x" * 64).decode()}), "utf-8")
        with self.assertRaises(ASEThreatFeedError):
            self.feed.import_signed(path, "abcd")

    @unittest.skipUnless(CRYPTO, "cryptography package not installed")
    def test_valid_feed_imported(self):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        path = self._signed({"version": 3, "sha256": ["a" * 64, "b" * 64]}, private)
        result = self.feed.import_signed(path, public.hex())
        self.assertTrue(result["signature_verified"])
        self.assertEqual(result["hashes"], 2)
        self.assertEqual(len(self.av._known_hashes()), 2)
        stored = json.loads(self.av.signatures_path.read_text("utf-8"))
        self.assertEqual(stored["feed_version"], 3)

    @unittest.skipUnless(CRYPTO, "cryptography package not installed")
    def test_rollback_refused(self):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        path = self._signed({"version": 5, "sha256": ["a" * 64]}, private)
        self.feed.import_signed(path, public.hex())
        with self.assertRaises(ASEThreatFeedError) as ctx:
            self.feed.import_signed(path, public.hex())
        self.assertIn("rollback", str(ctx.exception).lower())

    @unittest.skipUnless(CRYPTO, "cryptography package not installed")
    def test_wrong_key_refused(self):
        private = Ed25519PrivateKey.generate()
        other = Ed25519PrivateKey.generate()
        wrong_public = other.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        path = self._signed({"version": 2, "sha256": ["c" * 64]}, private)
        with self.assertRaises(ASEThreatFeedError):
            self.feed.import_signed(path, wrong_public.hex())

    @unittest.skipUnless(CRYPTO, "cryptography package not installed")
    def test_invalid_hash_entry_refused(self):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        path = self._signed({"version": 2, "sha256": ["not-a-hash"]}, private)
        with self.assertRaises(ASEThreatFeedError):
            self.feed.import_signed(path, public.hex())

    @unittest.skipUnless(CRYPTO, "cryptography package not installed")
    def test_bad_version_refused(self):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        path = self._signed({"version": 0, "sha256": []}, private)
        with self.assertRaises(ASEThreatFeedError):
            self.feed.import_signed(path, public.hex())


if __name__ == "__main__":
    unittest.main()
