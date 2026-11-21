"""Import locally supplied Ed25519-signed hash feeds; performs no network fetch.

An unsigned or unverifiable feed is always refused. The operator provisions the
trusted publisher public key out of band.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from core.exceptions import ASEThreatFeedError


class ASEThreatFeed:
    def __init__(self, antivirus, state_path="storage/antivirus/feed_state.json"):
        self.antivirus = antivirus
        self.state_path = Path(state_path)

    @staticmethod
    def _canonical(payload):
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def verify(self, envelope, public_key_hex):
        """Verify an envelope without writing anything. Returns the payload."""
        try:
            signature = base64.b64decode(envelope["signature"], validate=True)
            public_key = bytes.fromhex(public_key_hex)
        except (KeyError, ValueError, TypeError) as exc:
            raise ASEThreatFeedError("Feed envelope or key is malformed") from exc
        if len(public_key) != 32:
            raise ASEThreatFeedError("Ed25519 public key must be 32 bytes of hex")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError as exc:
            raise ASEThreatFeedError(
                "Ed25519 verification requires the optional 'cryptography' package") from exc
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            raise ASEThreatFeedError("Feed payload must be an object")
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, self._canonical(payload))
        except Exception as exc:
            raise ASEThreatFeedError("Feed signature verification failed") from exc
        return payload

    def _validate_payload(self, payload):
        version = payload.get("version")
        hashes = payload.get("sha256")
        if not isinstance(version, int) or version < 1:
            raise ASEThreatFeedError("Feed version must be a positive integer")
        if not isinstance(hashes, list):
            raise ASEThreatFeedError("Feed must contain a sha256 list")
        for item in hashes:
            if (not isinstance(item, str) or len(item) != 64
                    or any(char not in "0123456789abcdefABCDEF" for char in item)):
                raise ASEThreatFeedError("Invalid SHA-256 entry in feed")
        return version, sorted({item.lower() for item in hashes})

    def _previous_version(self):
        if not self.state_path.exists():
            return 0
        try:
            return int(json.loads(self.state_path.read_text("utf-8")).get("version", 0))
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ASEThreatFeedError("Feed state unreadable; refusing update") from exc

    def import_signed(self, envelope_path, public_key_hex):
        """Verify and apply a signed feed. Rejects rollback and duplicates."""
        try:
            envelope = json.loads(Path(envelope_path).read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ASEThreatFeedError("Feed file could not be read as JSON") from exc
        if not isinstance(envelope, dict):
            raise ASEThreatFeedError("Feed envelope must be an object")

        payload = self.verify(envelope, public_key_hex)
        version, hashes = self._validate_payload(payload)

        previous = self._previous_version()
        if version <= previous:
            raise ASEThreatFeedError("Feed rollback or duplicate version refused")

        base_dir = Path(getattr(self.antivirus, "base_dir", "storage/antivirus"))
        signatures_path = Path(getattr(self.antivirus, "signatures_path",
                                       base_dir / "signatures.json"))
        base_dir.mkdir(parents=True, exist_ok=True)

        tmp = Path(str(signatures_path) + ".tmp")
        tmp.write_text(json.dumps({"sha256": hashes, "feed_version": version}, indent=2), "utf-8")
        tmp.replace(signatures_path)

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        state_tmp = Path(str(self.state_path) + ".tmp")
        state_tmp.write_text(json.dumps({"version": version}, indent=2), "utf-8")
        state_tmp.replace(self.state_path)

        return {"version": version, "hashes": len(hashes), "signature_verified": True}
