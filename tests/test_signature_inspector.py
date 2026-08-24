from __future__ import annotations

import base64
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import signature_inspector as inspector


def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = inspector.BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def did_from_key(private_key: Ed25519PrivateKey) -> str:
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "did:key:z" + base58btc_encode(inspector.ED25519_MULTICODEC + public)


class SignatureInspectorTests(unittest.TestCase):
    def test_canonical_payload(self):
        result = inspector.inspect_payload("lobby", "123", "Hello agent")
        self.assertEqual(result["payload"], "lobby|123|Hello agent")
        self.assertFalse(result["changed"])
        self.assertEqual(result["replacements"], [])

    def test_control_zero_width_and_bidi_characters_are_reported(self):
        result = inspector.inspect_payload("lobby", "123", "a\nb\u200dc\u202ed")
        self.assertEqual(result["normalized_text"], "a b c d")
        self.assertEqual(
            [item["codepoint"] for item in result["replacements"]],
            ["U+000A", "U+200D", "U+202E"],
        )

    def test_surrounding_whitespace_is_trimmed(self):
        result = inspector.inspect_payload("lobby", "1", "  hello  ")
        self.assertEqual(result["normalized_text"], "hello")
        self.assertTrue(result["changed"])

    def test_unicode_payload_uses_utf8(self):
        result = inspector.inspect_payload("lobby", "1", "café")
        self.assertEqual(bytes.fromhex(result["payload_utf8_hex"]), "lobby|1|café".encode())

    def test_invalid_room_is_rejected(self):
        with self.assertRaisesRegex(inspector.InspectionError, "room must match"):
            inspector.inspect_payload("Bad Room", "1", "hello")

    def test_invalid_nonce_is_rejected(self):
        with self.assertRaisesRegex(inspector.InspectionError, "nonce"):
            inspector.inspect_payload("lobby", "-1", "hello")

    def test_empty_normalized_text_is_rejected(self):
        with self.assertRaisesRegex(inspector.InspectionError, "no visible content"):
            inspector.inspect_payload("lobby", "1", "\u200d\n")

    def test_valid_signature(self):
        key = Ed25519PrivateKey.generate()
        result = inspector.inspect_payload("lobby", "123", "hello\nagent")
        signature = base64.urlsafe_b64encode(
            key.sign(result["payload"].encode("utf-8"))
        ).decode("ascii").rstrip("=")
        inspector.verify_signature(did_from_key(key), signature, result["payload"].encode())

    def test_tampered_payload_is_rejected(self):
        key = Ed25519PrivateKey.generate()
        signature = base64.urlsafe_b64encode(key.sign(b"lobby|1|original")).decode(
            "ascii"
        ).rstrip("=")
        with self.assertRaisesRegex(inspector.InspectionError, "does not match"):
            inspector.verify_signature(did_from_key(key), signature, b"lobby|1|changed")


if __name__ == "__main__":
    unittest.main()
