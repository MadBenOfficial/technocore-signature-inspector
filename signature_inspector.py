#!/usr/bin/env python3
"""Inspect and verify canonical Technocore signed-message payloads."""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_MESSAGE_CHARS = 4096
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{86}")
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
ED25519_MULTICODEC = b"\xed\x01"
BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {character: index for index, character in enumerate(BASE58BTC_ALPHABET)}


class InspectionError(ValueError):
    """Input is not a valid Technocore signed-message field."""


@dataclass(frozen=True)
class Replacement:
    index: int
    codepoint: str
    category: str
    name: str


def validate_room(room: str) -> str:
    if not isinstance(room, str) or NAME_PATTERN.fullmatch(room) is None:
        raise InspectionError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    return room


def validate_nonce(nonce: str | int) -> str:
    value = str(nonce)
    if NONCE_PATTERN.fullmatch(value) is None:
        raise InspectionError("nonce must contain 1-19 ASCII digits")
    return value


def normalize_text(text: str) -> tuple[str, list[Replacement]]:
    if not isinstance(text, str):
        raise InspectionError("text must be a string")
    output: list[str] = []
    replacements: list[Replacement] = []
    for index, character in enumerate(text):
        category = unicodedata.category(character)
        if category in INVISIBLE_CATEGORIES:
            output.append(" ")
            replacements.append(
                Replacement(
                    index=index,
                    codepoint=f"U+{ord(character):04X}",
                    category=category,
                    name=unicodedata.name(character, "UNNAMED"),
                )
            )
        else:
            output.append(character)
    normalized = "".join(output).strip()
    if not normalized:
        raise InspectionError("text has no visible content after normalization")
    if len(normalized) > MAX_MESSAGE_CHARS:
        raise InspectionError(
            f"normalized text has {len(normalized)} characters; maximum is {MAX_MESSAGE_CHARS}"
        )
    return normalized, replacements


def inspect_payload(room: str, nonce: str | int, text: str) -> dict[str, Any]:
    valid_room = validate_room(room)
    valid_nonce = validate_nonce(nonce)
    normalized, replacements = normalize_text(text)
    payload = f"{valid_room}|{valid_nonce}|{normalized}"
    encoded = payload.encode("utf-8")
    return {
        "room": valid_room,
        "nonce": valid_nonce,
        "input_text": text,
        "normalized_text": normalized,
        "changed": normalized != text,
        "replacements": [asdict(item) for item in replacements],
        "payload": payload,
        "payload_utf8_hex": encoded.hex(),
        "payload_bytes": len(encoded),
    }


def base58btc_decode(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            digit = BASE58BTC_INDEX[character]
        except KeyError as error:
            raise InspectionError(f"invalid base58btc character: {character!r}") from error
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + decoded


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not isinstance(did, str) or not did.startswith("did:key:z6Mk"):
        raise InspectionError("DID must be a canonical Ed25519 did:key:z6Mk identifier")
    multibase = did.removeprefix("did:key:")
    if len(multibase) != 48 or not multibase.startswith("z6Mk"):
        raise InspectionError("DID must use the canonical 48-character multibase form")
    decoded = base58btc_decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(ED25519_MULTICODEC):
        raise InspectionError("DID does not contain an Ed25519 public key")
    try:
        return Ed25519PublicKey.from_public_bytes(decoded[2:])
    except ValueError as error:
        raise InspectionError("DID contains invalid Ed25519 key material") from error


def verify_signature(did: str, signature: str, payload: bytes) -> None:
    if SIGNATURE_PATTERN.fullmatch(signature or "") is None:
        raise InspectionError("signature must be 86 unpadded base64url characters")
    try:
        raw_signature = base64.urlsafe_b64decode(signature + "==")
    except ValueError as error:
        raise InspectionError("signature is not valid base64url") from error
    try:
        public_key_from_did(did).verify(raw_signature, payload)
    except InvalidSignature as error:
        raise InspectionError("signature does not match the DID and canonical payload") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_parser = commands.add_parser("inspect", help="show the canonical payload")
    inspect_parser.add_argument("room")
    inspect_parser.add_argument("nonce")
    inspect_parser.add_argument("text")
    verify_parser = commands.add_parser("verify", help="verify a signature")
    verify_parser.add_argument("room")
    verify_parser.add_argument("nonce")
    verify_parser.add_argument("text")
    verify_parser.add_argument("did")
    verify_parser.add_argument("signature")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = inspect_payload(args.room, args.nonce, args.text)
        if args.command == "verify":
            verify_signature(args.did, args.signature, result["payload"].encode("utf-8"))
            result["did"] = args.did
            result["signature_valid"] = True
    except InspectionError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
