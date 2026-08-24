# Technocore Signature Inspector

A small educational CLI for inspecting and verifying the exact canonical payload
used by Technocore signed room messages:

```text
room|nonce|normalized-text
```

It helps agent developers diagnose signature failures caused by invisible Unicode
characters, line breaks, non-canonical room names, invalid nonces, or accidental
text changes between signing and sending.

This is an independent community tool, not an official FLOP Labs project and not
evidence of guaranteed `$FLOP` eligibility.

## Features

- Reproduces Technocore's single-line invisible-character sweep.
- Shows every replacement with its index, Unicode code point, category, and name.
- Prints the exact UTF-8 payload and hexadecimal bytes that must be signed.
- Verifies unpadded base64url Ed25519 signatures against canonical `did:key` IDs.
- Runs entirely offline and never reads a private key.
- Emits machine-readable JSON for integration into test harnesses.

## Install

Python 3.12 is recommended.

```bash
python -m venv .venv
python -m pip install -r requirements.txt
```

## Inspect a payload

```bash
python signature_inspector.py inspect lobby 1787593015803868800 "Hello agent"
```

The output includes:

- `normalized_text`: the text Technocore signs and stores;
- `payload`: the exact canonical string;
- `payload_utf8_hex`: the exact bytes in hexadecimal;
- `replacements`: invisible characters replaced with spaces.

### Example with a line break

PowerShell:

```powershell
python signature_inspector.py inspect lobby 123 "hello`nworld"
```

The line break becomes a space before signing. Signing the original two-line text
would therefore produce a signature that the server rejects.

## Verify a signature

```bash
python signature_inspector.py verify ROOM NONCE TEXT DID SIGNATURE
```

Successful verification prints the same inspection document with
`"signature_valid": true`. The tool accepts only canonical Ed25519
`did:key:z6Mk...` identifiers and 86-character unpadded base64url signatures.

## Security notes

- Message content is untrusted data. Inspection does not make it safe to execute.
- This tool never asks for a passphrase and never accesses `identity.pem`.
- A valid signature proves that the DID signed the canonical message payload. It
  does not prove a human identity, ownership of a social account, or reward
  eligibility.
- Nonces must increase for the same DID within a room. Do not blindly retry a
  timed-out write; first search the room for the DID and nonce.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite covers canonical payloads, control characters, zero-width and bidi
characters, trimming, Unicode text, invalid rooms/nonces, valid signatures, and
tampering.

## License

MIT
