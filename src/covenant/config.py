"""Shared paths, constants, and the trusted keystore.

Keys and logs live under a single gitignored data directory so a fresh
`git clone` + `pip install -e .` starts from a clean slate. The keystore is
intentionally tiny: one Ed25519 issuer keypair, referenced by a fixed
`key_id`. The broker resolves `key_id` -> public key from this trusted
store rather than trusting a public key embedded in the token itself --
that distinction is what stops an attacker from self-signing a token that
"verifies" against a key they also control.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

DATA_DIR = Path(os.environ.get("COVENANT_DATA_DIR", ".covenant-data"))
KEY_DIR = DATA_DIR / "keys"
AUDIT_LOG_PATH = DATA_DIR / "audit.log"
HEADS_LOG_PATH = DATA_DIR / "heads.jsonl"

ISSUER_KEY_ID = "covenant-issuer-1"

DEFAULT_SUBJECT = "demo-agent"
DEFAULT_TTL_SECONDS = 15 * 60
DEFAULT_QUOTA = 10


def _private_key_path(key_id: str) -> Path:
    return KEY_DIR / f"{key_id}.ed25519.pem"


def _public_key_path(key_id: str) -> Path:
    return KEY_DIR / f"{key_id}.ed25519.pub"


def load_or_create_issuer_key(key_id: str = ISSUER_KEY_ID) -> Ed25519PrivateKey:
    """Loads the issuer's private key from disk, generating one on first run."""
    priv_path = _private_key_path(key_id)
    if priv_path.exists():
        return load_pem_private_key(priv_path.read_bytes(), password=None)  # type: ignore[return-value]

    KEY_DIR.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    priv_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public_key = private_key.public_key()
    _public_key_path(key_id).write_bytes(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    return private_key


def load_trusted_public_key(key_id: str) -> Ed25519PublicKey:
    """Resolves a key_id to a public key from the trusted local keystore.

    Raises FileNotFoundError if key_id is not a key this installation trusts --
    an attacker cannot make this succeed just by naming a key_id in a token.
    """
    pub_path = _public_key_path(key_id)
    if not pub_path.exists():
        raise FileNotFoundError(f"Unknown or untrusted key_id: {key_id!r}")
    return load_pem_public_key(pub_path.read_bytes())  # type: ignore[return-value]
