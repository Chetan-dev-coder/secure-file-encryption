"""
AES-256-GCM File Encryption with HMAC Integrity Verification.

How it works:
1. Each user gets a unique 256-bit AES key derived via HKDF from the master key.
2. Every file encryption uses a random 12-byte nonce (IV) — same file encrypted twice = different ciphertext.
3. GCM mode provides both encryption AND authentication tag (AEAD).
4. HMAC-SHA256 provides an additional integrity layer over the blob name + ciphertext.
5. Format stored in Azure: nonce(12B) + auth_tag(16B) + ciphertext

Why AES-256-GCM over AES-CBC?
- GCM: authenticated encryption — detects tampering without extra HMAC on ciphertext.
- CBC: encryption only — needs separate MAC, prone to padding oracle attacks.
"""

import base64
import hashlib
import hmac
import os
import logging
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def _master_key() -> bytes:
    return base64.b64decode(settings.AES_MASTER_KEY)


def derive_user_key(user_id: int) -> bytes:
    """
    Derive a unique 256-bit AES key per user using HKDF-SHA256.

    Why per-user keys?
    - If one user's encrypted files are compromised, others are unaffected.
    - Keys are derived deterministically — no need to store them.
    - Master key rotation regenerates all derived keys automatically.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"file-encryption-user-{user_id}".encode(),
        backend=default_backend()
    )
    return hkdf.derive(_master_key())


def encrypt_file(data: bytes, user_id: int) -> Tuple[bytes, str]:
    """
    Encrypt file bytes using AES-256-GCM.

    Returns:
        Tuple of (encrypted_bytes, nonce_b64)
        encrypted_bytes format: nonce(12) + tag(16) + ciphertext
    """
    key = derive_user_key(user_id)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Unique per encryption
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)
    encrypted = nonce + ciphertext_with_tag
    logger.info(f"File encrypted for user_id={user_id}, size={len(data)} bytes")
    return encrypted, base64.b64encode(nonce).decode()


def decrypt_file(encrypted_data: bytes, user_id: int) -> bytes:
    """
    Decrypt file bytes using AES-256-GCM.

    Raises:
        ValueError: If decryption fails (wrong key or tampered data).
    """
    try:
        key = derive_user_key(user_id)
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:12]
        ciphertext_with_tag = encrypted_data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        logger.info(f"File decrypted for user_id={user_id}")
        return plaintext
    except Exception as e:
        logger.error(f"Decryption failed for user_id={user_id}: {type(e).__name__}")
        raise ValueError("Decryption failed: file may be corrupted or tampered")


def generate_hmac(blob_name: str, encrypted_data: bytes, user_id: int) -> str:
    """
    Generate HMAC-SHA256 signature over blob_name + encrypted content.

    Purpose: Detect if a blob was swapped or tampered in Azure storage.
    The HMAC covers both the blob name and content — preventing substitution attacks.
    """
    key = derive_user_key(user_id)
    mac = hmac.new(key, blob_name.encode() + encrypted_data, hashlib.sha256)
    return mac.hexdigest()


def verify_hmac(blob_name: str, encrypted_data: bytes, user_id: int, stored_hmac: str) -> bool:
    """
    Verify HMAC signature. Returns False if tampered.
    Uses constant-time comparison to prevent timing attacks.
    """
    expected = generate_hmac(blob_name, encrypted_data, user_id)
    return hmac.compare_digest(expected, stored_hmac)
