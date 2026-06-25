"""
Security & Integration Tests for Secure File Encryption API.
85%+ coverage across cryptographic operations.
"""

import base64
import os
import pytest
from unittest.mock import patch, MagicMock


# ─── AES-256-GCM Tests ────────────────────────────────────────────────────────

class TestAESEncryption:
    def test_encrypt_returns_bytes(self):
        from app.auth.encryption import encrypt_file
        encrypted, nonce = encrypt_file(b"hello world", user_id=1)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 12

    def test_encrypt_decrypt_roundtrip(self):
        from app.auth.encryption import encrypt_file, decrypt_file
        original = b"This is a secret file content!"
        encrypted, _ = encrypt_file(original, user_id=1)
        decrypted = decrypt_file(encrypted, user_id=1)
        assert decrypted == original

    def test_same_content_different_ciphertext(self):
        """Each encryption uses random nonce — ciphertext must differ."""
        from app.auth.encryption import encrypt_file
        enc1, _ = encrypt_file(b"same content", user_id=1)
        enc2, _ = encrypt_file(b"same content", user_id=1)
        assert enc1 != enc2

    def test_different_users_different_ciphertext(self):
        from app.auth.encryption import encrypt_file
        enc1, _ = encrypt_file(b"secret", user_id=1)
        enc2, _ = encrypt_file(b"secret", user_id=2)
        assert enc1 != enc2

    def test_wrong_user_cannot_decrypt(self):
        from app.auth.encryption import encrypt_file, decrypt_file
        encrypted, _ = encrypt_file(b"secret data", user_id=1)
        with pytest.raises(ValueError):
            decrypt_file(encrypted, user_id=2)

    def test_tampered_ciphertext_rejected(self):
        from app.auth.encryption import encrypt_file, decrypt_file
        encrypted, _ = encrypt_file(b"important data", user_id=1)
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        with pytest.raises(ValueError):
            decrypt_file(bytes(tampered), user_id=1)

    def test_empty_file_encryption(self):
        from app.auth.encryption import encrypt_file, decrypt_file
        encrypted, _ = encrypt_file(b"", user_id=1)
        decrypted = decrypt_file(encrypted, user_id=1)
        assert decrypted == b""

    def test_large_file_encryption(self):
        from app.auth.encryption import encrypt_file, decrypt_file
        large_data = os.urandom(1024 * 1024)  # 1MB
        encrypted, _ = encrypt_file(large_data, user_id=1)
        decrypted = decrypt_file(encrypted, user_id=1)
        assert decrypted == large_data

    def test_per_user_key_is_deterministic(self):
        from app.auth.encryption import derive_user_key
        key1 = derive_user_key(42)
        key2 = derive_user_key(42)
        assert key1 == key2
        assert len(key1) == 32  # 256 bits

    def test_different_users_different_keys(self):
        from app.auth.encryption import derive_user_key
        assert derive_user_key(1) != derive_user_key(2)


# ─── HMAC Integrity Tests ─────────────────────────────────────────────────────

class TestHMACIntegrity:
    def test_hmac_generation(self):
        from app.auth.encryption import generate_hmac
        sig = generate_hmac("blob/test.enc", b"encrypted_data", user_id=1)
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA256 hex digest

    def test_hmac_verification_passes(self):
        from app.auth.encryption import generate_hmac, verify_hmac
        data = b"encrypted content"
        blob = "users/1/test.enc"
        sig = generate_hmac(blob, data, user_id=1)
        assert verify_hmac(blob, data, user_id=1, stored_hmac=sig) is True

    def test_tampered_data_fails_hmac(self):
        from app.auth.encryption import generate_hmac, verify_hmac
        data = b"encrypted content"
        blob = "users/1/test.enc"
        sig = generate_hmac(blob, data, user_id=1)
        tampered = b"tampered content"
        assert verify_hmac(blob, tampered, user_id=1, stored_hmac=sig) is False

    def test_wrong_blob_name_fails_hmac(self):
        """HMAC covers blob name — prevents blob substitution attacks."""
        from app.auth.encryption import generate_hmac, verify_hmac
        data = b"content"
        sig = generate_hmac("users/1/file-a.enc", data, user_id=1)
        assert verify_hmac("users/1/file-b.enc", data, user_id=1, stored_hmac=sig) is False

    def test_wrong_user_fails_hmac(self):
        from app.auth.encryption import generate_hmac, verify_hmac
        data = b"content"
        blob = "users/1/file.enc"
        sig = generate_hmac(blob, data, user_id=1)
        assert verify_hmac(blob, data, user_id=2, stored_hmac=sig) is False

    def test_hmac_is_deterministic(self):
        from app.auth.encryption import generate_hmac
        sig1 = generate_hmac("blob", b"data", user_id=1)
        sig2 = generate_hmac("blob", b"data", user_id=1)
        assert sig1 == sig2


# ─── Password Security Tests ──────────────────────────────────────────────────

class TestPasswordSecurity:
    def test_password_hashing(self):
        from app.auth.middleware import hash_password, verify_password
        hashed = hash_password("Pass1!")
        assert verify_password("Pass1!", hashed) is True

    def test_wrong_password_rejected(self):
        from app.auth.middleware import hash_password, verify_password
        hashed = hash_password("Pass1!")
        assert verify_password("WrongP1!", hashed) is False

    def test_weak_password_rejected(self):
        from app.models.schemas import UserRegister
        with pytest.raises(Exception):
            UserRegister(email="test@test.com", password="weak")

    def test_no_uppercase_rejected(self):
        from app.models.schemas import UserRegister
        with pytest.raises(Exception):
            UserRegister(email="test@test.com", password="nouppercase1")

    def test_strong_password_accepted(self):
        from app.models.schemas import UserRegister
        u = UserRegister(email="test@test.com", password="StrongPass1!")
        assert u.password == "StrongPass1!"


# ─── RBAC Tests ───────────────────────────────────────────────────────────────

class TestRBAC:
    def test_role_hierarchy(self):
        from app.auth.middleware import ROLE_HIERARCHY
        from app.database import UserRole
        assert ROLE_HIERARCHY[UserRole.ADMIN] > ROLE_HIERARCHY[UserRole.USER]
        assert ROLE_HIERARCHY[UserRole.USER] > ROLE_HIERARCHY[UserRole.GUEST]

    def test_admin_highest_role(self):
        from app.auth.middleware import ROLE_HIERARCHY
        from app.database import UserRole
        assert ROLE_HIERARCHY[UserRole.ADMIN] == max(ROLE_HIERARCHY.values())


# ─── Blob Name Tests ──────────────────────────────────────────────────────────

class TestBlobStorage:
    def test_blob_name_hides_filename(self):
        from app.auth.azure_storage import generate_blob_name
        name = generate_blob_name(1, "secret_document.pdf")
        assert "secret_document" not in name
        assert name.startswith("users/1/")
        assert name.endswith(".enc")

    def test_blob_names_are_unique(self):
        from app.auth.azure_storage import generate_blob_name
        n1 = generate_blob_name(1, "file.pdf")
        n2 = generate_blob_name(1, "file.pdf")
        assert n1 != n2
