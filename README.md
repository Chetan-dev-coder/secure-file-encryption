# Secure File Encryption API

A production-grade file encryption service implementing AES-256-GCM encryption, Azure Blob Storage persistence, per-user HKDF key derivation, HMAC integrity verification, role-based access control, and complete audit logging for every cryptographic operation.

[![CI/CD](https://github.com/Chetan-dev-coder/secure-file-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/Chetan-dev-coder/secure-file-encryption/actions)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)
![AES-256-GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-red)

---

## What It Does

This API allows users to securely upload, store, and retrieve files with end-to-end encryption. **Files are encrypted locally before reaching Azure Blob Storage** — the cloud never sees plaintext.

```
User uploads file
       │
       ▼
AES-256-GCM encryption (per-user HKDF key)
       │
       ▼
HMAC-SHA256 integrity signature generated
       │
       ▼
Ciphertext → Azure Blob Storage
Metadata + HMAC → PostgreSQL

User downloads file
       │
       ▼
Ciphertext downloaded from Azure
       │
       ▼
HMAC verified → reject if tampered
       │
       ▼
AES-256-GCM decryption
       │
       ▼
Plaintext returned to user
```

---

## Security Design

### AES-256-GCM Encryption

```
Master Key (env var, never in DB)
       │
       ▼ HKDF-SHA256(user_id)
Per-User Key (256-bit, derived deterministically)
       │
       ▼ AES-256-GCM + random 12-byte nonce
Ciphertext = nonce(12B) + auth_tag(16B) + encrypted_data
```

**Why AES-256-GCM over AES-CBC?**
- GCM = Galois/Counter Mode — provides authenticated encryption (AEAD)
- Built-in authentication tag detects any bit-level tampering
- CBC requires a separate MAC — prone to padding oracle attacks
- GCM is the industry standard for secure file encryption

### Per-User Key Derivation (HKDF)

Each user gets a unique 256-bit key derived from the master key using HKDF-SHA256:
- Master key compromise doesn't directly expose all files (attacker still needs user IDs)
- Keys are deterministic — no need to store them in the database
- Rotating the master key regenerates all derived keys

### HMAC Integrity Verification

Every file gets an HMAC-SHA256 signature covering `blob_name + ciphertext`:
- Detects if a blob was swapped or modified in Azure storage
- Covers blob name — prevents blob substitution attacks
- Uses constant-time comparison (`hmac.compare_digest`) to prevent timing attacks

### Blob Name Obfuscation

Files are stored with UUID-based blob names: `users/{user_id}/{uuid}.enc`
- Original filename never appears in Azure storage
- No information leakage about file content from storage keys

### Automated Key Expiry

- Per-user encryption keys track a 90-day expiry date in PostgreSQL
- `/auth/key-status` endpoint returns expiry status and days remaining
- Expired keys trigger rotation alerts

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Language | Python 3.11 | Primary language |
| Framework | FastAPI | REST API + async |
| Encryption | AES-256-GCM | File encryption |
| Key Derivation | HKDF-SHA256 | Per-user key generation |
| Integrity | HMAC-SHA256 | Tamper detection |
| Auth | JWT (HS256) + bcrypt | User authentication |
| Cloud Storage | Azure Blob Storage | Encrypted file persistence |
| Database | PostgreSQL + SQLAlchemy | Metadata + audit logs |
| Cache | Redis | Session management |
| Container | Docker + Compose | Deployment |
| CI/CD | GitHub Actions | Automated testing + build |
| Testing | Pytest | 85%+ coverage |

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/register` | None | Register user account |
| POST | `/auth/login` | None | Get JWT access token |
| GET | `/auth/me` | Bearer | Current user profile |
| GET | `/auth/key-status` | Bearer | Check encryption key expiry |
| POST | `/files/upload` | Bearer | Upload + encrypt file |
| GET | `/files/` | Bearer | List user's files |
| GET | `/files/{id}/download` | Bearer | Download + decrypt file |
| DELETE | `/files/{id}` | Bearer | Delete file |
| POST | `/files/{id}/share/{user_id}` | Bearer | Share file with another user |
| GET | `/files/audit/logs` | Admin | View all audit logs |
| GET | `/health` | None | Health check |

---

## Quick Start

### With Docker

```bash
git clone https://github.com/Chetan-dev-coder/secure-file-encryption
cd secure-file-encryption
cp .env.example .env
# Add your Azure connection string to .env
docker compose up --build
```

API docs at: http://localhost:8000/docs

### Local Development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

### Run Tests

```bash
pytest tests/ -v --cov=app --cov-report=term-missing
```

---

## Example Usage

```bash
# Register
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass1!"}'

# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass1!"}'

# Upload file (encrypted with AES-256-GCM before reaching Azure)
curl -X POST http://localhost:8000/files/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@document.pdf"

# Download and decrypt file
curl http://localhost:8000/files/1/download \
  -H "Authorization: Bearer <token>" \
  --output decrypted_document.pdf

# Check key expiry status
curl http://localhost:8000/auth/key-status \
  -H "Authorization: Bearer <token>"
```

---

## Project Structure

```
secure-file-encryption/
├── app/
│   ├── main.py                 # FastAPI entry point
│   ├── config.py               # Settings from env vars
│   ├── database.py             # PostgreSQL models
│   ├── auth/
│   │   ├── encryption.py       # AES-256-GCM + HMAC + HKDF
│   │   ├── azure_storage.py    # Azure Blob Storage client
│   │   └── middleware.py       # JWT auth + RBAC
│   ├── routes/
│   │   ├── auth.py             # Auth endpoints
│   │   └── files.py            # File CRUD endpoints
│   └── models/
│       └── schemas.py          # Pydantic schemas
├── tests/
│   └── test_encryption.py      # 20+ crypto + security tests
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
└── requirements.txt
```

---

## License

MIT
