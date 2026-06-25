"""Secure File Encryption API — FastAPI Entry Point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import create_tables
from app.routes import auth, files

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Secure File Encryption API...")
    create_tables()
    logger.info("Database tables ready.")
    yield
    logger.info("Shutting down.")


app = FastAPI(
    title="Secure File Encryption API",
    description=(
        "Production-grade file encryption service: AES-256-GCM encryption, "
        "Azure Blob Storage, per-user HKDF key derivation, HMAC integrity checks, "
        "RBAC, and complete audit logging for every cryptographic operation."
    ),
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

app.include_router(auth.router)
app.include_router(files.router)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "secure-file-encryption"}


@app.get("/")
def root():
    return {"service": "Secure File Encryption API", "docs": "/docs", "health": "/health"}
