"""
PostgreSQL Database Models.
Stores users, file metadata, and audit logs.
Actual file content lives in Azure Blob Storage — only metadata here.
"""

import enum
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, Enum, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

from app.config import get_settings

settings = get_settings()

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_size=10)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True)
    # Per-user AES key expiry tracking
    key_created_at = Column(DateTime(timezone=True), server_default=func.now())
    key_expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class FileRecord(Base):
    """
    File metadata stored in PostgreSQL.
    Actual encrypted content stored in Azure Blob Storage.
    """
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, nullable=False, index=True)
    original_filename = Column(String(500), nullable=False)
    blob_name = Column(String(500), nullable=False, unique=True)  # Azure blob key
    file_size = Column(BigInteger, nullable=False)
    content_type = Column(String(100), nullable=True)
    hmac_signature = Column(String(500), nullable=False)  # Integrity check
    encryption_version = Column(String(20), default="AES-256-GCM")
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class FileAccess(Base):
    """Tracks who has access to shared files."""
    __tablename__ = "file_access"
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, nullable=False, index=True)
    granted_to_user_id = Column(Integer, nullable=False)
    granted_by_user_id = Column(Integer, nullable=False)
    can_read = Column(Boolean, default=True)
    can_delete = Column(Boolean, default=False)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """
    Complete audit log for every cryptographic operation.
    Required for security compliance.
    """
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    action = Column(String(100), nullable=False)   # FILE_UPLOAD, FILE_DOWNLOAD, FILE_DELETE, KEY_EXPIRED
    file_id = Column(Integer, nullable=True)
    ip_address = Column(String(45), nullable=True)
    status = Column(String(20), nullable=False)    # SUCCESS or FAILURE
    details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    Base.metadata.create_all(bind=engine)
