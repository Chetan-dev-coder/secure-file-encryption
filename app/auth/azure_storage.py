"""
Azure Blob Storage Client for Encrypted File Persistence.

Architecture:
- Files are encrypted locally with AES-256-GCM BEFORE upload.
- Azure never sees plaintext — only ciphertext arrives at blob storage.
- Blob names are UUID-based — no information leakage from filenames.
- Metadata (original filename, owner, HMAC) stored in PostgreSQL.
"""

import logging
import uuid
from typing import Optional

from azure.storage.blob import BlobServiceClient, ContentSettings
from azure.core.exceptions import AzureError

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_blob_client: Optional[BlobServiceClient] = None


def get_blob_service() -> BlobServiceClient:
    global _blob_client
    if _blob_client is None:
        _blob_client = BlobServiceClient.from_connection_string(
            settings.AZURE_CONNECTION_STRING
        )
    return _blob_client


def generate_blob_name(user_id: int, original_filename: str) -> str:
    """
    Generate a UUID-based blob name — hides original filename in storage.
    Format: users/{user_id}/{uuid}.enc
    """
    return f"users/{user_id}/{uuid.uuid4()}.enc"


def upload_encrypted_file(
    blob_name: str,
    encrypted_data: bytes,
    content_type: str = "application/octet-stream"
) -> bool:
    """
    Upload encrypted file bytes to Azure Blob Storage.
    Content is already encrypted — this is just a raw bytes upload.
    """
    try:
        service = get_blob_service()
        container = service.get_container_client(settings.AZURE_CONTAINER_NAME)

        # Ensure container exists
        try:
            container.create_container()
        except Exception:
            pass  # Already exists

        blob_client = container.get_blob_client(blob_name)
        blob_client.upload_blob(
            encrypted_data,
            overwrite=True,
            content_settings=ContentSettings(content_type="application/octet-stream")
        )
        logger.info(f"Uploaded encrypted blob: {blob_name} ({len(encrypted_data)} bytes)")
        return True
    except AzureError as e:
        logger.error(f"Azure upload failed for {blob_name}: {e}")
        raise


def download_encrypted_file(blob_name: str) -> bytes:
    """
    Download encrypted file bytes from Azure Blob Storage.
    Caller is responsible for decryption.
    """
    try:
        service = get_blob_service()
        blob_client = service.get_blob_client(
            container=settings.AZURE_CONTAINER_NAME,
            blob=blob_name
        )
        data = blob_client.download_blob().readall()
        logger.info(f"Downloaded encrypted blob: {blob_name} ({len(data)} bytes)")
        return data
    except AzureError as e:
        logger.error(f"Azure download failed for {blob_name}: {e}")
        raise


def delete_blob(blob_name: str) -> bool:
    """Permanently delete a blob from Azure storage."""
    try:
        service = get_blob_service()
        blob_client = service.get_blob_client(
            container=settings.AZURE_CONTAINER_NAME,
            blob=blob_name
        )
        blob_client.delete_blob()
        logger.info(f"Deleted blob: {blob_name}")
        return True
    except AzureError as e:
        logger.error(f"Azure delete failed for {blob_name}: {e}")
        raise
