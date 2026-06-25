"""
File Management Routes — Upload, Download, Delete with AES-256-GCM + Azure Blob Storage.

Security flow for UPLOAD:
1. Receive file bytes in FastAPI
2. Encrypt locally with AES-256-GCM (per-user derived key)
3. Generate HMAC-SHA256 over blob_name + ciphertext
4. Upload ciphertext to Azure Blob Storage
5. Store metadata + HMAC in PostgreSQL

Security flow for DOWNLOAD:
1. Verify user owns file (or has access)
2. Download ciphertext from Azure
3. Verify HMAC — reject if tampered
4. Decrypt with AES-256-GCM
5. Stream plaintext back to user
"""

import logging
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.auth.azure_storage import generate_blob_name, upload_encrypted_file, download_encrypted_file, delete_blob
from app.auth.encryption import encrypt_file, decrypt_file, generate_hmac, verify_hmac
from app.auth.middleware import get_current_user, require_role, log_audit
from app.database import get_db, FileRecord, FileAccess, User, UserRole
from app.models.schemas import FileResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/files", tags=["Files"])

# Max file size: 100MB
MAX_FILE_SIZE = 100 * 1024 * 1024

ALLOWED_TYPES = {
    "application/pdf", "text/plain", "image/png", "image/jpeg",
    "application/json", "text/csv", "application/zip"
}


@router.post("/upload", response_model=FileResponse, status_code=201)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Upload and encrypt a file.
    File is encrypted with AES-256-GCM before reaching Azure Blob Storage.
    """
    # Read file content
    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 100MB.")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="File is empty.")

    try:
        # Step 1: Encrypt with AES-256-GCM
        encrypted_data, _ = encrypt_file(content, current_user.id)

        # Step 2: Generate unique blob name
        blob_name = generate_blob_name(current_user.id, file.filename)

        # Step 3: Generate HMAC for integrity verification
        hmac_sig = generate_hmac(blob_name, encrypted_data, current_user.id)

        # Step 4: Upload ciphertext to Azure Blob Storage
        upload_encrypted_file(blob_name, encrypted_data, file.content_type)

        # Step 5: Store metadata in PostgreSQL
        file_record = FileRecord(
            owner_id=current_user.id,
            original_filename=file.filename,
            blob_name=blob_name,
            file_size=len(content),
            content_type=file.content_type,
            hmac_signature=hmac_sig,
        )
        db.add(file_record)
        db.commit()
        db.refresh(file_record)

        log_audit(db, "FILE_UPLOAD", "SUCCESS", user_id=current_user.id,
                  file_id=file_record.id,
                  ip_address=request.client.host if request.client else None,
                  details=f"Uploaded '{file.filename}' ({len(content)} bytes)")

        return file_record

    except Exception as e:
        log_audit(db, "FILE_UPLOAD", "FAILURE", user_id=current_user.id,
                  details=str(e))
        raise HTTPException(status_code=500, detail="File upload failed")


@router.get("/", response_model=List[FileResponse])
def list_files(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all files owned by current user. Admins see all files."""
    if current_user.role == UserRole.ADMIN:
        files = db.query(FileRecord).filter(FileRecord.is_deleted == False).all()
    else:
        files = db.query(FileRecord).filter(
            FileRecord.owner_id == current_user.id,
            FileRecord.is_deleted == False
        ).all()
    return files


@router.get("/{file_id}/download")
def download_file(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Download and decrypt a file.
    HMAC is verified before decryption — rejects tampered files.
    """
    file_record = db.query(FileRecord).filter(
        FileRecord.id == file_id,
        FileRecord.is_deleted == False
    ).first()

    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    # Ownership validation
    has_access = (
        file_record.owner_id == current_user.id or
        current_user.role == UserRole.ADMIN or
        db.query(FileAccess).filter(
            FileAccess.file_id == file_id,
            FileAccess.granted_to_user_id == current_user.id,
            FileAccess.can_read == True
        ).first() is not None
    )

    if not has_access:
        log_audit(db, "FILE_DOWNLOAD", "FAILURE", user_id=current_user.id,
                  file_id=file_id, details="Unauthorized access attempt")
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        # Download ciphertext from Azure
        encrypted_data = download_encrypted_file(file_record.blob_name)

        # Verify HMAC — detect tampering
        if not verify_hmac(file_record.blob_name, encrypted_data, file_record.owner_id, file_record.hmac_signature):
            log_audit(db, "FILE_INTEGRITY_FAIL", "FAILURE", user_id=current_user.id,
                      file_id=file_id, details="HMAC verification failed — file may be tampered")
            raise HTTPException(status_code=422, detail="File integrity check failed — possible tampering detected")

        # Decrypt with AES-256-GCM
        plaintext = decrypt_file(encrypted_data, file_record.owner_id)

        log_audit(db, "FILE_DOWNLOAD", "SUCCESS", user_id=current_user.id,
                  file_id=file_id,
                  ip_address=request.client.host if request.client else None)

        return Response(
            content=plaintext,
            media_type=file_record.content_type or "application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{file_record.original_filename}"'}
        )

    except HTTPException:
        raise
    except Exception as e:
        log_audit(db, "FILE_DOWNLOAD", "FAILURE", user_id=current_user.id,
                  file_id=file_id, details=str(e))
        raise HTTPException(status_code=500, detail="File download failed")


@router.delete("/{file_id}", status_code=204)
def delete_file(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete file from Azure Blob Storage and mark as deleted in PostgreSQL."""
    file_record = db.query(FileRecord).filter(
        FileRecord.id == file_id,
        FileRecord.is_deleted == False
    ).first()

    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    if file_record.owner_id != current_user.id and current_user.role != UserRole.ADMIN:
        log_audit(db, "FILE_DELETE", "FAILURE", user_id=current_user.id,
                  file_id=file_id, details="Unauthorized delete attempt")
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        delete_blob(file_record.blob_name)
        file_record.is_deleted = True
        db.commit()
        log_audit(db, "FILE_DELETE", "SUCCESS", user_id=current_user.id,
                  file_id=file_id,
                  ip_address=request.client.host if request.client else None)
    except Exception as e:
        raise HTTPException(status_code=500, detail="File deletion failed")


@router.post("/{file_id}/share/{target_user_id}", status_code=201)
def share_file(
    file_id: int,
    target_user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Grant another user read access to a file."""
    file_record = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not file_record or file_record.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only share your own files")

    target = db.query(User).filter(User.id == target_user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")

    access = FileAccess(
        file_id=file_id,
        granted_to_user_id=target_user_id,
        granted_by_user_id=current_user.id
    )
    db.add(access)
    db.commit()
    log_audit(db, "FILE_SHARED", "SUCCESS", user_id=current_user.id,
              file_id=file_id, details=f"Shared with user_id={target_user_id}")
    return {"message": f"File shared with user {target_user_id}"}


@router.get("/audit/logs")
def get_audit_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """Get all audit logs — Admin only."""
    from app.database import AuditLog
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    return logs
