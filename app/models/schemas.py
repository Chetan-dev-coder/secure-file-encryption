from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator
from app.database import UserRole


class UserRegister(BaseModel):
    email: EmailStr
    password: str
    role: UserRole = UserRole.USER

    @field_validator("password")
    @classmethod
    def strong_password(cls, v):
        if len(v) < 8:
            raise ValueError("Min 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Need uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Need a digit")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class FileResponse(BaseModel):
    id: int
    original_filename: str
    file_size: int
    content_type: Optional[str]
    encryption_version: str
    created_at: datetime
    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    id: int
    action: str
    status: str
    file_id: Optional[int]
    details: Optional[str]
    created_at: datetime
    class Config:
        from_attributes = True
