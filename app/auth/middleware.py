"""
JWT Authentication and RBAC Middleware.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db, User, UserRole, AuditLog

logger = logging.getLogger(__name__)
settings = get_settings()
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLE_HIERARCHY = {UserRole.ADMIN: 3, UserRole.USER: 2, UserRole.GUEST: 1}


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm="HS256")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    try:
        payload = jwt.decode(credentials.credentials, settings.JWT_SECRET, algorithms=["HS256"])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.email == email, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_role(minimum_role: UserRole):
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if ROLE_HIERARCHY.get(current_user.role, 0) < ROLE_HIERARCHY.get(minimum_role, 0):
            raise HTTPException(status_code=403, detail=f"Requires {minimum_role.value} role")
        return current_user
    return checker


def log_audit(db: Session, action: str, status: str, user_id: Optional[int] = None,
              file_id: Optional[int] = None, ip_address: Optional[str] = None, details: Optional[str] = None):
    log = AuditLog(user_id=user_id, action=action, file_id=file_id,
                   ip_address=ip_address, status=status, details=details)
    db.add(log)
    db.commit()
    logger.info(f"AUDIT | {action} | user={user_id} | status={status}")
