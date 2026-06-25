"""Auth Routes: register, login, key expiry status."""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.middleware import hash_password, verify_password, create_token, get_current_user, log_audit
from app.config import get_settings
from app.database import get_db, User, UserRole
from app.models.schemas import UserRegister, UserLogin, TokenResponse, UserResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


@router.post("/register", response_model=UserResponse, status_code=201)
def register(payload: UserRegister, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    key_expires_at = datetime.now(timezone.utc) + timedelta(days=settings.KEY_EXPIRY_DAYS)
    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        key_expires_at=key_expires_at
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_audit(db, "USER_REGISTER", "SUCCESS", user_id=user.id,
              ip_address=request.client.host if request.client else None)
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email, User.is_active == True).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"sub": user.email, "role": user.role})
    log_audit(db, "USER_LOGIN", "SUCCESS", user_id=user.id)
    return TokenResponse(access_token=token, expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/key-status")
def key_status(current_user: User = Depends(get_current_user)):
    """Check if user's encryption key has expired — triggers key rotation alert."""
    now = datetime.now(timezone.utc)
    if current_user.key_expires_at and current_user.key_expires_at < now:
        return {"status": "EXPIRED", "expired_at": current_user.key_expires_at, "action": "Key rotation required"}
    days_left = (current_user.key_expires_at - now).days if current_user.key_expires_at else None
    return {"status": "ACTIVE", "expires_at": current_user.key_expires_at, "days_remaining": days_left}
