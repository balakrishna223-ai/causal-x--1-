from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    PasswordlessRequest,
    PasswordlessRequestResponse,
    PasswordlessVerifyRequest,
    RegisterRequest,
)
from app.services.auth_service import (
    authenticate_principal,
    register_operator,
    request_passwordless_login,
    verify_passwordless_login,
)

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    return authenticate_principal(db, payload)


@router.post("/register", response_model=LoginResponse)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> LoginResponse:
    return register_operator(db, payload)


@router.post("/passwordless/request", response_model=PasswordlessRequestResponse)
def passwordless_request(
    payload: PasswordlessRequest, db: Session = Depends(get_db)
) -> PasswordlessRequestResponse:
    return request_passwordless_login(db, payload)


@router.post("/passwordless/verify", response_model=LoginResponse)
def passwordless_verify(
    payload: PasswordlessVerifyRequest, db: Session = Depends(get_db)
) -> LoginResponse:
    return verify_passwordless_login(db, payload)
