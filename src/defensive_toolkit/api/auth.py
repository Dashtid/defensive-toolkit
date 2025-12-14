"""
JWT Authentication System

Implements OAuth2 with JWT tokens following 2025 security best practices:
- Short-lived access tokens (15 minutes)
- Long-lived refresh tokens (30 days)
- Secure password hashing with bcrypt
- API key authentication as alternative
- Token blacklisting support (for logout)
"""

import secrets
from datetime import datetime, timedelta
from typing import List, Optional

from api.config import get_settings
from api.models import Token, TokenData
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

settings = get_settings()

# Password hashing context using bcrypt (2025 best practice)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for JWT token
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_prefix}/auth/token", auto_error=False  # Allow API key auth as fallback
)

# API Key header scheme
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# In-memory token blacklist (use Redis in production)
# Format: {token: expiry_timestamp}
token_blacklist = {}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: Plain text password
        hashed_password: Bcrypt hashed password

    Returns:
        bool: True if password matches
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        str: Hashed password
    """
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.

    Args:
        data: Data to encode in token (username, scopes, etc.)
        expires_delta: Optional custom expiration time

    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "access"})

    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """
    Create a JWT refresh token (long-lived).

    Args:
        data: Data to encode in token (username)

    Returns:
        str: Encoded JWT refresh token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)

    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "refresh"})

    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

    return encoded_jwt


def create_token_pair(username: str, scopes: List[str] = None) -> Token:
    """
    Create both access and refresh tokens.

    Args:
        username: Username for token
        scopes: Optional list of permission scopes

    Returns:
        Token: Token response model with both tokens
    """
    if scopes is None:
        scopes = []

    access_token = create_access_token(data={"sub": username, "scopes": scopes})
    refresh_token = create_refresh_token(data={"sub": username})

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


def verify_token(token: str, token_type: str = "access") -> Optional[TokenData]:
    """
    Verify and decode a JWT token.

    Args:
        token: JWT token string
        token_type: Expected token type ("access" or "refresh")

    Returns:
        TokenData: Decoded token data or None if invalid

    Raises:
        HTTPException: If token is invalid or blacklisted
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Check if token is blacklisted
    if token in token_blacklist:
        if token_blacklist[token] > datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )
        else:
            # Clean up expired blacklist entry
            del token_blacklist[token]

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])

        username: str = payload.get("sub")
        token_type_claim: str = payload.get("type")
        scopes: List[str] = payload.get("scopes", [])

        if username is None:
            raise credentials_exception

        if token_type_claim != token_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token type. Expected {token_type}",
            )

        return TokenData(username=username, scopes=scopes)

    except JWTError:
        raise credentials_exception


def blacklist_token(token: str, expiry: datetime):
    """
    Add token to blacklist (for logout functionality).

    Args:
        token: JWT token to blacklist
        expiry: Token expiration time
    """
    token_blacklist[token] = expiry

    # Clean up expired tokens
    cleanup_blacklist()


def cleanup_blacklist():
    """Remove expired tokens from blacklist"""
    now = datetime.utcnow()
    expired = [token for token, exp in token_blacklist.items() if exp <= now]

    for token in expired:
        del token_blacklist[token]


def verify_api_key(api_key: str) -> bool:
    """
    Verify an API key against valid keys.

    Args:
        api_key: API key to verify

    Returns:
        bool: True if API key is valid
    """
    valid_keys = settings.get_api_keys_list()
    return api_key in valid_keys


def generate_api_key() -> str:
    """
    Generate a secure random API key.

    Returns:
        str: Random API key (32 bytes, hex encoded)
    """
    return secrets.token_hex(32)


# ============================================================================
# FastAPI Dependencies
# ============================================================================


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Security(api_key_header),
) -> str:
    """
    Dependency to get current authenticated user.

    Supports both JWT token and API key authentication.
    JWT is checked first, then API key as fallback.

    Args:
        token: JWT token from Authorization header
        api_key: API key from X-API-Key header

    Returns:
        str: Username of authenticated user

    Raises:
        HTTPException: If authentication fails
    """
    # Try JWT token first
    if token:
        token_data = verify_token(token, token_type="access")
        return token_data.username

    # Fallback to API key
    if api_key and verify_api_key(api_key):
        return "api_key_user"  # Generic username for API key auth

    # No valid authentication provided
    if settings.require_authentication:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Provide JWT token or API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If authentication not required, return anonymous user
    return "anonymous"


async def get_current_active_user(
    current_user: str = Depends(get_current_user),
) -> str:
    """
    Dependency to get current active user.

    Can be extended to check user status in database.

    Args:
        current_user: Username from get_current_user

    Returns:
        str: Username of active user
    """
    # Future: Check if user is active in database
    # For now, all authenticated users are considered active
    return current_user


# ============================================================================
# User Management (Placeholder for future database integration)
# ============================================================================

# In-memory user store (replace with database in production)
FAKE_USERS_DB = {
    "admin": {
        "username": "admin",
        "full_name": "Administrator",
        "email": "admin@example.com",
        # Password: "changeme123"
        "hashed_password": "$2b$12$sQSM7EN4n1mDR4F.RUDaMuZwcneJb29BEFV/WdcmMFT5FNAMfvV.q",
        "disabled": False,
        "scopes": ["admin", "read", "write"],
    },
    "analyst": {
        "username": "analyst",
        "full_name": "Security Analyst",
        "email": "analyst@example.com",
        # Password: "analyst123"
        "hashed_password": "$2b$12$RGr69ZJ7OCu4A56VJXGEjOQtCuEXRWOtFiOSpEVu6gHLjQY1uRaO6",
        "disabled": False,
        "scopes": ["read"],
    },
}


def authenticate_user(username: str, password: str) -> Optional[dict]:
    """
    Authenticate user with username and password.

    Args:
        username: Username
        password: Plain text password

    Returns:
        dict: User dict if authentication succeeds, None otherwise
    """
    user = FAKE_USERS_DB.get(username)

    if not user:
        return None

    if not verify_password(password, user["hashed_password"]):
        return None

    return user


def get_user(username: str) -> Optional[dict]:
    """
    Get user by username.

    Args:
        username: Username

    Returns:
        dict: User dict or None
    """
    return FAKE_USERS_DB.get(username)
