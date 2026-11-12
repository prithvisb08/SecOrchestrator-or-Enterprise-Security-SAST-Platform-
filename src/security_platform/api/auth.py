import os
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import jwt
from fastapi import Header, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from security_platform.core.logging import logger

security_scheme = HTTPBearer(auto_error=False)

JWT_SECRET = os.getenv("JWT_SECRET", "secorch_default_dev_secret_change_in_prod_minimum_32_bytes_long")
JWT_ALGORITHM = "HS256"
JWT_AUDIENCE = "secorch-api"
JWT_ISSUER = "secorch-auth"


class Role(StrEnum):
    VIEWER = "viewer"
    SCANNER = "scanner"
    ADMIN = "admin"


ROLE_HIERARCHY: dict[Role, int] = {
    Role.VIEWER: 1,
    Role.SCANNER: 2,
    Role.ADMIN: 3,
}


class UserContext(BaseModel):
    user_id: str
    tenant_id: str
    role: Role
    auth_method: str = "jwt"
    extra: dict[str, Any] = Field(default_factory=dict)


# In-memory configured API keys (API_KEY -> UserContext)
STATIC_API_KEYS: dict[str, UserContext] = {
    "secorch_admin_key_test": UserContext(
        user_id="admin-ci-user",
        tenant_id="tenant-default",
        role=Role.ADMIN,
        auth_method="api_key",
    ),
    "secorch_scanner_key_test": UserContext(
        user_id="scanner-ci-user",
        tenant_id="tenant-default",
        role=Role.SCANNER,
        auth_method="api_key",
    ),
    "secorch_viewer_key_test": UserContext(
        user_id="viewer-ci-user",
        tenant_id="tenant-default",
        role=Role.VIEWER,
        auth_method="api_key",
    ),
    # Additional tenant for isolation tests
    "secorch_tenant_b_key": UserContext(
        user_id="tenant-b-user",
        tenant_id="tenant-b",
        role=Role.SCANNER,
        auth_method="api_key",
    ),
}


def create_access_token(
    user_id: str,
    tenant_id: str,
    role: Role = Role.SCANNER,
    expires_in_seconds: int = 3600,
    secret: str = JWT_SECRET,
) -> str:
    """Helper to issue test and user JWT tokens with required aud, iss, exp claims."""
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": str(role.value),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + expires_in_seconds,
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str, secret: str = JWT_SECRET) -> UserContext:
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        role_str = payload.get("role", "viewer")
        return UserContext(
            user_id=str(payload["sub"]),
            tenant_id=str(payload.get("tenant_id", "default")),
            role=Role(role_str),
            auth_method="jwt",
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token has expired") from exc
    except (jwt.InvalidTokenError, Exception) as exc:
        logger.warning("JWT validation failed", extra={"error": str(exc)})
        raise HTTPException(status_code=401, detail="Invalid authentication credentials") from exc


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(security_scheme),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> UserContext:
    """Validates either X-API-Key or Bearer Token (JWT or API Key)."""
    # 1. Check direct X-API-Key header
    if x_api_key and x_api_key in STATIC_API_KEYS:
        return STATIC_API_KEYS[x_api_key]

    # 2. Check Bearer credentials
    if credentials and credentials.scheme.lower() == "bearer":
        token = credentials.credentials
        if token in STATIC_API_KEYS:
            return STATIC_API_KEYS[token]
        # Otherwise parse as JWT
        return decode_jwt_token(token)

    raise HTTPException(
        status_code=401,
        detail="Unauthorized: Authentication required (Bearer token or X-API-Key)",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(minimum_role: Role) -> Callable[[UserContext], UserContext]:
    """Dependency factory checking user's RBAC role against required minimum role."""
    def _role_checker(user: UserContext = Security(get_current_user)) -> UserContext:
        user_level = ROLE_HIERARCHY.get(user.role, 0)
        required_level = ROLE_HIERARCHY.get(minimum_role, 0)
        if user_level < required_level:
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Action requires '{minimum_role.value}' role, user has '{user.role.value}'",
            )
        return user

    return _role_checker
