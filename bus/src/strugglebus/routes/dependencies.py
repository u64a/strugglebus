from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    ConfigurationError,
    CredentialConflictError,
    CredentialLimitError,
    CredentialNotFoundError,
)
from strugglebus.models import (
    Agent,
    AuthenticatedIdentity,
)
from strugglebus.roe import credential_id


agent_bearer = HTTPBearer(
    auto_error=False,
    bearerFormat="Strugglebus agent API key",
    scheme_name="AgentBearer",
)
admin_bearer = HTTPBearer(
    auto_error=False,
    bearerFormat="LoadCredential admin token",
    scheme_name="AdminBearer",
)


class AdminVerifier:
    def __init__(self, secret: bytes) -> None:
        self._secret = secret
        self.credential_context = credential_id(secret)

    def verify(self, token: str) -> bool:
        if not isinstance(token, str):
            return False
        return hmac.compare_digest(
            token.encode("utf-8"),
            self._secret,
        )


async def require_agent(
    request: Request,
    _credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(agent_bearer),
    ],
) -> Agent:
    agent = getattr(request.state, "authenticated_agent", None)
    if not isinstance(agent, Agent):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="agent authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return agent


async def require_identity(
    request: Request,
    _credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(agent_bearer),
    ],
) -> AuthenticatedIdentity:
    identity = getattr(request.state, "authenticated_identity", None)
    if not isinstance(identity, AuthenticatedIdentity):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="agent authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return identity


def _secret_response_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"


def _lifecycle_http_error(error: Exception) -> HTTPException:
    if isinstance(error, (CredentialConflictError, CredentialLimitError)):
        return HTTPException(status_code=409, detail=str(error))
    if isinstance(error, (CredentialNotFoundError, AgentNotFoundError)):
        return HTTPException(status_code=404, detail=str(error))
    if isinstance(error, ConfigurationError):
        return HTTPException(status_code=422, detail=str(error))
    if isinstance(error, AgentAccessFrozenError):
        return HTTPException(status_code=503, detail="service is unavailable")
    raise error


async def require_admin(
    request: Request,
    _credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(admin_bearer),
    ],
) -> None:
    if not getattr(request.state, "admin_authenticated", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="admin authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
