import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
from django.conf import settings

from rm_auth_tenant.jwt_auth.keys import ResolvedKey


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_jti: str
    refresh_jti: str


def _build_claims(user_id: int, tenant_id: str, persona_id: int, ver: int, ttl_seconds: int) -> tuple[dict, str]:
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    claims = {
        "sub": str(user_id),
        "tenant": tenant_id,
        "persona": str(persona_id),
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "ver": ver,
    }
    return claims, jti


def issue_token_pair(user_id: int, tenant_id: str, persona_id: int, ver: int, key: ResolvedKey) -> TokenPair:
    """
    Issues a fresh access + refresh token pair. Claims are intentionally
    minimal (§7 of design doc) -- no roles/permissions are embedded; those
    are resolved server-side per-request via the Security Context (§8).
    """
    access_ttl = settings.RM_AUTH.get("JWT_ACCESS_TTL_SECONDS", 900)
    refresh_ttl = settings.RM_AUTH.get("JWT_REFRESH_TTL_SECONDS", 60 * 60 * 24 * 7)

    access_claims, access_jti = _build_claims(user_id, tenant_id, persona_id, ver, access_ttl)
    refresh_claims, refresh_jti = _build_claims(user_id, tenant_id, persona_id, ver, refresh_ttl)
    refresh_claims["token_type"] = "refresh"
    access_claims["token_type"] = "access"

    access_token = pyjwt.encode(access_claims, key.signing_key, algorithm=key.algorithm)
    refresh_token = pyjwt.encode(refresh_claims, key.signing_key, algorithm=key.algorithm)

    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        access_jti=access_jti,
        refresh_jti=refresh_jti,
    )
