from dataclasses import dataclass

import jwt as pyjwt

from rm_auth_tenant.jwt_auth.keys import ResolvedKey


class TokenInvalid(Exception):
    """Raised for any validation failure -- signature, expiry, malformed claims."""


class TokenVersionMismatch(Exception):
    """
    Raised when a token's `ver` claim no longer matches User.ver -- meaning
    the user changed password, was forced logged out, or switched persona
    since this token was issued (§5/§7 decision: persona switch bumps `ver`,
    invalidating every other outstanding token). Distinguished from
    TokenInvalid because callers may want to give a more specific error.
    """


@dataclass(frozen=True)
class DecodedToken:
    user_id: int
    tenant_id: str
    persona_id: int
    jti: str
    ver: int
    token_type: str


def decode(token: str, key: ResolvedKey) -> DecodedToken:
    try:
        claims = pyjwt.decode(token, key.verifying_key, algorithms=[key.algorithm])
    except pyjwt.PyJWTError as exc:
        raise TokenInvalid(str(exc)) from exc

    required = {"sub", "tenant", "persona", "jti", "ver", "token_type"}
    missing = required - claims.keys()
    if missing:
        raise TokenInvalid(f"Token missing required claims: {sorted(missing)}")

    return DecodedToken(
        user_id=int(claims["sub"]),
        tenant_id=claims["tenant"],
        persona_id=int(claims["persona"]),
        jti=claims["jti"],
        ver=int(claims["ver"]),
        token_type=claims["token_type"],
    )


def check_version(decoded: DecodedToken, current_user_ver: int) -> None:
    if decoded.ver != current_user_ver:
        raise TokenVersionMismatch(
            f"Token ver={decoded.ver} does not match current user ver={current_user_ver}"
        )
