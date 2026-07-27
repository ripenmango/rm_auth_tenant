from datetime import datetime, timezone

from rm_auth_tenant.jwt_auth.models import RefreshTokenRecord


class RefreshTokenStore:
    """
    Despite the name (kept for continuity with the design doc's package
    layout), this doubles as the refresh-token issuance record, not just a
    revocation blacklist -- every issued refresh token gets a row here so it
    can be looked up, single-use-enforced, and individually revoked on logout.
    """

    def record(self, jti: str, tenant_id: str, user_id: int, persona_id: int, ver: int, expires_at: datetime) -> None:
        RefreshTokenRecord.objects.create(
            jti=jti,
            tenant_id=tenant_id,
            user_id=user_id,
            persona_id=persona_id,
            issued_ver=ver,
            expires_at=expires_at,
        )

    def is_revoked(self, jti: str) -> bool:
        record = RefreshTokenRecord.objects.filter(jti=jti).first()
        if record is None:
            # Unknown jti -- treat as revoked/invalid rather than trusting an
            # unrecorded token (e.g. a token from before this store existed).
            return True
        if record.revoked:
            return True
        if record.expires_at < datetime.now(timezone.utc):
            return True
        return False

    def revoke(self, jti: str) -> None:
        RefreshTokenRecord.objects.filter(jti=jti).update(revoked=True)

    def revoke_all_for_user(self, tenant_id: str, user_id: int) -> None:
        """Used alongside a User.ver bump for defense-in-depth (§7)."""
        RefreshTokenRecord.objects.filter(tenant_id=tenant_id, user_id=user_id).update(revoked=True)
