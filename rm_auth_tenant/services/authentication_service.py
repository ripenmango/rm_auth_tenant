from datetime import datetime, timedelta, timezone

from django.conf import settings
from django.db import transaction

from rm_auth_tenant.accounts.models import User
from rm_auth_tenant.accounts.repositories import AccountRepository
from rm_auth_tenant.audit.service import AuditService
from rm_auth_tenant.jwt_auth import issuer, validator
from rm_auth_tenant.jwt_auth.blacklist import RefreshTokenStore
from rm_auth_tenant.jwt_auth.keys import resolve_signing_key
from rm_auth_tenant.policy.service import PolicyService
from rm_auth_tenant.roles.models import Persona
from rm_auth_tenant.roles.repositories import RoleRepository
from rm_auth.tenants.repositories import TenantRepository


class AuthenticationError(Exception):
    pass


class PersonaSelectionRequired(Exception):
    """
    Raised by login() when a user is eligible for more than one persona and
    hasn't picked one yet (§5: persona is selected per session). The caller
    (api/views.py) catches this and returns the eligible personas to the
    client for an explicit choice, rather than guessing one.
    """

    def __init__(self, eligible_personas: list[Persona]):
        self.eligible_personas = eligible_personas
        super().__init__("Multiple personas eligible; explicit selection required")


class AuthenticationService:
    """
    The only entry point api/views.py calls for anything auth-related (§3
    layering rule). Delegates to repositories/other services -- never
    queries models directly itself, either.
    """

    def __init__(self):
        self.accounts = AccountRepository()
        self.roles = RoleRepository()
        self.tenants = TenantRepository()
        self.policy = PolicyService()
        self.audit = AuditService()
        self.refresh_store = RefreshTokenStore()

    # -- login -----------------------------------------------------------

    def login(self, tenant_id: str, username: str, password: str, persona_id: int | None = None):
        user = self.accounts.get_user(tenant_id, username)
        if user is None or not self.accounts.verify_password(user, password):
            self.audit.record_login_attempt(tenant_id, username, success=False)
            raise AuthenticationError("Invalid credentials")

        eligible = self.roles.eligible_personas(tenant_id, user.id)
        default_persona = self.roles.get_default_persona(tenant_id, user.id)
        persona = self._resolve_persona(eligible, persona_id, default_persona)

        self.policy.warm_enforcer(tenant_id)
        token_pair = self._issue_and_record(user, tenant_id, persona)

        self.audit.record_login_attempt(
            tenant_id, username, success=True, persona_id=persona.id, jti=token_pair.access_jti
        )
        return token_pair, persona

    def _resolve_persona(
        self,
        eligible: list[Persona],
        persona_id: int | None,
        default_persona: Persona | None = None,
    ) -> Persona:
        if not eligible:
            raise AuthenticationError("User has no eligible personas configured")
        if len(eligible) == 1:
            return eligible[0]
        if persona_id is None:
            # More than one eligible persona and none explicitly requested --
            # use the one marked as this user's default (see
            # UserPersonaAssignment.is_default / default-tenant-and-persona.md)
            # instead of always forcing an explicit choice. Only falls back to
            # PersonaSelectionRequired if no default has been set yet.
            if default_persona is not None:
                return default_persona
            raise PersonaSelectionRequired(eligible)
        for persona in eligible:
            if persona.id == persona_id:
                return persona
        raise AuthenticationError("Requested persona is not eligible for this user")

    def _issue_and_record(self, user: User, tenant_id: str, persona: Persona):
        tenant = self.tenants.get_or_default(tenant_id)
        key = resolve_signing_key(tenant)
        token_pair = issuer.issue_token_pair(user.id, tenant_id, persona.id, user.ver, key)

        refresh_ttl = settings.RM_AUTH.get("JWT_REFRESH_TTL_SECONDS", 60 * 60 * 24 * 7)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=refresh_ttl)
        self.refresh_store.record(
            token_pair.refresh_jti, tenant_id, user.id, persona.id, user.ver, expires_at
        )
        return token_pair

    # -- persona switch (§5/§7: brand-new token pair, ver bump invalidates rest) --

    @transaction.atomic
    def switch_persona(self, tenant_id: str, user_id: int, new_persona_id: int):
        user = self.accounts.get_user_by_id(tenant_id, user_id)
        if user is None:
            raise AuthenticationError("User not found")

        eligible = self.roles.eligible_personas(tenant_id, user_id)
        persona = next((p for p in eligible if p.id == new_persona_id), None)
        if persona is None:
            raise AuthenticationError("Requested persona is not eligible for this user")

        # Confirmed decision (§5/§13): ver bump invalidates ALL outstanding
        # tokens/sessions for this user, not just the one being switched.
        self.accounts.bump_version(user)
        self.refresh_store.revoke_all_for_user(tenant_id, user_id)

        token_pair = self._issue_and_record(user, tenant_id, persona)
        self.audit.record_event(
            tenant_id, "persona_switched", user_id=user_id, metadata={"persona_id": persona.id}
        )
        return token_pair, persona

    # -- refresh (§14.3) --------------------------------------------------

    def refresh(self, tenant_id: str, refresh_token: str):
        tenant = self.tenants.get_or_default(tenant_id)
        key = resolve_signing_key(tenant)

        try:
            decoded = validator.decode(refresh_token, key)
        except validator.TokenInvalid as exc:
            raise AuthenticationError("Invalid refresh token") from exc

        if decoded.token_type != "refresh":
            raise AuthenticationError("Not a refresh token")

        if self.refresh_store.is_revoked(decoded.jti):
            raise AuthenticationError("Refresh token has been revoked or reused")

        user = self.accounts.get_user_by_id(decoded.tenant_id, decoded.user_id)
        if user is None:
            raise AuthenticationError("User not found")

        try:
            validator.check_version(decoded, user.ver)
        except validator.TokenVersionMismatch as exc:
            raise AuthenticationError(
                "Session invalidated (password changed, forced logout, or persona switch)"
            ) from exc

        # Single-use: revoke the old refresh token before issuing a new pair.
        self.refresh_store.revoke(decoded.jti)

        eligible = self.roles.eligible_personas(decoded.tenant_id, user.id)
        persona = next((p for p in eligible if p.id == decoded.persona_id), None)
        if persona is None:
            raise AuthenticationError("Persona no longer eligible for this user")

        token_pair = self._issue_and_record(user, decoded.tenant_id, persona)
        self.audit.record_event(
            decoded.tenant_id, "token_refreshed", user_id=user.id, metadata={"jti": token_pair.access_jti}
        )
        return token_pair, persona

    # -- logout / change_password -----------------------------------------

    def logout(self, tenant_id: str, user_id: int, refresh_jti: str | None = None) -> None:
        if refresh_jti:
            self.refresh_store.revoke(refresh_jti)
        self.audit.record_event(tenant_id, "logout", user_id=user_id)

    @transaction.atomic
    def change_password(self, tenant_id: str, user_id: int, old_password: str, new_password: str) -> None:
        user = self.accounts.get_user_by_id(tenant_id, user_id)
        if user is None or not self.accounts.verify_password(user, old_password):
            raise AuthenticationError("Old password is incorrect")
        if self.accounts.was_previously_used(user, new_password):
            raise AuthenticationError("Password was used recently; choose a different one")

        self.accounts.set_password(user, new_password)
        self.accounts.bump_version(user)  # invalidates every outstanding token (§7)
        self.refresh_store.revoke_all_for_user(tenant_id, user_id)
        self.audit.record_event(tenant_id, "password_changed", user_id=user_id)
