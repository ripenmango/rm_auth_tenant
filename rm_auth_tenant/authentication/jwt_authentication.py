from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from rm_auth_tenant.accounts.repositories import AccountRepository
from rm_auth_tenant.jwt_auth import validator
from rm_auth_tenant.jwt_auth.keys import resolve_signing_key
from rm_auth.middleware.security_context import SecurityContext, set_current
from rm_auth_tenant.roles.repositories import RoleRepository
from rm_auth.tenants.repositories import TenantRepository


class JWTAuthentication(BaseAuthentication):
    """
    DRF authentication class -- its ONLY job is identity (§4 of design doc:
    authentication and authorization are separate pipelines). It does not
    decide what the user can do; RequiresPermission (authorization/) does
    that, via the SecurityContext this class builds and attaches.
    """

    keyword = "Bearer"

    def __init__(self):
        self.accounts = AccountRepository()
        self.roles = RoleRepository()
        self.tenants = TenantRepository()

    def authenticate(self, request):
        header = request.headers.get("Authorization", "")
        if not header.startswith(f"{self.keyword} "):
            return None  # let other authenticators (or AllowAny) handle it

        token = header[len(self.keyword) + 1 :]

        # Tenant is resolved by TenantResolutionMiddleware upstream (or the
        # platform's tenancy middleware in the full deployment) -- but the
        # token's own `tenant` claim is the source of truth for validation,
        # since the key used to sign it is tenant-specific (§7).
        unverified_tenant_id = self._peek_tenant_claim(token)
        tenant = self.tenants.get(unverified_tenant_id)
        key = resolve_signing_key(tenant)

        try:
            decoded = validator.decode(token, key)
        except validator.TokenInvalid as exc:
            raise AuthenticationFailed(str(exc)) from exc

        if decoded.token_type != "access":
            raise AuthenticationFailed("Not an access token")

        user = self.accounts.get_user_by_id(decoded.tenant_id, decoded.user_id)
        if user is None:
            raise AuthenticationFailed("User not found or inactive")

        try:
            validator.check_version(decoded, user.ver)
        except validator.TokenVersionMismatch as exc:
            raise AuthenticationFailed(
                "Session invalidated (password changed, forced logout, or persona switch)"
            ) from exc

        persona = next(
            (p for p in self.roles.eligible_personas(decoded.tenant_id, user.id) if p.id == decoded.persona_id),
            None,
        )
        if persona is None:
            raise AuthenticationFailed("Persona no longer eligible for this user")

        context = SecurityContext(
            user_id=user.id,
            tenant_id=decoded.tenant_id,
            persona_id=persona.id,
            persona_slug=persona.slug,
            token_jti=decoded.jti,
        )
        set_current(context)
        request.security_context = context  # convenience accessor alongside the contextvar

        return (user, decoded)  # DRF convention: (user, auth)

    def _peek_tenant_claim(self, token: str) -> str | None:
        """
        Reads the `tenant` claim WITHOUT verifying the signature, purely to
        know which tenant's key to verify against next. This is standard
        practice for multi-key JWT systems -- the claim is not trusted until
        `validator.decode` verifies the signature with the resolved key.
        """
        import jwt as pyjwt

        try:
            unverified = pyjwt.decode(token, options={"verify_signature": False})
        except pyjwt.PyJWTError as exc:
            raise AuthenticationFailed("Malformed token") from exc
        return unverified.get("tenant")
