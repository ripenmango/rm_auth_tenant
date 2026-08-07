"""
Signing key resolution (§7 of design doc):
  - Tier A (self-serve): global HS256 secret, shared across all self-serve tenants.
  - Tier B/C (enterprise): per-tenant RS256 key pair, customer-supplied with
    platform-generated fallback (§7 decision).

Centralized here so jwt_auth.issuer / jwt_auth.validator never touch a raw
secret path or secrets-manager call directly.
"""

from dataclasses import dataclass
from rm_auth_tenant.conf import rm_auth_tenant_settings


@dataclass(frozen=True)
class ResolvedKey:
    algorithm: str  # "HS256" or "RS256"
    signing_key: str  # secret (HS256) or PEM private key (RS256)
    verifying_key: str  # same secret (HS256) or PEM public key (RS256)


def _fetch_from_secrets_manager(key_ref: str) -> str:
    """
    Stub -- wire to Vault / AWS Secrets Manager per the platform's Tier C
    secrets pattern (workflow-platform-architecture.md §3.3). Never call this
    from anywhere except this module.
    """
    raise NotImplementedError(
        f"Secrets manager integration not wired up yet (key_ref={key_ref!r}). "
        "Configure a real backend before enabling RS256/per-tenant signing."
    )


def resolve_signing_key(tenant) -> ResolvedKey:
    # from rm_auth.tenants.models import Tenant

    # tenant: Tenant = tenant if tenant is not None else None
    """
    Returns the key material to use for issuing/validating tokens for a given
    tenant. Falls back to the global HS256 default when the tenant has no
    record yet or is explicitly configured for HS256 (Tier A default).
    """
    if tenant is None or tenant.jwt_algorithm == "HS256":
        secret = rm_auth_tenant_settings.signing_secret
        return ResolvedKey(algorithm="HS256", signing_key=secret, verifying_key=secret)

    if tenant.jwt_algorithm == "RS256":
        if not tenant.signing_key_ref:
            raise ValueError(
                f"Tenant {tenant.id!r} is configured for RS256 but has no signing_key_ref. "
                "Run the enterprise onboarding key-provisioning step first."
            )
        # In production this returns a PEM-encoded private+public key pair.
        # The private key is only needed on the issuing side; a Tier C tenant
        # verifying tokens independently only ever needs the public half.
        pem_bundle = _fetch_from_secrets_manager(tenant.signing_key_ref)
        private_key, public_key = pem_bundle  # expected: (private_pem, public_pem)
        return ResolvedKey(
            algorithm="RS256", signing_key=private_key, verifying_key=public_key
        )

    raise ValueError(
        f"Unsupported jwt_algorithm {tenant.jwt_algorithm!r} for tenant {tenant.id!r}"
    )
