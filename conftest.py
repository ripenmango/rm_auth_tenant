"""
Project-level pytest fixtures for rm_auth's own test suite.

drf_base_testkit supplies model-agnostic fixtures (api_client, db_access,
BaseFactory, etc.) that work against django.contrib.auth.get_user_model()
and Django's request.user/permissions. Two things about rm_auth make that
insufficient on its own, so this file adds rm_auth-specific fixtures on top
rather than special-casing them into the shared testkit (which would leak
rm_auth-only assumptions into every other service that depends on it):

1. Authorization data lives in a separate `SecurityContext`
   (rm_auth.middleware.security_context), populated ONLY inside
   `JWTAuthentication.authenticate()`. drf_base_testkit's
   `authenticated_client`/`admin_api_client` fixtures use
   `api_client.force_authenticate(user=...)`, which sets `request.user`
   directly and skips DRF's authentication classes entirely -- so
   `request.security_context` stays None and any rm_auth view reading it
   (all of them) raises AttributeError under those fixtures.

2. `SecurityContext.can(resource, action)` calls `PolicyService().is_allowed(...)`
   -- a real Casbin check against PolicyRule rows -- not the `permissions`
   field on the context (documented as "for display only"). So granting
   access in a test means either seeding real PolicyRule rows or patching
   `SecurityContext.can` directly; the fixtures below do the latter by
   default (`allow_all=True`) to keep most view-level tests focused on the
   view/service wiring rather than re-testing Casbin evaluation, which is
   PolicyService's own test responsibility.
"""
import pytest

from rm_auth.middleware.security_context import SecurityContext, set_current
from rm_auth_tenant.authentication.jwt_authentication import JWTAuthentication
from rm_auth_tenant.policy.service import PolicyService
from rm_auth_tenant.roles.repositories import RoleRepository
from rm_auth_tenant.tests.factories import (
    DEFAULT_TEST_PERSONA_NAME,
    DEFAULT_TEST_TENANT_ID,
    AdminUserFactory,
    PersonaFactory,
    UserFactory,
)


@pytest.fixture
def tenant_id():
    """Default tenant used across rm_auth's own tests unless overridden."""
    return DEFAULT_TEST_TENANT_ID


@pytest.fixture
def rm_user_factory(db):
    """Tenant-aware user factory (see rm_auth/tests/factories.py). Use this
    instead of drf_base_testkit's generic `user_factory` for rm_auth models."""
    return UserFactory


@pytest.fixture
def rm_admin_user_factory(db):
    return AdminUserFactory


@pytest.fixture
def security_context_factory(mocker):
    """
    Returns a callable that, given a user, patches JWTAuthentication so any
    request in the test populates request.security_context exactly as a
    real login would -- without needing a signed JWT or Persona/Role/
    PolicyRule rows in the DB. Returns the SecurityContext for assertions.

    Pass allow_all=False to exercise real PolicyService evaluation instead
    (e.g. to test a 403 for a persona with no matching policy rule).
    """

    def _apply(
        user,
        tenant_id=DEFAULT_TEST_TENANT_ID,
        persona_id=1,
        persona_slug="default",
        allow_all=True,
    ):
        context = SecurityContext(
            user_id=user.id,
            tenant_id=tenant_id,
            persona_id=persona_id,
            persona_slug=persona_slug,
            token_jti="test-jti",
        )

        if allow_all:
            mocker.patch.object(SecurityContext, "can", return_value=True)

        def _fake_authenticate(self, request):
            set_current(context)
            request.security_context = context
            return (user, None)

        mocker.patch.object(JWTAuthentication, "authenticate", _fake_authenticate)
        return context

    return _apply


@pytest.fixture
def rm_auth_client(api_client, rm_user_factory, security_context_factory, tenant_id):
    """
    An APIClient authenticated as a fresh tenant-scoped user, with
    request.security_context populated and policy checks allowed by
    default. Returns (client, user, context).

    Use this instead of drf_base_testkit's `authenticated_client` for any
    rm_auth view -- see module docstring for why that fixture doesn't work
    here.
    """
    user = rm_user_factory(tenant_id=tenant_id)
    context = security_context_factory(user, tenant_id=tenant_id)
    return api_client, user, context


@pytest.fixture
def rm_persona_factory(db):
    """Tenant-aware persona factory (see rm_auth/tests/factories.py)."""
    return PersonaFactory


@pytest.fixture
def default_persona(db, tenant_id):
    """
    A single Persona named "default" for `tenant_id`. Kept separate from
    `assign_default_persona` below so tests that just need the row (e.g. to
    grant a Casbin policy against it) don't have to also create a user.
    """
    return PersonaFactory(tenant_id=tenant_id, name=DEFAULT_TEST_PERSONA_NAME)


@pytest.fixture
def assign_default_persona(default_persona, tenant_id):
    """
    Returns a callable that makes `user` eligible for `default_persona` via
    a real UserPersonaAssignment row.

    Needed for any test that goes through the real login flow
    (AuthenticationService.login -> RoleRepository.eligible_personas), since
    that path is NOT covered by `rm_auth_client`/`security_context_factory`
    -- those bypass persona lookup entirely by faking JWTAuthentication.
    """

    def _assign(user, tenant_id=tenant_id, persona=default_persona):
        RoleRepository().assign_persona(tenant_id, user.id, persona)
        return persona

    return _assign


@pytest.fixture
def grant_persona_permission():
    """
    Returns a callable that grants a real Casbin policy so
    `default_persona` (or any persona) passes `RequiresPermission`/
    `SecurityContext.can` checks for real, instead of relying on
    `security_context_factory`'s `allow_all=True` patch.

    Usage: grant_persona_permission(persona, "workflow", "edit", tenant_id=tenant_id)
    """

    def _grant(persona, resource: str, action: str, tenant_id=DEFAULT_TEST_TENANT_ID):
        # Real request-time checks key on persona.slug (see SecurityContext,
        # RoleService) -- grant against the same slug here, not .name, or
        # this fixture would grant a permission the real enforce() call never
        # actually matches.
        PolicyService().grant(tenant_id, persona.slug, resource, action)

    return _grant
