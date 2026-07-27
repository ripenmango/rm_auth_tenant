"""
rm_auth-specific test factories.

Built on drf_base_testkit.BaseFactory, but NOT reusable as generic
`user_factory`/`admin_user_factory` overrides in drf_base_testkit itself,
because rm_auth.accounts.models.User is tenant-scoped: `tenant_id` is
required (no default) and real uniqueness is (tenant_id, username), not a
globally-unique username. The generic testkit fixtures assume the latter,
so this factory replaces them for rm_auth's own tests -- see conftest.py.

_create is fully overridden (rather than relying on DjangoModelFactory's
default get_or_create/manager.create) so user creation goes through the
same UserManager.create_user/create_superuser methods AccountRepository
uses in production -- keeping password hashing and validation identical
between tests and real code, rather than re-implementing it here.
"""
import factory

from drf_base_testkit.factories.base import BaseFactory

from rm_auth_tenant.accounts.models import User
from rm_auth_tenant.roles.models import Persona, Role

DEFAULT_TEST_TENANT_ID = "test-tenant"
DEFAULT_TEST_PERSONA_NAME = "default"


class UserFactory(BaseFactory):
    class Meta:
        model = User

    tenant_id = DEFAULT_TEST_TENANT_ID
    username = factory.Sequence(lambda n: f"testuser{n}")
    email = factory.Faker("email")
    is_active = True

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        password = kwargs.pop("password", "testpass123")
        manager = cls._get_manager(model_class)
        return manager.create_user(password=password, **kwargs)


class AdminUserFactory(UserFactory):
    """A user with is_staff/is_superuser set (Django admin access only --
    does NOT grant rm_auth policy permissions, see conftest.py)."""

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        password = kwargs.pop("password", "testpass123")
        kwargs.setdefault("is_staff", True)
        kwargs.setdefault("is_superuser", True)
        manager = cls._get_manager(model_class)
        return manager.create_superuser(password=password, **kwargs)


class RoleFactory(BaseFactory):
    class Meta:
        model = Role

    tenant_id = DEFAULT_TEST_TENANT_ID
    name = factory.Sequence(lambda n: f"role-{n}")


class PersonaFactory(BaseFactory):
    """
    A Persona a test user can be eligible for. Needed for anything that
    exercises the real login flow (AuthenticationService.login ->
    RoleRepository.eligible_personas hits real UserPersonaAssignment rows)
    -- unlike `rm_auth_client`/`security_context_factory` in conftest.py,
    which bypass persona lookup entirely by faking JWTAuthentication.

    `.slug` (auto-derived from `name` on save -- see RMSluggedModel) is the
    real Casbin subject (see SecurityContext.persona_slug), not `.name`. If a
    test also needs an authorization check to pass, grant a policy against
    this persona's `.slug` via PolicyService/the `grant_persona_permission`
    fixture (which already does this correctly) rather than `.name`.
    """

    class Meta:
        model = Persona

    tenant_id = DEFAULT_TEST_TENANT_ID
    name = factory.Sequence(lambda n: f"persona-{n}")

    @factory.post_generation
    def roles(self, create, extracted, **kwargs):
        if not create or not extracted:
            return
        self.roles.set(extracted)
