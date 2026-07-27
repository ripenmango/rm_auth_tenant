from django.db import transaction

from drf_base_app.logging.logger import get_logger

from rm_auth_tenant.accounts.repositories import AccountRepository
from rm_auth_tenant.jwt_auth.blacklist import RefreshTokenStore
from rm_auth_tenant.roles.models import Persona
from rm_auth_tenant.services.role_service import RoleService

logger = get_logger(__name__)


class UserServiceError(Exception):
    pass


class UserService:
    """
    The only entry point api/views.py calls for User CRUD (same layering
    rule as AuthenticationService, §3: never queries models directly --
    always through AccountRepository).
    """

    def __init__(self):
        self.accounts = AccountRepository()
        self.refresh_store = RefreshTokenStore()
        self.roles = RoleService()

    def list_users(self, tenant_id: str):
        return self.accounts.list_users(tenant_id)

    def get_user(self, tenant_id: str, user_id: int):
        user = self.accounts.get_user_by_id(tenant_id, user_id)
        if user is None:
            raise UserServiceError("User not found")
        return user

    @transaction.atomic
    def create_user(
        self,
        tenant_id: str | None,
        username: str,
        password: str,
        email: str = "",
        assign_default_persona: bool = True,
        personas: list[Persona] | None = None,
        default_persona: Persona | None = None,
    ):
        """
        tenant_id=None falls back to the configured default tenant (see
        AccountRepository.create_user / default-tenant-and-persona.md).

        Persona assignment, in order of precedence:

        - `personas` given (e.g. from the API's `persona_ids` field): assigns
          exactly those, and marks `default_persona` as the user's default
          login persona (see UserPersonaAssignment.is_default /
          default-tenant-and-persona.md). `default_persona` must be one of
          `personas` -- raises UserServiceError otherwise. If omitted and
          `personas` has exactly one entry, that one becomes the default
          automatically (unambiguous); if omitted with more than one persona,
          no default is set and /login will require an explicit `persona_id`
          until one is set later (RoleService.set_default_persona).
        - `personas=None` (the common case) with `assign_default_persona=True`
          (the default): the tenant's lazily-created "Default" persona is
          assigned and marked default -- see
          RoleService.get_or_create_default_persona.
        - `personas=None` with `assign_default_persona=False`: no persona is
          assigned at all -- the caller is expected to assign one itself
          right after creation.
        """
        logger.info("user.created", tenant_id=tenant_id, username=username)
        user = self.accounts.create_user(tenant_id, username, password, email)

        if personas is not None:
            if default_persona is not None and default_persona not in personas:
                raise UserServiceError("default_persona must be one of the assigned personas")
            resolved_default = default_persona
            if resolved_default is None and len(personas) == 1:
                resolved_default = personas[0]
            for persona in personas:
                self.roles.assign_persona(
                    user.tenant_id, user.id, persona,
                    is_default=(persona == resolved_default),
                )
        elif assign_default_persona:
            default = self.roles.get_or_create_default_persona(user.tenant_id)
            self.roles.assign_persona(user.tenant_id, user.id, default, is_default=True)

        return user

    def update_user(self, tenant_id: str, user_id: int, **fields):
        user = self.get_user(tenant_id, user_id)
        return self.accounts.update_user(user, **fields)

    def deactivate_user(self, tenant_id: str, user_id: int) -> None:
        user = self.get_user(tenant_id, user_id)
        self.accounts.deactivate_user(user)
        # Same pattern as AuthenticationService.change_password (§7): a
        # user-state change that should invalidate outstanding sessions.
        self.accounts.bump_version(user)
        self.refresh_store.revoke_all_for_user(tenant_id, user_id)
