from django.conf import settings
from django.db import transaction

from rm_auth_tenant.audit.service import AuditService
from rm_auth_tenant.permissions.repositories import PermissionRepository
from rm_auth_tenant.policy.models import RoleAssignment
from rm_auth_tenant.policy.service import PolicyService
from rm_auth_tenant.roles.models import Persona, Role
from rm_auth_tenant.roles.repositories import RoleRepository


class RoleServiceError(Exception):
    """Raised for not-found lookups / invalid references -- e.g. an unknown
    role_id passed while creating a Persona. Views translate this into a
    404/400 as appropriate (see api/views.py)."""


class RoleService:
    """
    The only entry point for role/persona/permission administration --
    keeps the Django-native Permission table and the Casbin PolicyRule table
    in sync so they never drift apart (§5, §6 of design doc).
    """

    def __init__(self):
        self.roles = RoleRepository()
        self.permissions = PermissionRepository()
        self.policy = PolicyService()
        self.audit = AuditService()

    @transaction.atomic
    def create_role(self, tenant_id: str, name: str, description: str = "") -> Role:
        return self.roles.create_role(tenant_id, name, description)

    def list_roles(self, tenant_id: str) -> list[Role]:
        return self.roles.list_roles(tenant_id)

    def get_role(self, tenant_id: str, role_id: int) -> Role:
        role = self.roles.get_role_by_id(tenant_id, role_id)
        if role is None:
            raise RoleServiceError(f"Role {role_id} not found")
        return role

    def get_role_by_name(self, tenant_id: str, name: str) -> Role:
        role = self.roles.get_role(tenant_id, name)
        if role is None:
            raise RoleServiceError(f"Role '{name}' not found")
        return role

    def get_roles(self, tenant_id: str, role_ids: list[int]) -> list[Role]:
        """Resolves and validates a list of role ids -- e.g. for building a
        Persona. Raises if any id doesn't belong to this tenant, so a typo'd
        or cross-tenant id fails loudly instead of silently being dropped."""
        roles = self.roles.get_roles_by_ids(tenant_id, role_ids)
        missing = set(role_ids) - {role.id for role in roles}
        if missing:
            raise RoleServiceError(f"Unknown role id(s): {sorted(missing)}")
        return roles

    @transaction.atomic
    def grant_permission(self, tenant_id: str, role: Role, resource: str, action: str) -> None:
        self.permissions.grant(tenant_id, role, resource, action)
        # Casbin subject is the role's SLUG, not .name -- slug is set once at
        # creation and never recomputed (see RMSluggedModel), so a later rename
        # of the role doesn't orphan this policy row the way .name would.
        self.policy.grant(tenant_id, role.slug, resource, action)
        self.audit.record_event(
            tenant_id, "permission_granted",
            metadata={"role": role.name, "resource": resource, "action": action},
        )

    @transaction.atomic
    def revoke_permission(self, tenant_id: str, role: Role, resource: str, action: str) -> None:
        self.policy.revoke(tenant_id, role.slug, resource, action)
        self.audit.record_event(
            tenant_id, "permission_revoked",
            metadata={"role": role.name, "resource": resource, "action": action},
        )

    @transaction.atomic
    def create_persona(self, tenant_id: str, name: str, roles: list[Role]) -> Persona:
        persona = self.roles.create_persona(tenant_id, name, roles)
        # Link the persona to each bundled role in Casbin -- WITHOUT this,
        # a persona's `roles` M2M is Django-only bookkeeping and grants it
        # NO real permissions, no matter what its slug is. Multi-level RBAC:
        # g(user, persona.slug) + g(persona.slug, role.slug) + p(role.slug, ...)
        # resolves transitively through Casbin's own role manager.
        for role in roles:
            self.policy.assign_role_to_subject(
                tenant_id, persona.slug, role.slug,
                subject_type=RoleAssignment.SUBJECT_TYPE_PERSONA,
                group_type=RoleAssignment.GROUP_TYPE_ROLE,
            )
        self.audit.record_event(
            tenant_id, "persona_created",
            metadata={"persona": persona.name, "roles": [r.name for r in roles]},
        )
        return persona

    def list_personas(self, tenant_id: str) -> list[Persona]:
        return self.roles.list_personas(tenant_id)

    def get_persona(self, tenant_id: str, persona_id: int) -> Persona:
        persona = self.roles.get_persona_by_id(tenant_id, persona_id)
        if persona is None:
            raise RoleServiceError(f"Persona {persona_id} not found")
        return persona

    def get_persona_by_name(self, tenant_id: str, name: str) -> Persona:
        persona = self.roles.get_persona(tenant_id, name)
        if persona is None:
            raise RoleServiceError(f"Persona '{name}' not found")
        return persona

    def get_or_create_default_persona(self, tenant_id: str) -> Persona:
        """
        Every tenant (including the configured default tenant -- see
        default-tenant-and-persona.md) lazily gets its own Persona with this
        name on first use, rather than requiring one to be pre-provisioned
        per tenant. Starts with ZERO bundled roles (zero real permissions)
        until an admin explicitly grants some -- a safe, no-privilege
        starting point, not an implicit admin/superuser shortcut.

        Called by UserService.create_user (and the create_user.py CLI
        command) whenever a new user isn't given an explicit persona, so
        every user ends up with at least one eligible persona -- which is
        what lets AuthenticationService._resolve_persona auto-select at
        login without needing `persona_id` in the request (exactly one
        eligible persona -> auto-selected, no code change needed there).
        """
        name = settings.RM_AUTH.get("DEFAULT_PERSONA_NAME", "Default")
        existing = self.roles.get_persona(tenant_id, name)
        if existing:
            return existing
        return self.create_persona(tenant_id, name, roles=[])

    @transaction.atomic
    def assign_persona(
        self, tenant_id: str, user_id: int, persona: Persona, is_default: bool = False
    ) -> None:
        self.roles.assign_persona(tenant_id, user_id, persona, is_default=is_default)
        # Persona is the Casbin `g` grouping subject -- keyed by SLUG (stable
        # across renames), not .name. See PolicyRule/RoleAssignment docstrings.
        # NOTE: `is_default` is intentionally NOT threaded into this Casbin
        # call -- it's a login-time UX flag (which persona /login picks when
        # persona_id is omitted), not an authorization concept, and has no
        # meaning to Casbin's enforce() at all. See UserPersonaAssignment's
        # docstring for why it lives only in the Django-side table.
        self.policy.assign_role_to_subject(
            tenant_id, str(user_id), persona.slug,
            subject_type=RoleAssignment.SUBJECT_TYPE_USER,
            group_type=RoleAssignment.GROUP_TYPE_PERSONA,
        )
        self.audit.record_event(
            tenant_id, "role_assigned", user_id=user_id,
            metadata={"persona": persona.name, "is_default": is_default},
        )

    def get_default_persona(self, tenant_id: str, user_id: int) -> Persona | None:
        """The persona /login uses when `persona_id` is omitted, even if the
        user has more than one eligible persona. Returns None if none has
        been marked default yet -- login then falls back to requiring an
        explicit choice, same as before this feature existed."""
        return self.roles.get_default_persona(tenant_id, user_id)

    @transaction.atomic
    def set_default_persona(self, tenant_id: str, user_id: int, persona: Persona) -> None:
        """Marks an ALREADY-assigned persona as the user's default, without
        re-assigning it -- e.g. for fixing up a user who already has several
        personas and no default set. Raises if the persona isn't assigned to
        this user yet (assign it first via assign_persona)."""
        assignment = self.roles.set_default_persona(tenant_id, user_id, persona)
        if assignment is None:
            raise RoleServiceError(
                f"Persona '{persona.name}' is not assigned to user {user_id} for tenant "
                f"'{tenant_id}' -- assign it first (RoleService.assign_persona)."
            )
        self.audit.record_event(
            tenant_id, "default_persona_set", user_id=user_id,
            metadata={"persona": persona.name},
        )

    @transaction.atomic
    def revoke_persona(self, tenant_id: str, user_id: int, persona: Persona) -> None:
        self.roles.revoke_persona(tenant_id, user_id, persona)
        self.policy.revoke_role_from_subject(tenant_id, str(user_id), persona.slug)
        self.audit.record_event(
            tenant_id, "role_revoked", user_id=user_id, metadata={"persona": persona.name}
        )

    def eligible_personas(self, tenant_id: str, user_id: int) -> list[Persona]:
        return self.roles.eligible_personas(tenant_id, user_id)

    def user_permissions(self, tenant_id: str, persona: Persona) -> set[str]:
        """
        Expands a persona's roles into a flat "resource:action" permission
        set, for display/debugging purposes (e.g. an admin UI). Request-time
        allow/deny decisions still go through PolicyService.is_allowed, not
        this method (§6).
        """
        roles = list(persona.roles.all())
        perms = self.permissions.for_roles(tenant_id, roles)
        return {f"{p.resource.name}:{p.action.name}" for p in perms}
