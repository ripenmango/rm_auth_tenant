from drf_base_app import models
from drf_base_app.models.base import RMAuditModel, RMPublicIdModel, RMSluggedModel
from django.db import models as dj_models


class Role(RMAuditModel, RMSluggedModel, RMPublicIdModel):
    """A named set of Permissions (§5 of design doc)."""

    public_id_prefix = "rol"

    tenant_id = models.CharField(max_length=64, db_index=True)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=255, blank=True, default="")
    # Tenant-scoped, not globally unique -- see uniq_role_tenant_slug below.
    slug = models.SlugField(max_length=255, unique=False, blank=True)

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_role"  # unchanged -- db_table is independent of app_label
        constraints = [
            dj_models.UniqueConstraint(
                fields=["tenant_id", "name"], name="uniq_role_tenant_name"
            ),
            dj_models.UniqueConstraint(
                fields=["tenant_id", "slug"], name="uniq_role_tenant_slug"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.tenant_id}:{self.name}"


class PersonaRole(RMAuditModel):
    """
    Explicit through table for Persona.roles -- replaces what would
    otherwise be Django's implicit `rm_auth_tenant_persona_roles` M2M
    table. Kept explicit (rather than an implicit ManyToManyField) so a
    later need to record e.g. who granted a role to a persona and when
    doesn't require migrating off an implicit M2M table.

    No extra required fields beyond the two FKs, so existing callers like
    RoleRepository.create_persona's `persona.roles.set(roles)` keep working
    unchanged -- Django allows .set()/.add()/.remove() through an explicit
    `through` model as long as it has no additional required fields.
    """

    persona = models.ForeignKey(
        "Persona", on_delete=dj_models.CASCADE, related_name="persona_roles"
    )
    role = models.ForeignKey(
        Role, on_delete=dj_models.CASCADE, related_name="role_personas"
    )

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_persona_role"
        constraints = [
            dj_models.UniqueConstraint(
                fields=["persona", "role"], name="uniq_persona_role"
            )
        ]


class Persona(RMAuditModel, RMSluggedModel, RMPublicIdModel):
    """
    A named bundle of Roles representing "how a user is acting" (§5). A user
    can be eligible for several personas but only one is active per session
    (§5 decision: persona is selected per session, fixed for its lifetime).
    """

    public_id_prefix = "per"

    tenant_id = models.CharField(max_length=64, db_index=True)
    name = models.CharField(max_length=100)
    roles = models.ManyToManyField(
        Role, through=PersonaRole, related_name="personas", blank=True
    )
    # Tenant-scoped, not globally unique -- see uniq_persona_tenant_slug below.
    slug = models.SlugField(max_length=255, unique=False, blank=True)

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_persona"  # unchanged -- db_table is independent of app_label
        constraints = [
            dj_models.UniqueConstraint(
                fields=["tenant_id", "name"], name="uniq_persona_tenant_name"
            ),
            dj_models.UniqueConstraint(
                fields=["tenant_id", "slug"], name="uniq_persona_tenant_slug"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.tenant_id}:{self.name}"


class UserPersonaAssignment(RMAuditModel):
    """
    Which personas a given user is eligible to act as, within a tenant.

    `is_default` marks which one of a user's (possibly several) eligible
    personas `/login` should use when the request omits `persona_id` --
    see AuthenticationService._resolve_persona and
    default-tenant-and-persona.md. This is purely a login-time UX concern:
    it has no Casbin/authorization meaning whatsoever (unlike
    RoleAssignment's `subject`/`group_slug`, this flag is never read by
    PolicyService or the enforcer) -- a user can be denied everything their
    default persona would grant, same as any other persona.

    At most one row per (tenant_id, user_id) may have `is_default=True` --
    enforced by the partial unique constraint below, not just by
    RoleService's write path, so this can never drift even from a direct
    ORM write elsewhere.
    """

    tenant_id = models.CharField(max_length=64, db_index=True)
    user_id = models.BigIntegerField(db_index=True)
    persona = models.ForeignKey(
        Persona, on_delete=dj_models.CASCADE, related_name="assignments"
    )
    is_default = models.BooleanField(default=False)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_user_persona_assignment"  # unchanged
        constraints = [
            dj_models.UniqueConstraint(
                fields=["tenant_id", "user_id", "persona"], name="uniq_user_persona"
            ),
            dj_models.UniqueConstraint(
                fields=["tenant_id", "user_id"],
                condition=dj_models.Q(is_default=True),
                name="uniq_default_persona_per_user",
            ),
        ]
        indexes = [dj_models.Index(fields=["tenant_id", "user_id"])]
