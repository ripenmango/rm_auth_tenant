from django.db import models as dj_models

from drf_base_app import models
from drf_base_app.models.base import RMAuditModel, RMSluggedModel

# Action stays behind in the (shared) rm_auth app -- it's platform-wide
# vocabulary, not tenant data. This is the one intentional cross-app
# ForeignKey in this split: Permission (tenant-scoped, lives in whichever
# schema is active) -> Action (shared, always in the public schema). Valid
# and supported by Postgres (cross-schema FKs within the same database) --
# see "Tier B Implementation Plan" doc, sections 0.2 and 6.
from rm_auth.permissions.models import Action

__all__ = ["Action", "Resource", "Permission"]


class Resource(RMAuditModel, RMSluggedModel):
    """A protectable resource type, e.g. "workflow", "form", "user"."""

    tenant_id = models.CharField(max_length=64, db_index=True)
    name = models.CharField(max_length=100)
    # Tenant-scoped, not globally unique -- two tenants can each have a
    # "workflow" resource with the same slug (see uniq_resource_tenant_slug
    # below), unlike RMSluggedModel's column-level default.
    slug = models.SlugField(max_length=255, unique=False, blank=True)

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_resource"  # unchanged -- db_table is independent of app_label
        constraints = [
            dj_models.UniqueConstraint(
                fields=["tenant_id", "name"], name="uniq_resource_tenant_name"
            ),
            dj_models.UniqueConstraint(
                fields=["tenant_id", "slug"], name="uniq_resource_tenant_slug"
            ),
        ]

    def __str__(self) -> str:
        return self.name


class Permission(RMAuditModel):
    """
    (Resource, Action) granted to a Role, within a tenant. This is the
    Django-native mirror of the Casbin `p` rows in policy.models.PolicyRule --
    kept as a normal relational table too so RoleService.user_permissions()
    can be queried/joined/reported on without going through Casbin, and so
    role administration UIs have a normal table to manage. PolicyService is
    still the source of truth for allow/deny decisions at request time.
    """

    tenant_id = models.CharField(max_length=64, db_index=True)
    role = models.ForeignKey(
        "rm_auth_tenant.Role", on_delete=dj_models.CASCADE, related_name="permissions"
    )
    resource = models.ForeignKey(
        Resource, on_delete=dj_models.CASCADE, related_name="permissions"
    )
    action = models.ForeignKey(
        Action, on_delete=dj_models.CASCADE, related_name="permissions"
    )

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_permission"  # unchanged -- db_table is independent of app_label
        constraints = [
            dj_models.UniqueConstraint(
                fields=["tenant_id", "role", "resource", "action"],
                name="uniq_permission",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.role.name}:{self.resource.name}:{self.action.name}"
