from drf_base_app import models
from drf_base_app.models.base import RMAuditModel
from drf_base_app.models.indexes import TenantIndex
from django.db import models as dj_models


class EntityAccessGrant(RMAuditModel):
    """
    Generic, per-object access-control row: "this user has this role on
    this specific entity" -- deliberately NOT `WorkflowCollaborator` (or any
    other single-entity-typed table). See authorization/DESIGN.md ("Why one
    generic table, not per-entity share tables") for the full rationale;
    short version: every future shareable entity (Workspace, a future
    "WorkflowRunner", anything else) reuses this same table and the same
    RequiresPermission.has_object_permission / TenantAndAccessScopedFilterBackend
    code path, instead of a bespoke *Collaborator model + bespoke scoping
    logic per entity type.

    `entity_id` is deliberately a plain CharField (the target's `public_id`,
    e.g. "wrf_8jz3k2n9qr7tv..."), not a typed ForeignKey -- this table has
    no way to know at class-definition time which model(s) it will ever
    need to point at (that's the whole point: new entity types opt in
    without a migration here). The cost is a real one and is deliberate,
    not an oversight:

      - No FK-enforced referential integrity. A grant can silently outlive
        its target if that target is ever HARD-deleted (soft-delete is
        unaffected -- see below).
      - Mitigated by `authorization.signals.connect_hard_delete_cleanup`,
        an opt-in post_delete receiver wired per model (see that module),
        not automatic for every model in the project.
      - The share endpoint (e.g. rm_workflow's WorkflowCollaboratorsView --
        each consuming app owns its own share/revoke HTTP surface, calling
        EntityAccessService directly) always fetches the target through its
        owning service first (to check the caller actually holds an
        `owner` grant on it), so a grant can never be CREATED against a
        nonexistent object -- only orphaned later, by a hard-delete, which
        the signal above cleans up.

    role semantics (see access_scope.py's ROLES_ALLOWING_ACTION for the
    authoritative action mapping -- this is a summary, not the source of
    truth):
      - viewer: read-only
      - editor: read + write metadata/content, not publish/delete/share
      - owner:  everything, including publish/delete/share. Set
                automatically for the creator of every entity at creation
                time (see EntityAccessService.grant_owner) -- ownership
                IS a grant row here, not a separate created_by-based
                special case downstream.
    """

    ROLE_VIEWER = "viewer"
    ROLE_EDITOR = "editor"
    ROLE_OWNER = "owner"
    ROLE_CHOICES = [
        (ROLE_VIEWER, "Viewer"),
        (ROLE_EDITOR, "Editor"),
        (ROLE_OWNER, "Owner"),
    ]

    tenant_id = models.CharField(max_length=64, db_index=True)
    # Matches the Casbin `resource` vocabulary (Resource.name -- "workspace",
    # "workflow", ...) so the two systems stay conceptually aligned, even
    # though this table is never read by Casbin/the policy engine itself.
    entity_type = models.CharField(max_length=64)
    entity_id = models.CharField(max_length=64)
    user_id = models.BigIntegerField(db_index=True)
    role = models.CharField(max_length=16, choices=ROLE_CHOICES)

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_entity_access_grant"
        constraints = [
            dj_models.UniqueConstraint(
                fields=["tenant_id", "entity_type", "entity_id", "user_id"],
                name="uniq_entity_access_grant",
            ),
        ]
        indexes = [
            # Backs "who can access THIS entity" (has_object_permission,
            # the share/revoke/list-collaborators endpoints).
            TenantIndex(fields=["entity_type", "entity_id"]),
            # Backs "what can THIS user see" (TenantAndAccessScopedFilterBackend's
            # list-view query -- the hot path, one per list() call).
            TenantIndex(fields=["entity_type", "user_id"]),
        ]

    def __str__(self) -> str:
        return f"{self.tenant_id}:{self.entity_type}:{self.entity_id}:{self.user_id}:{self.role}"
