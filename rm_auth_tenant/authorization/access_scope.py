"""
Object-level access scoping -- "which specific entities can this caller see
or act on", as distinct from Casbin's `RequiresPermission` ("can this
persona reach this endpoint at all"). See DESIGN.md in this package for the
full rationale (Casbin vs EntityAccessGrant, why a generic table, etc.).

Two things live here:
  - ROLES_ALLOWING_ACTION: which EntityAccessGrant roles permit which action.
  - resolve_allowed_roles(): the one function both
    TenantAndAccessScopedFilterBackend (queryset scoping) and
    RequiresPermission.has_object_permission (single-object scoping) call,
    so the two can never drift out of sync with each other.
  - EntityAccessService: the only entry point for reading/writing
    EntityAccessGrant rows -- share/revoke endpoints, and
    grant_owner()/purge_for_entity() called by the owning service/signal.
"""
from django.db import transaction

from rm_auth_tenant.authorization.entity_access_models import EntityAccessGrant

# Which EntityAccessGrant roles permit which action. "manage" here means
# "full CRUD" (create/update/delete/read on the entity's own metadata) --
# not to be confused with Casbin's coarse `RequiresPermission("workflow",
# "manage")` gate, which is a different, type-level check that happens
# first and separately (see policy_permission.py).
ROLES_ALLOWING_ACTION = {
    "view": {EntityAccessGrant.ROLE_VIEWER, EntityAccessGrant.ROLE_EDITOR, EntityAccessGrant.ROLE_OWNER},
    "edit": {EntityAccessGrant.ROLE_EDITOR, EntityAccessGrant.ROLE_OWNER},
    "manage": {EntityAccessGrant.ROLE_OWNER},
    "publish": {EntityAccessGrant.ROLE_OWNER},
    "share": {EntityAccessGrant.ROLE_OWNER},
}


def resolve_allowed_roles(context, entity_type: str, action: str) -> set[str] | None:
    """
    Returns the set of EntityAccessGrant roles that satisfy `action` for
    this caller, or None to mean "no object-level scoping applies -- every
    entity of this type in the tenant is visible" (a real admin/enterprise
    persona holding `manage_all`).

    Returns an empty set when the persona holds neither `owner_only` nor
    `shared` for this entity_type -- i.e. genuinely no access, not "forgot
    to configure" (a persona that also lacks the coarse `RequiresPermission`
    gate never reaches this code at all, so an empty set here specifically
    means "reachable but nothing to scope to").
    """
    if context.can(entity_type, "manage_all"):
        return None

    action_roles = ROLES_ALLOWING_ACTION.get(action, {EntityAccessGrant.ROLE_OWNER})
    allowed: set[str] = set()
    if context.can(entity_type, "owner_only"):
        allowed |= {EntityAccessGrant.ROLE_OWNER} & action_roles
    if context.can(entity_type, "shared"):
        allowed |= action_roles
    return allowed


class EntityAccessError(Exception):
    """Raised for invalid share/revoke requests (e.g. revoking the last
    owner) -- views translate this into a 400."""


class EntityAccessService:
    @transaction.atomic
    def grant_owner(self, tenant_id: str, entity_type: str, entity_id: str, user_id: int) -> EntityAccessGrant:
        """Called once, by the owning service (e.g. WorkspaceService.create_workspace/
        WorkflowService.create_workflow), in the SAME transaction as the entity
        itself. This is what makes a freshly created entity "belong" to its
        creator -- there's no separate created_by-based fallback downstream."""
        grant, _ = EntityAccessGrant.objects.update_or_create(
            tenant_id=tenant_id, entity_type=entity_type, entity_id=entity_id, user_id=user_id,
            defaults={"role": EntityAccessGrant.ROLE_OWNER},
        )
        return grant

    def share(
        self, tenant_id: str, entity_type: str, entity_id: str, user_id: int, role: str
    ) -> EntityAccessGrant:
        if role == EntityAccessGrant.ROLE_OWNER:
            # Ownership transfer is a distinct, rarer operation with its own
            # "don't leave the entity ownerless" invariant to protect -- not
            # something the ordinary share endpoint should do as a side effect.
            raise EntityAccessError(
                "Use the ownership-transfer endpoint to grant the 'owner' role, "
                "not share()."
            )
        grant, _ = EntityAccessGrant.objects.update_or_create(
            tenant_id=tenant_id, entity_type=entity_type, entity_id=entity_id, user_id=user_id,
            defaults={"role": role},
        )
        return grant

    def revoke(self, tenant_id: str, entity_type: str, entity_id: str, user_id: int) -> None:
        grant = EntityAccessGrant.objects.filter(
            tenant_id=tenant_id, entity_type=entity_type, entity_id=entity_id, user_id=user_id,
        ).first()
        if grant is None:
            return
        if grant.role == EntityAccessGrant.ROLE_OWNER:
            raise EntityAccessError(
                "Can't revoke the owner's own access -- transfer ownership first, "
                "or delete the entity."
            )
        grant.delete()

    def list_grants(self, tenant_id: str, entity_type: str, entity_id: str) -> list[EntityAccessGrant]:
        return list(
            EntityAccessGrant.objects.filter(
                tenant_id=tenant_id, entity_type=entity_type, entity_id=entity_id
            ).order_by("role", "user_id")
        )

    def has_access(
        self, tenant_id: str, entity_type: str, entity_id: str, user_id: int, allowed_roles: set[str]
    ) -> bool:
        if not allowed_roles:
            return False
        return EntityAccessGrant.objects.filter(
            tenant_id=tenant_id, entity_type=entity_type, entity_id=entity_id,
            user_id=user_id, role__in=allowed_roles,
        ).exists()

    def allowed_entity_ids(
        self, tenant_id: str, entity_type: str, user_id: int, allowed_roles: set[str]
    ):
        """Returns a values_list queryset of entity_ids -- lazy, meant to be
        used inside a `.filter(public_id__in=...)`, not evaluated eagerly."""
        if not allowed_roles:
            return EntityAccessGrant.objects.none().values_list("entity_id", flat=True)
        return EntityAccessGrant.objects.filter(
            tenant_id=tenant_id, entity_type=entity_type, user_id=user_id, role__in=allowed_roles,
        ).values_list("entity_id", flat=True)

    def purge_for_entity(self, tenant_id: str, entity_type: str, entity_id: str) -> None:
        """Called by the post_delete signal on hard-delete (see signals.py)
        -- not by ordinary soft-delete, which should leave sharing intact in
        case the entity is later restored."""
        EntityAccessGrant.objects.filter(
            tenant_id=tenant_id, entity_type=entity_type, entity_id=entity_id
        ).delete()
