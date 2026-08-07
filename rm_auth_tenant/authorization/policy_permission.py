from rest_framework.permissions import BasePermission

from rm_auth_tenant.authorization.access_scope import EntityAccessService, resolve_allowed_roles


class RequiresPermission(BasePermission):
    """
    DRF permission class -- two separate jobs, both delegating out rather
    than deciding anything itself (see authorization/DESIGN.md):

        class WorkflowViewSet(RMScopedModelViewSet):
            entity_type = "workflow"
            permission_classes = [RequiresPermission("workflow", "manage")]

    has_permission -- coarse, type-level: "can this persona perform `action`
    on resource `resource` AT ALL", via request.security_context.can(...) ->
    PolicyService.is_allowed (Casbin). Runs for every request, list or
    detail. Never queries EntityAccessGrant.

    has_object_permission -- fine, object-level: "does THIS caller qualify
    for `action` on THIS specific object", via EntityAccessGrant. Only runs
    when a view actually calls check_object_permissions(request, obj) --
    DRF's ModelViewSet does this automatically inside the default
    get_object(), and RMScopedModelViewSet's own get_object() override
    (viewsets.py) calls it explicitly too, so every retrieve/update/destroy
    on an RMScopedModelViewSet is covered. A plain RMModelViewSet (no
    per-object concept -- Role, Persona, ...) never calls this, which is
    fine: has_permission alone is the complete, correct check for those.
    """

    def __init__(self, resource: str, action: str):
        self.resource = resource
        self.action = action

    def __call__(self):
        # DRF instantiates permission_classes entries with no args; this
        # factory pattern lets call sites parameterize per-view while still
        # satisfying that instantiation contract.
        return self

    def has_permission(self, request, view) -> bool:
        context = getattr(request, "security_context", None)
        if context is None:
            return False
        return context.can(self.resource, self.action)

    def has_object_permission(self, request, view, obj) -> bool:
        context = request.security_context
        allowed_roles = resolve_allowed_roles(context, self.resource, self.action)
        if allowed_roles is None:
            return True  # manage_all -- tenant-wide, no object-level restriction
        return EntityAccessService().has_access(
            context.tenant_id, self.resource, obj.public_id, context.user_id, allowed_roles
        )
