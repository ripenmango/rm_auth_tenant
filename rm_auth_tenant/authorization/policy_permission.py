from rest_framework.permissions import BasePermission


class RequiresPermission(BasePermission):
    """
    DRF permission class -- its ONLY job is the allow/deny call (§4 of design
    doc). Usage:

        class WorkflowViewSet(RMModelViewSet):
            permission_classes = [RequiresPermission("workflow", "edit")]

    Delegates to request.security_context.can(...), which in turn calls
    PolicyService.is_allowed (Casbin). Never queries roles/permissions itself.
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
