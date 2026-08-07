from django.shortcuts import get_object_or_404

from drf_base_app.views import RMModelViewSet

from rm_auth_tenant.authorization.filters import TenantAndAccessScopedFilterBackend


class RMScopedModelViewSet(RMModelViewSet):
    """
    Base ViewSet for any tenant-scoped entity that also needs per-object
    ("own it or it's shared with you") access control -- Workspace,
    Workflow, and any future shareable entity. See DESIGN.md for the full
    picture; short version:

        class WorkflowViewSet(RMScopedModelViewSet):
            entity_type = "workflow"
            permission_classes = [RequiresPermission("workflow", "manage")]
            ...

    Two things happen automatically just from setting `entity_type`:
      1. list() is scoped by TenantAndAccessScopedFilterBackend (registered
         below) -- DRF's own ListModelMixin already calls
         self.filter_queryset(self.get_queryset()), nothing else to wire up.
      2. get_object() (retrieve/update/destroy/partial_update) is ALSO
         scoped by the same backend, because it's routed through
         self.filter_queryset() below -- DRF's own documented pattern for
         exactly this purpose -- and check_object_permissions() runs
         afterward, which is what invokes
         RequiresPermission.has_object_permission (the `manage`-action
         check, sibling to the `view`-action check the filter backend does).

    ViewSets that have no per-object ownership concept (Role, Persona,
    Resource, ...) should keep using plain RMModelViewSet, not this class --
    entity_type would have nothing meaningful to scope by for them.
    """

    entity_type: str | None = None
    lookup_field = "public_id"
    filter_backends = [TenantAndAccessScopedFilterBackend]
    abstract = True  # base class -- concrete subclasses declare permission_classes

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
        obj = get_object_or_404(queryset, **{self.lookup_field: self.kwargs[lookup_url_kwarg]})
        self.check_object_permissions(self.request, obj)
        return obj
