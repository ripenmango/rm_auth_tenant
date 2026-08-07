from rest_framework.filters import BaseFilterBackend

from rm_auth_tenant.authorization.access_scope import EntityAccessService, resolve_allowed_roles


class TenantAndAccessScopedFilterBackend(BaseFilterBackend):
    """
    Centralizes tenant + object-level access scoping for list AND (via
    RMScopedModelViewSet.get_object(), see viewsets.py) detail views --
    registered once, applies automatically to every ViewSet that opts in by
    setting `entity_type`, the same "can't be forgotten at a new call site"
    guarantee RMSoftDeleteManager gives for deleted_at. See DESIGN.md,
    "Why a FilterBackend, not middleware or a Manager".

    Not used for the `manage`-action's object-level scope decision --
    that's `RequiresPermission.has_object_permission`, reusing the same
    resolve_allowed_roles() so the two can never disagree. This backend is
    what shapes list() queries specifically.
    """

    def filter_queryset(self, request, queryset, view):
        entity_type = getattr(view, "entity_type", None)
        if entity_type is None:
            # Opt-out for viewsets with no per-object ownership concept at
            # all (Role, Persona, Resource, ... -- tenant-wide by nature).
            return queryset

        context = request.security_context
        queryset = queryset.filter(tenant_id=context.tenant_id)

        allowed_roles = resolve_allowed_roles(context, entity_type, "view")
        if allowed_roles is None:
            return queryset  # manage_all -- tenant-wide, unscoped

        entity_ids = EntityAccessService().allowed_entity_ids(
            context.tenant_id, entity_type, context.user_id, allowed_roles
        )
        return queryset.filter(public_id__in=entity_ids)
