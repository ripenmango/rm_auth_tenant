from rm_auth.permissions.repositories import ActionRepository

from rm_auth_tenant.permissions.models import Action, Permission, Resource


class PermissionRepository:
    def get_or_create_resource(self, tenant_id: str, name: str) -> Resource:
        resource, _ = Resource.objects.get_or_create(tenant_id=tenant_id, name=name)
        return resource

    def get_or_create_action(self, name: str) -> Action:
        # Action lives in the shared rm_auth app now -- see permissions/models.py's
        # docstring and "Tier B Implementation Plan" doc section 0.2.
        return ActionRepository().get_or_create_action(name)

    def grant(
        self, tenant_id: str, role, resource_name: str, action_name: str
    ) -> Permission:
        resource = self.get_or_create_resource(tenant_id, resource_name)
        action = self.get_or_create_action(action_name)
        permission, _ = Permission.objects.get_or_create(
            tenant_id=tenant_id, role=role, resource=resource, action=action
        )
        return permission

    def for_roles(self, tenant_id: str, roles) -> list[Permission]:
        return list(
            Permission.objects.filter(
                tenant_id=tenant_id, role__in=roles
            ).select_related("resource", "action")
        )
