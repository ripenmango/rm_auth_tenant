from django.apps import AppConfig


class RmAuthTenantConfig(AppConfig):
    """
    Single app_label ("rm_auth_tenant") for tenant-scoped identity and
    authorization data, split out of rm_auth per the "Tier B Implementation
    Plan" doc (section 0/0.1): Tenant/Domain/Action are platform-wide and
    stay in rm_auth (SHARED_APPS); everything here -- User, Role, Persona,
    Permission, PolicyRule, RoleAssignment, and their supporting services --
    is tenant-specific data and belongs in TENANT_APPS, migrated onto every
    tenant schema (including "public", the default shared home for
    not-yet-promoted tenants).

    Depends on rm_auth (Tenant/Domain lookups, e.g. TenantRepository) --
    never the other way around. rm_auth must never import from this app.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "rm_auth_tenant"
    label = "rm_auth_tenant"
    verbose_name = "RM Auth Tenant"
