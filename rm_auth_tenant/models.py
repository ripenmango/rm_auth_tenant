"""
Re-exports every tenant-specific model split out of rm_auth into this app,
per the "Tier B Implementation Plan" doc, section 0/0.1: everything here is
tenant-scoped data (User/Role/Persona/Permission/PolicyRule/RoleAssignment/
RefreshTokenRecord/LoginAttempt/SecurityEvent all carry -- or are uniquely
constrained on -- tenant_id) and belongs in TENANT_APPS, migrated onto every
tenant schema (including "public", the default shared home for
not-yet-promoted tenants -- see that doc's section 1).

Tenant/Domain/Action stay behind in rm_auth (see that module's docstring) --
Resource/Permission import Action cross-app from there (see
permissions/models.py's docstring for why that one cross-app FK is fine).

Each model's own Meta.app_label = "rm_auth_tenant" is what actually binds it
to this app; this module just gives
`python manage.py makemigrations rm_auth_tenant` one place to discover
everything and gives callers a convenient
`from rm_auth_tenant.models import User` shortcut.
"""
from rm_auth_tenant.accounts.models import PasswordHistory, User
from rm_auth_tenant.audit.models import LoginAttempt, SecurityEvent
from rm_auth_tenant.authorization.entity_access_models import EntityAccessGrant
from rm_auth_tenant.jwt_auth.models import RefreshTokenRecord
from rm_auth_tenant.permissions.models import Permission, Resource
from rm_auth_tenant.policy.models import PolicyRule, RoleAssignment
from rm_auth_tenant.roles.models import Persona, Role, UserPersonaAssignment

__all__ = [
    "User",
    "PasswordHistory",
    "Role",
    "Persona",
    "UserPersonaAssignment",
    "Resource",
    "Permission",
    "PolicyRule",
    "RoleAssignment",
    "RefreshTokenRecord",
    "LoginAttempt",
    "SecurityEvent",
    "EntityAccessGrant",
]
