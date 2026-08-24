"""
Standalone test-harness settings for exercising `rm_auth_tenant`
independently. A consuming platform project would NOT use this file — it
defines its own settings and adds both `rm_auth` (shared/platform app) and
`rm_auth_tenant` (this app) to INSTALLED_APPS (see README.md and the
"Tier B Implementation Plan" doc in rm_workflow_store/docs/, section 0/0.1,
for why there are two apps).

This harness installs `rm_auth` as a normal dependency (its wheel, same as
`drf_base`) purely to satisfy rm_auth_tenant's own cross-app references
(Tenant/Domain lookups, TenantResolutionMiddleware, SecurityContextMiddleware
-- see that doc's section 0.1 for exactly which pieces stayed in rm_auth).
It does NOT run django-tenants' schema-per-tenant machinery -- that's the
composing platform project's job; this harness tests rm_auth_tenant's models/
services/API against a single plain schema, which is sufficient for this
app's own unit/API tests (none of which currently exercise cross-schema
behavior).
"""

import os
from pathlib import Path

from drf_base_app.logging.config import setup as configure_logging
from drf_base_app.tenancy.settings import get_default_persona_name, get_default_tenant_id

BASE_DIR = Path(__file__).resolve().parent.parent

configure_logging(level=os.environ.get("LOG_LEVEL"))

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-not-for-production")
DEBUG = os.environ.get("DJANGO_DEBUG", "true").lower() == "true"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")

# django_tenants requires SHARED_APPS/TENANT_APPS to exist even in a harness
# like this one that never actually runs migrate_schemas or switches schemas
# -- its own AppConfig.ready() checks for TENANT_APPS unconditionally. Unlike
# rm_auth's own harness, this one has a real tenant-scoped app (this repo),
# so the split below is meaningful even though migrate_schemas is never
# actually invoked here.
SHARED_APPS = [
    "django_tenants",  # provides TenantMixin/DomainMixin used by rm_auth.tenants.models
    "django.contrib.contenttypes",
    "django.contrib.auth",  # kept only for Django admin/permission plumbing compatibility
    # "django.contrib.admin",
    # "django.contrib.sessions",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "rm_auth",  # shared/platform app -- Tenant, Domain, Action (dependency, not this repo's code)
    "django.contrib.messages",
    "drf_base_app",
]

TENANT_APPS = [
    "rm_auth_tenant",  # this repo
]

INSTALLED_APPS = list(SHARED_APPS) + [
    app for app in TENANT_APPS if app not in SHARED_APPS
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    # Stays in rm_auth (shared) -- resolves tenant_id from subdomain/header/JWT
    # claim onto request. See "Tier B Implementation Plan" doc, section 0.1.
    "rm_auth.middleware.tenant_resolution.TenantResolutionMiddleware",
    "drf_base_app.logging.middleware.RequestContextMiddleware",
    # Also stays in rm_auth (shared) -- its PolicyService import is a lazy,
    # cross-app import into rm_auth_tenant.policy.service at call time (see
    # that middleware's own docstring).
    "rm_auth.middleware.security_context.SecurityContextMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        # django_tenants' backend, NOT plain django.db.backends.postgresql --
        # required the moment any model uses TenantMixin/DomainMixin (rm_auth's
        # Tenant/Domain do), even though this harness never itself calls
        # migrate_schemas or switches schemas.
        "ENGINE": "django_tenants.postgresql_backend",
        # Deliberately a DIFFERENT default database name than rm_auth_project's
        # own harness ("appdb") -- the two are separate Django projects with
        # independent migration histories, and pointing both at one physical
        # database produces exactly the kind of
        # InconsistentMigrationHistory error this comment is here to prevent.
        # See .env.example and the "Tier B Implementation Plan" doc's
        # correction note for the incident that caused this.
        "NAME": os.environ.get("POSTGRES_DB", "rm_auth_tenant_appdb"),
        "USER": os.environ.get("POSTGRES_USER", "appuser"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "apppassword"),
        "HOST": os.environ.get("POSTGRES_HOST", "localhost"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": int(os.environ.get("DB_CONN_MAX_AGE", "0")),
    }
}
HAS_MULTI_TYPE_TENANTS = False  # django_tenants setting -- this harness never actually runs migrate_schemas, but rm_auth_tenant's own models use TenantMixin/DomainMixin, so this must be set to satisfy django_tenants' AppConfig.ready() check.
DATABASE_ROUTERS = ["drf_base_app.tenancy.routers.HybridTenantSyncRouter"]  # NOT django_tenants.routers.TenantSyncRouter -- see §1's correction, v0.6
# Tells django_tenants' own AppConfig.ready() check (which otherwise demands
# the stock TenantSyncRouter specifically) that our custom router is the
# intended one -- see django_tenants/apps.py's ready(), and
# HybridTenantSyncRouter's own docstring.
TENANT_SYNC_ROUTER = "drf_base_app.tenancy.routers.HybridTenantSyncRouter"

# Required as soon as rm_auth.tenants.models (Tenant/Domain, TenantMixin/
# DomainMixin) is imported -- django_tenants builds a real ForeignKey field
# from these settings at class-definition time, not just when actual
# schema-per-tenant switching/migrate_schemas is invoked.
TENANT_MODEL = "rm_auth.Tenant"
TENANT_DOMAIN_MODEL = "rm_auth.Domain"

AUTH_USER_MODEL = "rm_auth_tenant.User"

# The "system" sentinel actor RMAuditModel.save() falls back to as
# created_by/updated_by when no request-scoped AuditContext user exists.
# The matching User row needs provisioning by this app's own migrations
# once `makemigrations`/a seed step exists here (rm_auth's old
# 0002_seed_system_user migration doesn't apply -- User isn't rm_auth's
# model anymore).
AUDIT_SYSTEM_USERNAME = "system"

AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]

# Standard Django password-strength rules, applied by SignupSerializer's
# validate_password (see api/serializers.py) via django.contrib.auth
# .password_validation.validate_password. Also used anywhere else in the
# project that calls validate_password -- there's only one configured set of
# rules, not a bespoke one per call site.
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": int(os.environ.get("RM_AUTH_PASSWORD_MIN_LENGTH", "8"))},
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# --- Outbound email (signup verification, etc.) ---
# Console backend by default -- prints the email (and its verification
# link/token) to stdout instead of actually sending anything, which is all
# local/dev needs. Point DJANGO_EMAIL_BACKEND at
# 'django.core.mail.backends.smtp.EmailBackend' (plus the EMAIL_HOST_* vars
# below) once there's a real SMTP provider to send through in production.
EMAIL_BACKEND = os.environ.get(
    "DJANGO_EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"
)
EMAIL_HOST = os.environ.get("DJANGO_EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.environ.get("DJANGO_EMAIL_PORT", "25"))
EMAIL_HOST_USER = os.environ.get("DJANGO_EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("DJANGO_EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.environ.get("DJANGO_EMAIL_USE_TLS", "false").lower() == "true"
DEFAULT_FROM_EMAIL = os.environ.get(
    "DJANGO_DEFAULT_FROM_EMAIL", "no-reply@rm-auth-tenant.local"
)

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rm_auth_tenant.authentication.jwt_authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "EXCEPTION_HANDLER": "drf_base_app.error_handler.exceptions.custom_exception_handler",
    "DEFAULT_RENDERER_CLASSES": [
        "drf_base_app.rest_framework.renderers.RMJSONRenderer",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "rm_auth_tenant API",
    "VERSION": "v1",
    "DESCRIPTION": (
        "Tenant-scoped identity & policy-driven authorization API (login, "
        "token refresh, logout, password change, persona switching), split "
        "out of rm_auth -- see the 'Tier B Implementation Plan' doc in "
        "rm_workflow_store/docs/."
    ),
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "APPEND_COMPONENTS": {
        "securitySchemes": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": (
                    "JWT access token issued by /api/rm_auth_tenant/login, sent as "
                    "'Bearer <access_token>' (see JWTAuthentication)."
                ),
            }
        }
    },
    "SWAGGER_UI_SETTINGS": {
        "deepLinking": True,
        "persistAuthorization": True,
        "docExpansion": "list",
    },
    "REDOC_UI_SETTINGS": {
        "lazyRendering": False,
    },
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# rm_auth_tenant library configuration
# ---------------------------------------------------------------------------
RM_AUTH = {
    "JWT_ACCESS_TTL_SECONDS": int(os.environ.get("RM_AUTH_ACCESS_TTL", "900")),
    "JWT_REFRESH_TTL_SECONDS": int(
        os.environ.get("RM_AUTH_REFRESH_TTL", str(60 * 60 * 24 * 7))
    ),
    "DEFAULT_ALGORITHM": os.environ.get("RM_AUTH_DEFAULT_ALGORITHM", "HS256"),
    "DEFAULT_SIGNING_SECRET": os.environ.get(
        "RM_AUTH_HS256_SECRET", "dev-only-hs256-secret"
    ),
    "CASBIN_MODEL_PATH": str(
        BASE_DIR / "rm_auth_tenant" / "policy" / "casbin_model.conf"
    ),
    "ENFORCER_CACHE_TTL_SECONDS": int(os.environ.get("RM_AUTH_ENFORCER_TTL", "300")),
    "DEFAULT_TENANT_ID": get_default_tenant_id(),
    "DEFAULT_PERSONA_NAME": get_default_persona_name(),
    # --- Auto-granted permissions for the default persona (community edition) ---
    # Every (resource, action) pair here is granted to the default tenant's
    # lazily-created default persona ("tenant-administrator" in rm_community
    # by default) -- see RoleService.get_or_create_default_persona /
    # RoleService._sync_default_persona_permissions. Applied via the same
    # RoleService.grant_permission API seed_roles.py uses -- not a management
    # command -- so it runs automatically on every signup/user-creation call
    # that lands a user on the default persona.
    #
    # Extensible: add a tuple here and it's granted immediately to every
    # existing AND future default-persona user -- no backfill needed, since
    # the grant lands on the shared role the persona bundles, and Casbin
    # evaluates permissions per-persona, not per-user.
    #
    # NOTE: these grants are tenant-wide at the Casbin layer (Casbin has no
    # per-object "own records only" concept -- see casbin_model.conf's
    # matcher). "manage" here is only the coarse, type-level gate checked by
    # RequiresPermission.has_permission ("can this persona reach this
    # endpoint AT ALL") -- it is NOT tenant-wide visibility.
    #
    # Object-level scoping -- which specific workspaces/workflows a caller
    # can actually see/act on -- is a SEPARATE pair of actions, resolved by
    # rm_auth_tenant.authorization.access_scope + EntityAccessGrant (not
    # Casbin, not an owner_id kwarg threaded through services -- see
    # rm_auth_tenant/authorization/DESIGN.md for the full rationale):
    #   - "owner_only": caller sees/manages entities THEY created
    #   - "shared":     caller ALSO sees/manages entities explicitly shared
    #                   with them (EntityAccessGrant rows with role
    #                   viewer/editor/owner, action-gated -- see
    #                   access_scope.ROLES_ALLOWING_ACTION)
    #   - "manage_all": bypasses object-level scoping entirely -- tenant-wide,
    #                   for real admin/enterprise personas. Deliberately NOT
    #                   granted here -- a community/self-serve user should
    #                   never see every other user's data by default.
    # Every action each view actually gates on must be listed -- "manage"
    # does NOT imply edit/view/publish/share (Casbin has no action
    # hierarchy; casbin_model.conf's matcher is an exact match). Missing one
    # here means a default-persona user gets 403 on that specific endpoint
    # even though they can already CRUD the workflow itself.
    "DEFAULT_PERSONA_PERMISSIONS": [
        ("workspace", "manage"),
        ("workspace", "owner_only"),
        ("workspace", "shared"),
        ("workflow", "manage"),
        ("workflow", "owner_only"),
        ("workflow", "shared"),
        ("workflow", "edit"),
        ("workflow", "view"),
        ("workflow", "publish"),
        ("workflow", "share"),
        # Project has no publish/share sub-endpoints of its own (unlike
        # workflow) -- object-level scoping only ever resolves via
        # owner_only/shared (see access_scope.resolve_allowed_roles and its
        # callers in rm_workflow's views.py: ProjectViewSet's own
        # RequiresPermission gate, plus _check_entity_access(...,"project",
        # ...,"edit") when a workflow references one). Same 3-tuple shape
        # as workspace, for the same reason.
        ("project", "manage"),
        ("project", "owner_only"),
        ("project", "shared"),
    ],
    # --- Signup email verification (community edition) ---
    # Feature-flagged and OFF by default -- local/dev signup stays
    # frictionless (new users are active/verified immediately, same as
    # today). Flip RM_AUTH_SIGNUP_EMAIL_VERIFICATION_ENABLED=true once this
    # is going to production, so new signups must click the emailed link
    # before they can log in (see SignupView / EmailVerificationService).
    "SIGNUP_EMAIL_VERIFICATION_ENABLED": os.environ.get(
        "RM_AUTH_SIGNUP_EMAIL_VERIFICATION_ENABLED", "false"
    ).lower()
    == "true",
    # How long a verification link stays valid (django.core.signing's
    # max_age -- see EmailVerificationService.verify). Default: 3 days.
    "EMAIL_VERIFICATION_TTL_SECONDS": int(
        os.environ.get("RM_AUTH_EMAIL_VERIFICATION_TTL", str(60 * 60 * 24 * 3))
    ),
    # `{token}` is substituted with the signed verification token. This
    # should point at wherever the *frontend* handles verification (which
    # then calls POST /api/rm_auth_tenant/verify-email with that token) --
    # not at this API directly.
    "EMAIL_VERIFICATION_URL": os.environ.get(
        "RM_AUTH_EMAIL_VERIFICATION_URL",
        "http://localhost:3000/verify-email?token={token}",
    ),
}
