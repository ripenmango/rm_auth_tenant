from rm_auth.conf import RMAuthSettings

from config.settings import BASE_DIR


class RMAuthTenantSettings(RMAuthSettings):
    """
    Settings for rm_auth_tenant, with defaults and validation.
    """

    namespace = "RM_AUTH_TENANT"
    defaults = {
        "JWT_ACCESS_TTL_SECONDS": 900,  # 15 minutes
        "JWT_REFRESH_TTL_SECONDS": 60 * 60 * 24 * 7,  # 7 days
        "CASBIN_MODEL_PATH": str(
            BASE_DIR / "rm_auth_tenant" / "policy" / "casbin_model.conf"
        ),
        "ENFORCER_CACHE_TTL_SECONDS": 300,  # 5 minutes
        "ENFORCER_CACHE_MAX_SIZE": 1000,  # max number of cached enforcer instances
        "ENFORCER_CACHE_CLEANUP_INTERVAL_SECONDS": 60,
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
        ],
        # --- Signup email verification (community edition) ---
        # Feature-flagged and OFF by default -- local/dev signup stays
        # frictionless (new users are active/verified immediately, same as
        # today). Flip RM_AUTH_SIGNUP_EMAIL_VERIFICATION_ENABLED=true once this
        # is going to production, so new signups must click the emailed link
        # before they can log in (see SignupView / EmailVerificationService).
        "SIGNUP_EMAIL_VERIFICATION_ENABLED": "false",
        # How long a verification link stays valid (django.core.signing's
        # max_age -- see EmailVerificationService.verify). Default: 3 days.
        "EMAIL_VERIFICATION_TTL_SECONDS": 60 * 60 * 24 * 3,
        # `{token}` is substituted with the signed verification token. This
        # should point at wherever the *frontend* handles verification (which
        # then calls POST /api/rm_auth_tenant/verify-email with that token) --
        # not at this API directly.
        "EMAIL_VERIFICATION_URL": "http://localhost:3000/verify-email?token={token}",
        # Default from email for verification emails
        "DEFAULT_FROM_EMAIL": "noreply@localhost",
    }

    @property
    def jwt_access_ttl_seconds(self):
        return self.config["JWT_ACCESS_TTL_SECONDS"]

    @property
    def jwt_refresh_ttl_seconds(self):
        return self.config["JWT_REFRESH_TTL_SECONDS"]

    @property
    def casbin_model_path(self):
        return self.config["CASBIN_MODEL_PATH"]

    @property
    def enforcer_cache_ttl_seconds(self):
        return self.config["ENFORCER_CACHE_TTL_SECONDS"]

    @property
    def enforcer_cache_max_size(self):
        return self.config["ENFORCER_CACHE_MAX_SIZE"]

    @property
    def enforcer_cache_cleanup_interval_seconds(self):
        return self.config["ENFORCER_CACHE_CLEANUP_INTERVAL_SECONDS"]

    @property
    def default_persona_permissions(self):
        return self.config["DEFAULT_PERSONA_PERMISSIONS"]

    @property
    def signup_email_verification_enabled(self):
        return self.config["SIGNUP_EMAIL_VERIFICATION_ENABLED"].lower() == "true"

    @property
    def email_verification_ttl_seconds(self):
        return self.config["EMAIL_VERIFICATION_TTL_SECONDS"]

    @property
    def email_verification_url(self):
        return self.config["EMAIL_VERIFICATION_URL"]

    @property
    def default_from_email(self):
        return self.config["DEFAULT_FROM_EMAIL"]


rm_auth_tenant_settings = RMAuthTenantSettings()
