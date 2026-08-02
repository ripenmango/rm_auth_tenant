from drf_base_app import models
from drf_base_app.models.base import (
    RMAbstractBaseUser,
    RMAuditModel,
    RMSluggedModel,
    BaseUserManager,
)
from django.conf import settings
from django.db import models as dj_models


class UserManager(BaseUserManager):
    """
    Tenant-aware manager. Django's default BaseUserManager assumes global
    username uniqueness -- here uniqueness is (tenant_id, username), see
    User.Meta.constraints, so callers must always pass tenant_id.
    """

    use_in_migrations = True

    def create_user(
        self,
        tenant_id: str | None,
        username: str,
        password: str | None = None,
        **extra_fields,
    ):
        if not tenant_id:
            # Non-enterprise / self-serve simplification -- see
            # default-tenant-and-persona.md. A caller that doesn't know or
            # care about tenants (or a future public signup flow) lands in
            # this single shared tenant rather than being forced to invent one.
            tenant_id = settings.RM_AUTH.get("DEFAULT_TENANT_ID", "default")
        if not username:
            raise ValueError("username is required")
        user = self.model(tenant_id=tenant_id, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(
        self,
        tenant_id: str | None = None,
        username: str = None,
        password: str | None = None,
        **extra_fields,
    ):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        # tenant_id=None flows through to create_user's own default-tenant
        # fallback above -- previously hardcoded "rm_default" here, which
        # didn't match any other default-tenant convention in the codebase.
        return self.create_user(tenant_id, username, password, **extra_fields)

    def get_by_natural_key(self, username):
        # NOTE: only safe for single-tenant lookups (e.g. Django admin/manage.py
        # shell usage). Tenant-scoped lookups in request-handling code MUST go
        # through accounts.repositories.AccountRepository.get_user instead.
        return self.get(username=username)


class User(RMAbstractBaseUser, RMSluggedModel):
    """
    Tenant-scoped user. Deliberately does NOT use Django's PermissionsMixin --
    authorization is handled entirely by rm_auth.policy (Casbin), not by
    Django's built-in groups/permissions framework (see design doc §4-6).
    """

    slug_source_field = "username"

    tenant_id = models.CharField(max_length=64, db_index=True)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(blank=True, default="")
    # Tenant-scoped, not globally unique -- see uniq_user_tenant_slug below.
    slug = models.SlugField(max_length=255, unique=False, blank=True)

    is_active = models.BooleanField(default=True)
    # Default True so every existing creation path (POST /users, seed/
    # management commands, admin) is unaffected -- only SignupView ever
    # passes False, and only when RM_AUTH["SIGNUP_EMAIL_VERIFICATION_ENABLED"]
    # is on (see EmailVerificationService / default-tenant-and-persona.md).
    # NOTE: while a signup is pending verification, SignupView also sets
    # is_active=False (see EmailVerificationService.verify) -- reusing the
    # existing is_active gate is what actually blocks login pre-verification
    # (AccountRepository.get_user already filters on it), rather than adding
    # a second login-time check. The tradeoff: list_users/get_user also
    # filter on is_active, so a pending-verification signup won't show up to
    # tenant admins via GET /users until it's verified, same as a
    # deactivated user wouldn't.
    is_email_verified = models.BooleanField(default=True)
    is_tenant_admin = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # JWT invalidation version (§7 of design doc). Bumping this invalidates
    # every previously issued token for the user -- used on password change,
    # forced logout, and persona switch (§5/§7 decision).
    ver = models.PositiveIntegerField(default=1)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS: list[str] = []

    objects = UserManager()

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_user"  # unchanged -- db_table is independent of app_label
        constraints = [
            dj_models.UniqueConstraint(
                fields=["tenant_id", "username"], name="uniq_user_tenant_username"
            ),
            dj_models.UniqueConstraint(
                fields=["tenant_id", "slug"], name="uniq_user_tenant_slug"
            ),
        ]
        indexes = [
            dj_models.Index(fields=["tenant_id", "email"]),
        ]

    def __str__(self) -> str:
        return f"{self.tenant_id}:{self.username}"

    # Django admin calls these directly (e.g. ModelAdmin.has_module_permission
    # -> request.user.has_module_perms(...)); AbstractBaseUser alone doesn't
    # provide them (only PermissionsMixin does). We deliberately don't use
    # PermissionsMixin (see class docstring -- Casbin owns authorization, not
    # Django's groups/permissions tables), so these are minimal stand-ins
    # gated on is_superuser, sufficient for admin access. Not wired to Casbin
    # -- add that if/when non-superuser staff need scoped admin access.
    def has_perm(self, perm, obj=None):
        return self.is_active and self.is_superuser

    def has_perms(self, perm_list, obj=None):
        return self.is_active and self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_active and self.is_superuser

    def bump_version(self) -> int:
        """
        Atomically increments `ver`, invalidating every outstanding JWT for
        this user (§7). Returns the new version.
        """
        User.objects.filter(pk=self.pk).update(ver=dj_models.F("ver") + 1)
        self.refresh_from_db(fields=["ver"])
        return self.ver


class PasswordHistory(RMAuditModel):
    """Retained so password-reuse policy can be enforced by AuthenticationService."""

    user = models.ForeignKey(
        User, on_delete=dj_models.CASCADE, related_name="password_history"
    )
    password_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_password_history"  # unchanged -- db_table is independent of app_label
        ordering = ["-created_at"]
