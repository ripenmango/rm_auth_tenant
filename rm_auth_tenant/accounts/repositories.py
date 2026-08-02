from django.contrib.auth.hashers import check_password
from django.db import transaction

from rm_auth_tenant.accounts.models import PasswordHistory, User

# How many previous password hashes to keep/check for reuse prevention.
PASSWORD_HISTORY_DEPTH = 5


class AccountRepository:
    """
    The only place in rm_auth allowed to issue queries against User/PasswordHistory.
    Services call this; nothing in api/ or policy/ should import User directly.
    """

    def get_user(self, tenant_id: str, username: str) -> User | None:
        return User.objects.filter(tenant_id=tenant_id, username=username, is_active=True).first()

    def get_user_by_id(self, tenant_id: str, user_id: int) -> User | None:
        return User.objects.filter(tenant_id=tenant_id, id=user_id, is_active=True).first()

    def list_users(self, tenant_id: str):
        return User.objects.filter(tenant_id=tenant_id, is_active=True).order_by("username")

    def create_user(
        self,
        tenant_id: str | None,
        username: str,
        password: str,
        email: str = "",
        is_active: bool = True,
        is_email_verified: bool = True,
    ) -> User:
        """tenant_id=None falls back to the configured default tenant -- see
        UserManager.create_user / default-tenant-and-persona.md.

        is_active/is_email_verified default True (unchanged behavior for
        every existing caller, e.g. POST /users). SignupView is the only
        caller that ever passes both False -- when email verification is
        enabled, a new signup starts inactive/unverified until it verifies
        (see EmailVerificationService)."""
        return User.objects.create_user(
            tenant_id=tenant_id,
            username=username,
            password=password,
            email=email,
            is_active=is_active,
            is_email_verified=is_email_verified,
        )

    def get_user_by_id_any_state(self, tenant_id: str, user_id: int) -> User | None:
        """
        Same as get_user_by_id, but WITHOUT the is_active=True filter --
        needed for email verification, where the whole point of the lookup
        is to find a user who is currently inactive pending verification.
        Not for use anywhere a deactivated user shouldn't be resolvable
        (e.g. login, admin CRUD) -- those must keep using get_user/
        get_user_by_id.
        """
        return User.objects.filter(tenant_id=tenant_id, id=user_id).first()

    def mark_email_verified(self, user: User) -> User:
        user.is_email_verified = True
        user.is_active = True
        user.save(update_fields=["is_email_verified", "is_active"])
        return user

    def update_user(self, user: User, **fields) -> User:
        for field, value in fields.items():
            setattr(user, field, value)
        user.save(update_fields=list(fields))
        return user

    def deactivate_user(self, user: User) -> None:
        user.is_active = False
        user.save(update_fields=["is_active"])

    def verify_password(self, user: User, raw_password: str) -> bool:
        return check_password(raw_password, user.password)

    @transaction.atomic
    def set_password(self, user: User, raw_password: str) -> None:
        user.set_password(raw_password)
        user.save(update_fields=["password"])
        PasswordHistory.objects.create(user=user, password_hash=user.password)
        # Trim history beyond the retention depth.
        stale_ids = list(
            PasswordHistory.objects.filter(user=user)
            .order_by("-created_at")
            .values_list("id", flat=True)[PASSWORD_HISTORY_DEPTH:]
        )
        if stale_ids:
            PasswordHistory.objects.filter(id__in=stale_ids).delete()

    def was_previously_used(self, user: User, raw_password: str) -> bool:
        recent_hashes = PasswordHistory.objects.filter(user=user).order_by("-created_at")[
            :PASSWORD_HISTORY_DEPTH
        ].values_list("password_hash", flat=True)
        return any(check_password(raw_password, h) for h in recent_hashes)

    def bump_version(self, user: User) -> int:
        return user.bump_version()
