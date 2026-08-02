from django.conf import settings
from django.core import signing
from django.core.mail import send_mail

from drf_base_app.logging.logger import get_logger

from rm_auth_tenant.accounts.repositories import AccountRepository
from rm_auth_tenant.audit.service import AuditService

logger = get_logger(__name__)

# Namespaces the signed token so it can never be confused with/replayed as
# any other django.core.signing token this project (or drf_base_app) issues
# elsewhere.
_SIGNING_SALT = "rm_auth_tenant.email_verification"


class EmailVerificationError(Exception):
    pass


class EmailVerificationService:
    """
    Feature-flagged (RM_AUTH["SIGNUP_EMAIL_VERIFICATION_ENABLED"], default
    False -- see settings.py/.env.example) verify-before-login flow for
    community-edition signup (SignupView).

    Tokens are stateless -- django.core.signing.dumps/loads over
    {tenant_id, user_id}, signed with SECRET_KEY and namespaced under
    _SIGNING_SALT. There's no separate token table to create/expire/clean
    up: signing.loads' own max_age check (EMAIL_VERIFICATION_TTL_SECONDS)
    is the expiry, and a bad/tampered token just fails to verify.

    Only entry point api/views.py should call for anything
    verification-related, same layering rule as the other services in this
    package -- it goes through AccountRepository, never queries User
    directly.
    """

    def __init__(self):
        self.accounts = AccountRepository()
        self.audit = AuditService()

    @staticmethod
    def is_enabled() -> bool:
        return bool(settings.RM_AUTH.get("SIGNUP_EMAIL_VERIFICATION_ENABLED", False))

    def generate_token(self, tenant_id: str, user_id: int) -> str:
        return signing.dumps(
            {"tenant_id": tenant_id, "user_id": user_id}, salt=_SIGNING_SALT
        )

    def send_verification_email(self, tenant_id: str, user) -> None:
        """
        Sends the verification link to `user.email`. Uses Django's
        send_mail -- EMAIL_BACKEND defaults to the console backend (see
        settings.py), so in dev this just prints the email/link to stdout
        instead of actually sending anything.
        """
        token = self.generate_token(tenant_id, user.id)
        url_template = settings.RM_AUTH.get(
            "EMAIL_VERIFICATION_URL",
            "http://localhost:3000/verify-email?token={token}",
        )
        verify_url = url_template.format(token=token)
        ttl_hours = settings.RM_AUTH.get(
            "EMAIL_VERIFICATION_TTL_SECONDS", 60 * 60 * 24 * 3
        ) // 3600

        logger.info(
            "email_verification.sent", tenant_id=tenant_id, user_id=user.id
        )
        send_mail(
            subject="Verify your email address",
            message=(
                "Welcome! Please verify your email address by visiting the "
                f"link below:\n\n{verify_url}\n\n"
                f"This link expires in {ttl_hours} hours. If you didn't "
                "sign up for this account, you can safely ignore this email."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        self.audit.record_event(
            tenant_id,
            "email_verification_sent",
            user_id=user.id,
            metadata={"email": user.email},
        )

    def verify(self, token: str):
        """
        Decodes/validates `token` and activates + marks verified the user
        it names. Idempotent -- verifying an already-verified user is a
        no-op, not an error (a user might click the link twice, or click it
        after a stale page reload).
        """
        ttl = settings.RM_AUTH.get("EMAIL_VERIFICATION_TTL_SECONDS", 60 * 60 * 24 * 3)
        try:
            payload = signing.loads(token, salt=_SIGNING_SALT, max_age=ttl)
        except signing.SignatureExpired as exc:
            raise EmailVerificationError("Verification link has expired") from exc
        except signing.BadSignature as exc:
            raise EmailVerificationError("Verification link is invalid") from exc

        tenant_id = payload.get("tenant_id")
        user_id = payload.get("user_id")

        # Deliberately bypasses AccountRepository.get_user_by_id's
        # is_active=True filter -- flipping is_active from False to True is
        # exactly what this call needs to do, so it can't pre-filter on it.
        user = self.accounts.get_user_by_id_any_state(tenant_id, user_id)
        if user is None:
            raise EmailVerificationError("User not found")

        if user.is_email_verified:
            return user

        self.accounts.mark_email_verified(user)
        self.audit.record_event(tenant_id, "email_verified", user_id=user.id)
        return user
