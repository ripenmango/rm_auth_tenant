from drf_base_app import models
from drf_base_app.models.base import RMAbstractBaseUser, RMAuditModel
from django.db import models as dj_models


class LoginAttempt(RMAuditModel):
    tenant_id = models.CharField(max_length=64, db_index=True)
    username = models.CharField(max_length=150)
    success = models.BooleanField()
    persona_id = models.BigIntegerField(null=True, blank=True)
    jti = models.CharField(max_length=64, null=True, blank=True)
    ip_address = dj_models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_login_attempt"  # unchanged -- db_table is independent of app_label
        indexes = [dj_models.Index(fields=["tenant_id", "username", "created_at"])]


class SecurityEvent(RMAuditModel):
    """
    Durable, append-only audit trail for security-sensitive events (create/
    update/delete/permission-change), kept separate from operational logs
    per platform doc §5.1 -- operational logs go to Loki/ELK with a retention
    policy; these rows are for compliance and are meant to be queryable for
    years.
    """

    EVENT_CHOICES = [
        ("login_success", "login_success"),
        ("login_failure", "login_failure"),
        ("logout", "logout"),
        ("token_refreshed", "token_refreshed"),
        ("password_changed", "password_changed"),
        ("persona_switched", "persona_switched"),
        ("role_assigned", "role_assigned"),
        ("role_revoked", "role_revoked"),
        ("permission_granted", "permission_granted"),
        ("permission_revoked", "permission_revoked"),
        ("user_signed_up", "user_signed_up"),
        ("email_verification_sent", "email_verification_sent"),
        ("email_verified", "email_verified"),
    ]

    tenant_id = models.CharField(max_length=64, db_index=True)
    user_id = models.BigIntegerField(null=True, blank=True, db_index=True)
    event = models.CharField(max_length=32, choices=EVENT_CHOICES)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_security_event"  # unchanged -- db_table is independent of app_label
        indexes = [dj_models.Index(fields=["tenant_id", "event", "created_at"])]
