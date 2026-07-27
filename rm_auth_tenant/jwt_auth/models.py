from drf_base_app import models
from drf_base_app.models.base import RMAuditModel
from django.db import models as dj_models


class RefreshTokenRecord(RMAuditModel):
    """
    Server-side record of an issued refresh token, keyed by its `jti`.
    Backs both the "single-use refresh token" behavior and explicit
    per-token revocation described in design doc §14.3 -- distinct from the
    coarser `User.ver` bump, which invalidates *every* token for a user.
    """

    jti = models.CharField(max_length=64, primary_key=True)
    tenant_id = models.CharField(max_length=64, db_index=True)
    user_id = models.BigIntegerField(db_index=True)
    persona_id = models.BigIntegerField()
    issued_ver = models.PositiveIntegerField()  # User.ver at issuance time
    revoked = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_refresh_token"  # unchanged -- db_table is independent of app_label
        indexes = [dj_models.Index(fields=["tenant_id", "user_id"])]
