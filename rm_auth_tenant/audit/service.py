from rm_auth_tenant.audit.models import LoginAttempt, SecurityEvent
from drf_base_app.logging import get_logger

# In the full platform this is structlog, configured centrally by
# platform_core.audit (see workflow-platform-architecture.md §5.1), which
# binds tenant_id/request_id/user_id via contextvars so every log line is
# tagged automatically. Standalone, we fall back to stdlib logging.
logger = get_logger(__name__)


class AuditService:
    def record_login_attempt(
        self,
        tenant_id: str,
        username: str,
        success: bool,
        persona_id: int | None = None,
        jti: str | None = None,
        ip_address: str | None = None,
    ) -> None:
        LoginAttempt.objects.create(
            tenant_id=tenant_id,
            username=username,
            success=success,
            persona_id=persona_id,
            jti=jti,
            ip_address=ip_address,
        )
        event = "login_success" if success else "login_failure"
        self.record_event(
            tenant_id, event, user_id=None, metadata={"username": username, "jti": jti}
        )

    def record_event(
        self,
        tenant_id: str,
        event: str,
        user_id: int | None = None,
        metadata: dict | None = None,
    ) -> None:
        metadata = metadata or {}
        SecurityEvent.objects.create(
            tenant_id=tenant_id, user_id=user_id, event=event, metadata=metadata
        )
        logger.info(
            "rm_auth.security_event",
            extra={"tenant_id": tenant_id, "event": event, **metadata},
        )
