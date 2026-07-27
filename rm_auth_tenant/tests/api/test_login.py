from rest_framework.test import APIClient

from rm_auth_tenant.tests.factories import UserFactory
from drf_base_app.logging import get_logger

logger = get_logger(__name__)


def test_login(api_client: APIClient, rm_user_factory: UserFactory, assign_default_persona):
    raw_password = "testpass123"
    user = rm_user_factory(
        tenant_id="test-tenant", username="login-user", password=raw_password
    )
    assign_default_persona(user)
    payload = {
        "username": user.username,
        "password": raw_password,
        "tenant": user.tenant_id,
    }
    response = api_client.post("/api/rm_auth/login", data=payload, format="json")
    logger.info(f"Login response: {response.data}")
    assert response.status_code == 200
