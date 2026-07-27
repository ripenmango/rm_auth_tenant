"""
Example tests for UserViewSet -- demonstrates the intended split of
responsibility: drf_base_testkit supplies the generic pieces (api_client,
BaseFactory, response asserts); rm_auth's own conftest.py supplies the
tenant-aware user factory and security-context authentication (see
conftest.py's module docstring for why that part can't live in the shared
testkit).

Note on response shape: RMJSONRenderer wraps the wire response as
{"success": ..., "data": ..., "meta": ...}, but that wrapping happens in
the renderer's render() step (bytes only) -- `response.data` on the test
client's response object is the original, pre-envelope value the view
returned (a list for list/, a dict for retrieve/create/etc). So assertions
below use `response.data` directly rather than `response.data["data"]`.
"""
import logging


def test_list_users_returns_only_current_tenant(rm_auth_client, rm_user_factory, tenant_id):
    client, _caller, _context = rm_auth_client
    rm_user_factory(tenant_id=tenant_id, username="same-tenant-user")
    rm_user_factory(tenant_id="other-tenant", username="other-tenant-user")

    response = client.get("/api/rm_auth/users")

    assert response.status_code == 200
    usernames = {row["username"] for row in response.data}
    assert "same-tenant-user" in usernames
    assert "other-tenant-user" not in usernames


def test_create_user(rm_auth_client):
    client, _caller, _context = rm_auth_client
    payload = {
        "username": "new-user",
        "email": "new-user@example.com",
        "password": "s3cur3pass",
    }

    response = client.post("/api/rm_auth/users", data=payload, format="json")

    assert response.status_code == 201
    assert response.data["username"] == "new-user"
    assert response.data["is_active"] is True


def test_deactivate_user(rm_auth_client, rm_user_factory, tenant_id):
    client, _caller, _context = rm_auth_client
    target = rm_user_factory(tenant_id=tenant_id, username="to-deactivate")

    response = client.delete(f"/api/rm_auth/users/{target.id}")

    assert response.status_code == 200
    assert response.data == {"deactivated": True}

    target.refresh_from_db()
    assert target.is_active is False


def test_cannot_see_other_tenants_user(rm_auth_client, rm_user_factory):
    client, _caller, _context = rm_auth_client
    other_tenant_user = rm_user_factory(tenant_id="other-tenant", username="not-yours")

    response = client.get(f"/api/rm_auth/users/{other_tenant_user.id}")

    assert response.status_code == 404


def test_create_user_logs_with_request_id_and_tenant_id(rm_auth_client, tenant_id, caplog):
    """
    Proves RequestContextMiddleware's contextvar binding actually reaches
    UserService's log call -- not just that a log line was emitted, but
    that it carries the same request_id as the request's own
    request.started/request.finished lines, and the caller's tenant_id.

    Uses pytest's `caplog` (attaches a handler to the real stdlib root
    logger our `logging.config.dictConfig` writes to), NOT
    structlog.testing.capture_logs() -- capture_logs() works by swapping
    structlog's global processor config, but `cache_logger_on_first_use=True`
    (set in drf_base_app.logging.config.setup) means already-cached logger
    instances -- like UserService's module-level `logger`, created at
    import time -- are unaffected by that swap (this is a documented
    structlog gotcha, not a bug here). caplog sidesteps it entirely by
    reading real LogRecords off the root logger instead.

    Because our stdlib integration passes the whole event_dict as the
    LogRecord's `msg` (via `ProcessorFormatter.wrap_for_formatter`), each
    matching record's `.msg` is the actual dict -- no JSON/text parsing
    needed.
    """
    caplog.set_level(logging.INFO)
    client, _caller, _context = rm_auth_client
    payload = {"username": "logged-user", "email": "logged@example.com", "password": "s3cur3pass"}

    response = client.post("/api/rm_auth/users", data=payload, format="json")

    assert response.status_code == 201

    events = {
        record.msg["event"]: record.msg
        for record in caplog.records
        if isinstance(record.msg, dict) and "event" in record.msg
    }
    assert "user.created" in events, f"Expected a 'user.created' log line, got: {events.keys()}"

    created_event = events["user.created"]
    assert created_event["tenant_id"] == tenant_id
    assert created_event["username"] == "logged-user"

    # Same request_id as the request lifecycle logs -> proves the binding,
    # not just that logging works at all.
    assert "request_id" in created_event
    assert created_event["request_id"] == events["request.finished"]["request_id"]

