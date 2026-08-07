"""
Unit tests for rm_auth_tenant.authorization.access_scope -- the object-level
scoping core (resolve_allowed_roles + EntityAccessService) that
TenantAndAccessScopedFilterBackend and RequiresPermission.has_object_permission
both build on (see authorization/DESIGN.md).

Deliberately doesn't go through rm_auth_client/security_context_factory
(conftest.py) for resolve_allowed_roles -- those fixtures default to
`allow_all=True`, which patches SecurityContext.can to always return True.
That's exactly the "manage_all" bypass path, so it would make every
resolve_allowed_roles case collapse to None and defeat the point of these
tests. A minimal stub context (just `.can()`) is enough here since
resolve_allowed_roles never touches anything else on the context.
"""
import pytest

from rm_auth_tenant.authorization.access_scope import (
    EntityAccessError,
    EntityAccessService,
    resolve_allowed_roles,
)
from rm_auth_tenant.authorization.entity_access_models import EntityAccessGrant

TENANT_ID = "test-tenant"


class _StubContext:
    """`.can(resource, action) -> bool` is the entire surface
    resolve_allowed_roles needs from a SecurityContext."""

    def __init__(self, granted: set[tuple[str, str]]):
        self._granted = granted

    def can(self, resource: str, action: str) -> bool:
        return (resource, action) in self._granted


# ---------------------------------------------------------------------------
# resolve_allowed_roles
# ---------------------------------------------------------------------------


def test_manage_all_bypasses_object_level_scoping():
    context = _StubContext({("workflow", "manage_all")})
    assert resolve_allowed_roles(context, "workflow", "manage") is None


def test_no_grants_means_no_access():
    context = _StubContext(set())
    assert resolve_allowed_roles(context, "workflow", "view") == set()


def test_owner_only_grants_only_the_owner_role_for_manage_action():
    context = _StubContext({("workflow", "owner_only")})
    # "manage" only admits the owner role (ROLES_ALLOWING_ACTION["manage"]);
    # owner_only intersected with that is just {owner}.
    assert resolve_allowed_roles(context, "workflow", "manage") == {EntityAccessGrant.ROLE_OWNER}


def test_owner_only_alone_does_not_grant_view_via_shared_roles():
    """owner_only only ever contributes the owner role, regardless of
    action -- it should never expand to viewer/editor even for a
    broad-admitting action like "view"."""
    context = _StubContext({("workflow", "owner_only")})
    assert resolve_allowed_roles(context, "workflow", "view") == {EntityAccessGrant.ROLE_OWNER}


def test_shared_grants_the_full_action_role_set():
    context = _StubContext({("workflow", "shared")})
    assert resolve_allowed_roles(context, "workflow", "view") == {
        EntityAccessGrant.ROLE_VIEWER,
        EntityAccessGrant.ROLE_EDITOR,
        EntityAccessGrant.ROLE_OWNER,
    }
    assert resolve_allowed_roles(context, "workflow", "edit") == {
        EntityAccessGrant.ROLE_EDITOR,
        EntityAccessGrant.ROLE_OWNER,
    }


def test_owner_only_and_shared_together_union_correctly():
    context = _StubContext({("workflow", "owner_only"), ("workflow", "shared")})
    # For "edit": owner_only contributes {owner} (intersected with
    # {editor, owner}), shared contributes {editor, owner} outright ->
    # union is {editor, owner}, same as shared alone would give for this
    # action, but exercised via both flags together.
    assert resolve_allowed_roles(context, "workflow", "edit") == {
        EntityAccessGrant.ROLE_EDITOR,
        EntityAccessGrant.ROLE_OWNER,
    }


def test_share_action_only_ever_admits_owner_regardless_of_shared_flag():
    """Sharing a workflow further is owner-only by design (see
    DESIGN.md, "Why sharing requires owner") -- even a caller with the
    broad `shared` flag should only get {owner} back for this action,
    since ROLES_ALLOWING_ACTION["share"] = {owner}."""
    context = _StubContext({("workflow", "shared")})
    assert resolve_allowed_roles(context, "workflow", "share") == {EntityAccessGrant.ROLE_OWNER}


# ---------------------------------------------------------------------------
# EntityAccessService
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_grant_owner_is_idempotent():
    service = EntityAccessService()
    first = service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)
    second = service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)

    assert first.pk == second.pk
    assert (
        EntityAccessGrant.objects.filter(
            tenant_id=TENANT_ID, entity_type="workflow", entity_id="wfl_1", user_id=1
        ).count()
        == 1
    )
    assert second.role == EntityAccessGrant.ROLE_OWNER


@pytest.mark.django_db
def test_share_creates_viewer_and_editor_grants():
    service = EntityAccessService()
    service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)

    viewer_grant = service.share(TENANT_ID, "workflow", "wfl_1", user_id=2, role="viewer")
    editor_grant = service.share(TENANT_ID, "workflow", "wfl_1", user_id=3, role="editor")

    assert viewer_grant.role == "viewer"
    assert editor_grant.role == "editor"


@pytest.mark.django_db
def test_share_rejects_granting_owner_role():
    service = EntityAccessService()

    with pytest.raises(EntityAccessError):
        service.share(TENANT_ID, "workflow", "wfl_1", user_id=2, role=EntityAccessGrant.ROLE_OWNER)


@pytest.mark.django_db
def test_revoke_removes_a_non_owner_grant():
    service = EntityAccessService()
    service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)
    service.share(TENANT_ID, "workflow", "wfl_1", user_id=2, role="viewer")

    service.revoke(TENANT_ID, "workflow", "wfl_1", user_id=2)

    assert not EntityAccessGrant.objects.filter(
        tenant_id=TENANT_ID, entity_type="workflow", entity_id="wfl_1", user_id=2
    ).exists()


@pytest.mark.django_db
def test_revoke_refuses_to_remove_the_owner():
    service = EntityAccessService()
    service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)

    with pytest.raises(EntityAccessError):
        service.revoke(TENANT_ID, "workflow", "wfl_1", user_id=1)

    assert EntityAccessGrant.objects.filter(
        tenant_id=TENANT_ID, entity_type="workflow", entity_id="wfl_1", user_id=1
    ).exists()


@pytest.mark.django_db
def test_revoke_on_a_grant_that_never_existed_is_a_silent_no_op():
    service = EntityAccessService()
    service.revoke(TENANT_ID, "workflow", "wfl_1", user_id=999)  # should not raise


@pytest.mark.django_db
def test_list_grants_scoped_to_the_specific_entity():
    service = EntityAccessService()
    service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)
    service.grant_owner(TENANT_ID, "workflow", "wfl_2", user_id=1)
    service.share(TENANT_ID, "workflow", "wfl_1", user_id=2, role="viewer")

    grants = service.list_grants(TENANT_ID, "workflow", "wfl_1")

    assert {(g.user_id, g.role) for g in grants} == {(1, "owner"), (2, "viewer")}


@pytest.mark.django_db
def test_has_access_respects_allowed_roles():
    service = EntityAccessService()
    service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)
    service.share(TENANT_ID, "workflow", "wfl_1", user_id=2, role="viewer")

    # user 2 is a viewer -- qualifies when "viewer" is in allowed_roles...
    assert service.has_access(
        TENANT_ID, "workflow", "wfl_1", user_id=2, allowed_roles={"viewer", "editor", "owner"}
    )
    # ...but not when only {editor, owner} qualify for the action in question.
    assert not service.has_access(
        TENANT_ID, "workflow", "wfl_1", user_id=2, allowed_roles={"editor", "owner"}
    )
    # A user with no grant at all never qualifies, regardless of allowed_roles.
    assert not service.has_access(
        TENANT_ID, "workflow", "wfl_1", user_id=999, allowed_roles={"viewer", "editor", "owner"}
    )


@pytest.mark.django_db
def test_has_access_with_empty_allowed_roles_is_always_false():
    service = EntityAccessService()
    service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)

    assert not service.has_access(TENANT_ID, "workflow", "wfl_1", user_id=1, allowed_roles=set())


@pytest.mark.django_db
def test_allowed_entity_ids_only_returns_entities_the_user_has_a_qualifying_role_on():
    service = EntityAccessService()
    service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)
    service.grant_owner(TENANT_ID, "workflow", "wfl_2", user_id=2)  # someone else's
    service.share(TENANT_ID, "workflow", "wfl_2", user_id=1, role="viewer")

    owner_only_ids = set(
        service.allowed_entity_ids(TENANT_ID, "workflow", user_id=1, allowed_roles={"owner"})
    )
    assert owner_only_ids == {"wfl_1"}

    owner_and_shared_ids = set(
        service.allowed_entity_ids(
            TENANT_ID, "workflow", user_id=1, allowed_roles={"owner", "viewer", "editor"}
        )
    )
    assert owner_and_shared_ids == {"wfl_1", "wfl_2"}


@pytest.mark.django_db
def test_purge_for_entity_only_removes_grants_for_that_entity():
    service = EntityAccessService()
    service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)
    service.grant_owner(TENANT_ID, "workflow", "wfl_2", user_id=1)

    service.purge_for_entity(TENANT_ID, "workflow", "wfl_1")

    assert not EntityAccessGrant.objects.filter(entity_id="wfl_1").exists()
    assert EntityAccessGrant.objects.filter(entity_id="wfl_2").exists()


@pytest.mark.django_db
def test_grants_are_isolated_per_tenant():
    service = EntityAccessService()
    service.grant_owner(TENANT_ID, "workflow", "wfl_1", user_id=1)
    service.grant_owner("other-tenant", "workflow", "wfl_1", user_id=1)

    assert set(
        service.allowed_entity_ids(TENANT_ID, "workflow", user_id=1, allowed_roles={"owner"})
    ) == {"wfl_1"}
    assert (
        EntityAccessGrant.objects.filter(entity_type="workflow", entity_id="wfl_1").count() == 2
    )
