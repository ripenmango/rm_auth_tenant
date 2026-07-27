from rm_auth_tenant.policy import engine
from rm_auth_tenant.policy.models import PolicyRule, RoleAssignment


class PolicyService:
    """
    Facade over the Casbin enforcer -- this is the ONLY thing the rest of the
    codebase (services/, authorization/) is allowed to call. Nothing outside
    policy/ should import casbin directly (design doc §3 layering rule).
    """

    def is_allowed(self, subject: str, tenant_id: str, resource: str, action: str) -> bool:
        enforcer = engine.get_enforcer(tenant_id)
        return bool(enforcer.enforce(subject, tenant_id, resource, action))

    def grant(self, tenant_id: str, role_or_persona: str, resource: str, action: str) -> None:
        """Adds a `p` (policy) line: role/persona may perform action on resource.
        `role_or_persona` must be a SLUG (stable across renames), not `.name` --
        see policy/models.py's PolicyRule docstring for why."""
        enforcer = engine.get_enforcer(tenant_id)
        enforcer.add_policy(role_or_persona, tenant_id, resource, action)
        engine.invalidate(tenant_id)

    def revoke(self, tenant_id: str, role_or_persona: str, resource: str, action: str) -> None:
        """`role_or_persona` must be the same SLUG used in the matching `grant()` call."""
        enforcer = engine.get_enforcer(tenant_id)
        enforcer.remove_policy(role_or_persona, tenant_id, resource, action)
        engine.invalidate(tenant_id)

    def assign_role_to_subject(
        self,
        tenant_id: str,
        subject: str,
        role_or_persona: str,
        subject_type: str | None = None,
        group_type: str | None = None,
    ) -> None:
        """Adds a `g` (grouping) line: subject is a member of this role/persona, in this
        tenant. `subject` may be a raw user id OR a persona slug (see
        policy/models.py's RoleAssignment docstring) -- Casbin doesn't distinguish.
        `role_or_persona` must be a SLUG, for the same reason as grant() above.

        `subject_type`/`group_type` (e.g. RoleAssignment.SUBJECT_TYPE_USER /
        GROUP_TYPE_PERSONA) are OPTIONAL debugging annotations, not passed to
        Casbin at all -- Casbin's own add_grouping_policy() call only accepts
        the 3 fields model.conf's `g` relation defines. They're written as a
        follow-up ORM update on the row the adapter just created/reused, so a
        human reading rm_auth_role_assignment can tell a user->persona edge
        from a persona->role edge without guessing. Omit them and the row is
        still fully functional for enforcement -- they're pure readability."""
        enforcer = engine.get_enforcer(tenant_id)
        enforcer.add_grouping_policy(str(subject), role_or_persona, tenant_id)
        engine.invalidate(tenant_id)
        if subject_type or group_type:
            updates = {}
            if subject_type:
                updates["subject_type"] = subject_type
            if group_type:
                updates["group_type"] = group_type
            RoleAssignment.objects.filter(
                tenant_id=tenant_id, subject=str(subject), group_slug=role_or_persona
            ).update(**updates)

    def revoke_role_from_subject(self, tenant_id: str, subject: str, role_or_persona: str) -> None:
        """`role_or_persona` must be the same SLUG used in the matching assign call."""
        enforcer = engine.get_enforcer(tenant_id)
        enforcer.remove_grouping_policy(str(subject), role_or_persona, tenant_id)
        engine.invalidate(tenant_id)

    def warm_enforcer(self, tenant_id: str) -> None:
        engine.warm(tenant_id)

    def policies_for_tenant(self, tenant_id: str) -> list[PolicyRule]:
        """Read-only introspection (`p` rows) -- e.g. for an admin UI listing effective rules."""
        return list(PolicyRule.objects.filter(tenant_id=tenant_id))

    def role_assignments_for_tenant(self, tenant_id: str) -> list[RoleAssignment]:
        """Read-only introspection (`g` rows) -- which users hold which roles/personas."""
        return list(RoleAssignment.objects.filter(tenant_id=tenant_id))
