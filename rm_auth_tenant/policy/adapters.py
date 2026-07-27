"""
Custom Casbin storage adapter backed by named Django models
(rm_auth.policy.models.PolicyRule for `p` lines, RoleAssignment for `g`
lines) instead of Casbin's default file/CSV adapter -- so policy rows live
in the tenant-aware Postgres control plane (§6 of the design doc) and can be
routed consistently with the rest of the platform's Tier A/B/C access
patterns.

Two models instead of one generic v0..v5 table: `p` and `g` lines have
genuinely different shapes (subject/resource/action vs. subject/group/
domain), so each gets its own named-column table -- see policy/models.py
docstrings and casbin-flow-architecture.md §2 for the rationale, including
why RoleAssignment's fields are named relation-agnostically
(`subject`/`group_slug`, not `user_id`/`role_or_persona`).

One adapter instance is scoped to a single tenant_id -- see policy/engine.py
for how enforcers (and therefore adapters) are cached per tenant.
"""
from casbin.persist import Adapter
from casbin.persist.adapter import load_policy_line

from rm_auth_tenant.policy.models import PolicyRule, RoleAssignment


class TenantScopedPolicyAdapter(Adapter):
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def load_policy(self, model):
        for row in PolicyRule.objects.filter(tenant_id=self.tenant_id):
            load_policy_line("p, " + ", ".join(row.as_casbin_line()), model)
        for row in RoleAssignment.objects.filter(tenant_id=self.tenant_id):
            load_policy_line("g, " + ", ".join(row.as_casbin_line()), model)

    def save_policy(self, model) -> bool:
        # Bulk save: used rarely (e.g. bootstrapping/import); incremental
        # writes normally go through add_policy/remove_policy below.
        PolicyRule.objects.filter(tenant_id=self.tenant_id).delete()
        RoleAssignment.objects.filter(tenant_id=self.tenant_id).delete()

        if "p" in model.model:
            p_rows = [
                self._policy_row_from_rule(rule)
                for ast in model.model["p"].values()
                for rule in ast.policy
            ]
            PolicyRule.objects.bulk_create(p_rows)

        if "g" in model.model:
            g_rows = [
                self._assignment_row_from_rule(rule)
                for ast in model.model["g"].values()
                for rule in ast.policy
            ]
            RoleAssignment.objects.bulk_create(g_rows)

        return True

    def add_policy(self, sec, ptype, rule) -> None:
        if ptype == "g":
            row = self._assignment_row_from_rule(rule)
            RoleAssignment.objects.get_or_create(
                tenant_id=row.tenant_id,
                subject=row.subject,
                group_slug=row.group_slug,
            )
        else:
            row = self._policy_row_from_rule(rule)
            PolicyRule.objects.get_or_create(
                tenant_id=row.tenant_id,
                subject=row.subject,
                resource=row.resource,
                action=row.action,
            )

    def remove_policy(self, sec, ptype, rule) -> bool:
        if ptype == "g":
            row = self._assignment_row_from_rule(rule)
            deleted, _ = RoleAssignment.objects.filter(
                tenant_id=row.tenant_id,
                subject=row.subject,
                group_slug=row.group_slug,
            ).delete()
        else:
            row = self._policy_row_from_rule(rule)
            deleted, _ = PolicyRule.objects.filter(
                tenant_id=row.tenant_id,
                subject=row.subject,
                resource=row.resource,
                action=row.action,
            ).delete()
        return deleted > 0

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values) -> bool:
        if ptype == "g":
            fields = ["subject", "group_slug", "tenant_id"]  # g = subject, group, domain
            qs = RoleAssignment.objects.filter(tenant_id=self.tenant_id)
        else:
            fields = ["subject", "tenant_id", "resource", "action"]  # p = sub, dom, obj, act
            qs = PolicyRule.objects.filter(tenant_id=self.tenant_id)

        for offset, value in enumerate(field_values):
            if value == "":
                continue
            pos = field_index + offset
            if pos < len(fields):
                qs = qs.filter(**{fields[pos]: value})

        deleted, _ = qs.delete()
        return deleted > 0

    def _policy_row_from_rule(self, rule: list[str]) -> PolicyRule:
        # model.conf: p = sub, dom, obj, act
        subject, domain, resource, action = (list(rule) + ["", "", "", ""])[:4]
        return PolicyRule(
            tenant_id=domain or self.tenant_id,
            subject=subject,
            resource=resource,
            action=action,
        )

    def _assignment_row_from_rule(self, rule: list[str]) -> RoleAssignment:
        # model.conf: g = _, _, _  (subject, group, domain)
        subject, group_slug, domain = (list(rule) + ["", "", ""])[:3]
        return RoleAssignment(
            tenant_id=domain or self.tenant_id,
            subject=subject,
            group_slug=group_slug,
        )
