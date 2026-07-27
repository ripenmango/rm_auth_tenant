from drf_base_app import models
from drf_base_app.models.base import RMAuditModel
from django.db import models as dj_models


class PolicyRule(RMAuditModel):
    """
    One Casbin `p` (policy) line: <subject> may <action> <resource>, in <tenant>.

    Named columns instead of the generic v0..v5 Casbin adapter convention --
    we're still in development, so a future model.conf change (e.g. adding
    an `effect` column for deny-override, see
    user-level-permission-overrides-design.md §7.1) is a normal migration,
    not something we need to pre-provision opaque columns for. See
    casbin-flow-architecture.md §2 for the full rationale on this trade-off.

    `subject` is a role or persona **slug** (stable once created -- see
    RMSluggedModel -- unlike `.name`, which can change later without this
    row updating). Never a raw user id -- users are linked in via
    RoleAssignment's `g` rows, not here.
    """

    tenant_id = models.CharField(max_length=64, db_index=True)  # Casbin "dom"
    subject = models.CharField(max_length=255)  # Casbin "sub" -- role/persona SLUG
    resource = models.CharField(max_length=255)  # Casbin "obj"
    action = models.CharField(max_length=255)  # Casbin "act"

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_policy_rule"  # unchanged -- db_table is independent of app_label
        indexes = [
            dj_models.Index(fields=["tenant_id", "subject"]),
        ]
        constraints = [
            dj_models.UniqueConstraint(
                fields=["tenant_id", "subject", "resource", "action"],
                name="uniq_policy_rule",
            )
        ]

    def as_casbin_line(self) -> list[str]:
        """Renders this row in the field order model.conf's `p` expects: sub, dom, obj, act."""
        return [self.subject, self.tenant_id, self.resource, self.action]

    def __str__(self) -> str:
        return f"{self.tenant_id}: p({self.subject}, {self.resource}, {self.action})"


class RoleAssignment(RMAuditModel):
    """
    One Casbin `g` (grouping) line: <subject> is a member of <group_slug>, in <tenant>.

    Field names are deliberately relation-agnostic (`subject`/`group_slug`,
    not `user_id`/`role_or_persona`) because this one table stores TWO
    distinct kinds of Casbin `g` edge -- both are just "X is a member of Y",
    which is exactly what Casbin's `g(subject, group, domain)` relation
    means, regardless of what X and Y conceptually are:

      1. user -> persona   e.g. subject="42",              group_slug="branch-manager"
         (written by RoleService.assign_persona)
      2. persona -> role   e.g. subject="branch-manager",   group_slug="workflow-editor"
         (written by RoleService.create_persona, so a persona's bundled
         Roles actually confer real, enforced permissions -- a Persona.roles
         M2M with no matching row here grants nothing. See
         casbin-flow-architecture.md §2/§3 for the bug this fixed.)

    `subject_type`/`group_type` are DEBUGGING/READABILITY AIDS ONLY --
    Casbin's `enforce()` never reads them, doesn't know they exist, and
    would behave identically if they were dropped entirely. They exist so a
    human looking at this table (or a log line) doesn't have to guess
    whether a given `subject` string is a raw user id or a persona slug.
    Populated by `PolicyService.assign_role_to_subject` as a follow-up
    annotation AFTER the Casbin-facing write -- Casbin's own
    `add_grouping_policy(subject, group, domain)` call accepts exactly the
    3 fields `model.conf`'s `g` relation defines, so type info can't be
    threaded through that call itself without corrupting the policy line;
    see PolicyService for how the annotation step works and its one known
    gap (the `save_policy` bulk-import path leaves these blank).

    `subject` therefore holds either a raw user id (case 1) or a persona
    slug (case 2) depending on which edge the row represents -- `subject_type`
    tags which case a given row is. If a third kind of edge is ever added
    (e.g. persona -> persona composition), it fits this same shape with a
    new choice value, no further renaming needed.

    `group_slug` is a **slug**, for the same stability reason as
    PolicyRule.subject above -- see that docstring.

    This is the Casbin-facing mirror of RoleService.assign_persona /
    RoleService.create_persona / UserPersonaAssignment -- kept as its own
    table (rather than folded into PolicyRule) because a `g` row has a
    different shape than a `p` row (subject + group + domain, vs. subject +
    domain + resource + action) and naming both shapes onto one generic
    table is exactly the trade-off we moved away from.
    """

    SUBJECT_TYPE_USER = "user"
    SUBJECT_TYPE_PERSONA = "persona"
    SUBJECT_TYPE_CHOICES = [
        (SUBJECT_TYPE_USER, "User"),
        (SUBJECT_TYPE_PERSONA, "Persona"),
    ]

    GROUP_TYPE_PERSONA = "persona"
    GROUP_TYPE_ROLE = "role"
    GROUP_TYPE_CHOICES = [
        (GROUP_TYPE_PERSONA, "Persona"),
        (GROUP_TYPE_ROLE, "Role"),
    ]

    tenant_id = models.CharField(max_length=64, db_index=True)  # Casbin "dom"
    subject = models.CharField(max_length=64)  # Casbin g's 1st field -- user id OR persona slug
    group_slug = models.CharField(max_length=255)  # Casbin g's 2nd field -- persona or role slug

    # Debugging aids only -- not read by Casbin, not part of enforcement.
    # blank=True/default="" (not choices-required) because the rare
    # save_policy bulk-import path can't populate these -- see docstring.
    subject_type = models.CharField(
        max_length=16, choices=SUBJECT_TYPE_CHOICES, blank=True, default=""
    )
    group_type = models.CharField(
        max_length=16, choices=GROUP_TYPE_CHOICES, blank=True, default=""
    )

    class Meta:
        app_label = "rm_auth_tenant"
        db_table = "rm_auth_role_assignment"  # unchanged -- db_table is independent of app_label
        indexes = [
            dj_models.Index(fields=["tenant_id", "subject"]),
            dj_models.Index(fields=["tenant_id", "subject_type"]),  # e.g. "all user->persona rows for this tenant"
        ]
        constraints = [
            dj_models.UniqueConstraint(
                fields=["tenant_id", "subject", "group_slug"],
                name="uniq_role_assignment",
            )
        ]

    def as_casbin_line(self) -> list[str]:
        """Renders this row in the field order model.conf's `g` expects: subject, group, domain.
        subject_type/group_type are intentionally excluded -- Casbin's model.conf only
        defines 3 fields for `g`; these two are DB-only annotations (see class docstring)."""
        return [self.subject, self.group_slug, self.tenant_id]

    def __str__(self) -> str:
        subject_label = f"{self.subject}[{self.subject_type or '?'}]"
        group_label = f"{self.group_slug}[{self.group_type or '?'}]"
        return f"{self.tenant_id}: g({subject_label}, {group_label})"
