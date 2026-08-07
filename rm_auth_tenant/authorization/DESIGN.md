# Object-Level Authorization: Casbin + EntityAccessGrant

Status: implemented (`rm_auth_tenant/authorization/`).
Consumers: `rm_workflow_store` (Workspace, Workflow) today; any future
tenant-scoped, shareable entity can opt in the same way.

## The problem this solves

Casbin (`rm_auth_tenant/policy/`, `RequiresPermission`) answers exactly one
question well: **"can this persona perform `action` on resource-type
`resource`, in this tenant, at all?"** — a coarse, type-level, cacheable
check. `casbin_model.conf`'s matcher is:

```
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
```

`obj` here is always a literal resource-type string ("workspace",
"workflow") — never a specific row. That's a deliberate, good design for
what Casbin is for: a persona either can or can't reach an endpoint.

It cannot answer a second, different question: **"of all the workflows in
this tenant, which specific ones can *this* user see or touch?"** That
needed a different mechanism once two requirements landed together:

1. Self-registered community users share one tenant (`rm_community`) and
   one persona (`tenant-administrator`) — see `default-tenant-and-persona.md`.
   Granting that persona `(workflow, manage)` in Casbin, on its own, would
   mean *every* community user can CRUD *every other* community user's
   workflows, since Casbin has no concept of "this row belongs to that
   user."
2. Users need to be able to **share** a specific workflow with a specific
   colleague — a per-object grant that has nowhere to live in a type-level
   system, and that a naive `created_by`-only ownership filter can't
   express at all (see "What we tried first," below).

## What we tried first, and why it was replaced

The first pass added an `owner_id` keyword argument threaded through every
repository/service method (`WorkspaceRepository.list(tenant_id,
owner_id=...)`, etc.), derived in `api/views.py` and passed down manually
at every call site.

This was rejected for two compounding reasons:

- **It's an opt-in filter, not a structural guarantee.** Every new
  endpoint, every new service method, has to *remember* to thread
  `owner_id` through, or it silently returns/mutates every tenant's data.
  That's the same class of bug as forgetting a `WHERE` clause — it works
  today and leaks the day someone adds a call site without it.
- **Ownership is binary.** `created_by == user` can express "mine" but has
  nowhere to put "shared with me as an editor" or "shared with me as a
  read-only viewer." Sharing would have needed a second, bolted-on
  mechanism anyway.

`EntityAccessGrant` + a centrally-registered `FilterBackend` fixes both:
scoping is declared once per ViewSet (`entity_type = "workflow"`) and
applies automatically to every list/retrieve/update/destroy without a new
call site ever having to remember it — the same "can't be forgotten"
guarantee `RMSoftDeleteModel`'s default manager already gives for
`deleted_at` filtering, applied one level down to per-object ownership.

## Why a generic table, not `WorkflowCollaborator`

`EntityAccessGrant` is `(tenant_id, entity_type, entity_id, user_id,
role)`, not a `Workflow`-specific join table. The alternative — a typed
`ForeignKey` to `Workflow` — buys real referential integrity, at the cost
of needing a near-identical bespoke table (and bespoke scoping code) for
every future shareable entity (a future `WorkflowRunner`, `Workspace`
sharing, anything else). One generic table means every future entity gets
the same `resolve_allowed_roles()` / `EntityAccessService` /
`TenantAndAccessScopedFilterBackend` code path for free — set one class
attribute (`entity_type = "..."`), done.

The cost is real and was a deliberate trade, not an oversight:

- **No FK-enforced referential integrity.** `entity_id` is a plain
  `CharField` holding the target's `public_id` — this table can't know at
  class-definition time which model(s) it will ever point at, which is the
  whole point of it being generic.
- **Mitigation 1 — grants can't be created against nothing.** The share
  endpoint always fetches the target through its owning service first (to
  confirm the caller holds `owner` on it), so a grant is never created
  against a nonexistent object.
- **Mitigation 2 — grants can still be orphaned by a hard-delete.**
  `Workspace`/`Workflow`'s ordinary `.delete()` is a soft-delete (no row
  removed, no signal fired) — grants on a soft-deleted-but-restorable
  entity deliberately stay intact, so an undelete also restores who it was
  shared with. Only `.hard_delete()` issues a real `DELETE`, and
  `authorization/signals.py`'s `connect_hard_delete_cleanup()` is a
  `post_delete` receiver, opt-in per model (wired once in each owning
  app's `AppConfig.ready()` — see `rm_workflow/apps.py`), that purges
  matching grants when that actually happens.

## The action vocabulary

Four Casbin actions, all granted per-tenant/per-persona the same way any
other permission is (`RoleService.grant_permission` — see
`config/settings.py`'s `DEFAULT_PERSONA_PERMISSIONS` for the default
persona's grants):

| Action        | Checked by                              | Meaning |
|---------------|------------------------------------------|---------|
| `manage`      | `RequiresPermission.has_permission`       | Coarse gate: can this persona reach this endpoint AT ALL. Type-level only — **not** tenant-wide visibility. |
| `owner_only`  | `resolve_allowed_roles`                   | Caller sees/manages entities they hold `owner` on. |
| `shared`      | `resolve_allowed_roles`                   | Caller ALSO sees/manages entities explicitly shared with them (any `EntityAccessGrant` role, narrowed by the specific action — see below). |
| `manage_all`  | `resolve_allowed_roles` / `has_object_permission` | Bypasses object-level scoping entirely — tenant-wide. For a real admin/enterprise persona. Deliberately **not** granted to the default community persona. |

Separately, each `EntityAccessGrant.role` (`viewer` / `editor` / `owner`)
is mapped to which fine-grained *actions* it satisfies, in
`access_scope.ROLES_ALLOWING_ACTION`:

```python
ROLES_ALLOWING_ACTION = {
    "view":    {viewer, editor, owner},
    "edit":    {editor, owner},
    "manage":  {owner},
    "publish": {owner},
    "share":   {owner},
}
```

So "an editor can use a workflow but can't hand out access to it" and "a
viewer can read but not touch stages" both fall directly out of this table
— no special-casing per endpoint.

**Both layers must agree.** `RequiresPermission.__init__(resource, action)`
is invoked per-ViewSet/View with the SAME action string
`ROLES_ALLOWING_ACTION` keys off — e.g. `StageGraphView` gates on
`("workflow", "edit")` at both the coarse (Casbin) and fine (grant-role)
layers. This is why `DEFAULT_PERSONA_PERMISSIONS` has to separately list
`edit`/`view`/`publish`/`share` alongside `manage` — Casbin has no action
hierarchy, so `manage` grants nothing for an endpoint gated on `edit`.

## Why a `FilterBackend`, not middleware or a custom Manager

Three options were considered for "centralize this so it can't be
forgotten":

1. **Django `MIDDLEWARE`.** Rejected — same reason `AuditContext` isn't
   middleware (see `drf_base_app/audit/mixins.py`'s docstring): JWT
   authentication resolves `request.security_context` inside DRF's
   `APIView.initial()`, which runs *after* all Django middleware has
   already executed. Middleware here would only ever see it unset.
2. **`django-filter`'s `FilterSet`.** Rejected — that library is built for
   client-supplied, opt-in query params (`?status=active`); "the client
   didn't ask to be restricted" is a normal, expected outcome for it. Wrong
   ownership model for a security boundary, where the *absence* of a
   client-supplied constraint must never mean "see everything."
3. **A custom `Manager`/`QuerySet`** (the `RMSoftDeleteManager` pattern).
   Would work for `list()`, but doesn't have access to `request` (which
   user, which persona) without a contextvar plumbed through — an extra
   moving part `TenantAndAccessScopedFilterBackend` doesn't need, since
   DRF hands `filter_queryset(self, request, queryset, view)` its `request`
   directly.

What was actually built: `TenantAndAccessScopedFilterBackend`, registered
once on `RMScopedModelViewSet.filter_backends`. DRF's own `ListModelMixin`
already calls `self.filter_queryset(self.get_queryset())` — nothing to
wire up for `list()`. `RMScopedModelViewSet.get_object()` explicitly routes
through the same `self.filter_queryset(...)` before the `public_id` lookup
(DRF's own documented pattern for exactly this purpose), so
retrieve/update/destroy inherit the identical scoping with zero extra
code. A ViewSet opts in with one class attribute:

```python
class WorkflowViewSet(RMScopedModelViewSet):
    entity_type = "workflow"
    permission_classes = [RequiresPermission("workflow", "manage")]
```

ViewSets with no per-object ownership concept (`Role`, `Persona`,
`Resource`, ...) simply keep using plain `RMModelViewSet` — `entity_type`
stays unset, the backend no-ops.

### The one gap a `FilterBackend` doesn't cover: referenced objects

`filter_queryset`/`get_object` only cover the ViewSet's *own* object.
Creating a `Workflow` inside a `Workspace` the caller doesn't own is a
different shape of check — the workspace is *referenced*, not *fetched via
get_object*. `api/views.py`'s `_check_entity_access(request, entity_type,
entity_id, action)` covers this: same `resolve_allowed_roles` +
`EntityAccessService.has_access` pair, called explicitly wherever an
endpoint reads a `public_id` out of its request body/URL to act on a
*different* entity type than the one it's a ViewSet for (see
`WorkflowViewSet.create()` checking `("workspace", "edit")` before creating
the workflow).

## Why sharing requires `owner`, not just `edit`

`ROLES_ALLOWING_ACTION["share"] = {owner}`. An editor can use a workflow
productively without being able to hand out access to it themselves —
otherwise access could fan out uncontrollably from anyone with write
access, not just the person who created (or was made owner of) the
workflow. Transferring ownership itself is deliberately a separate,
unimplemented-so-far operation from `EntityAccessService.share()` (which
explicitly rejects `role="owner"`) — it needs its own "never leave an
entity ownerless" invariant that ordinary sharing doesn't.

## Defense in depth this doesn't (yet) include

Everything above is enforced in Django application code — correct, and
structurally hard to bypass by accident (see `RMScopedModelViewSet`), but
still application code. The natural next layer, not yet implemented, is
**Postgres Row-Level Security**: a session-level GUC
(`SET LOCAL app.current_user_id = ...`) set once per request (same
lifecycle as `SchemaActivationMiddleware`'s existing `set_tenant()` call),
paired with an RLS policy on `EntityAccessGrant`-backed tables that makes
cross-user leakage impossible even from a raw SQL query or a future ORM
bug — not just unlikely. Worth doing before this pattern is relied on for
data with materially higher sensitivity than workflow definitions.

## What's still out of scope

- **Workspace sharing.** Only `Workflow` has share/revoke HTTP endpoints
  today (`WorkflowCollaboratorsView`, `WorkflowCollaboratorDetailView`).
  `Workspace` already grants `owner` to its creator via the same
  `EntityAccessGrant` mechanism and already has `entity_type = "workspace"`
  wired into `RMScopedModelViewSet`/`RequiresPermission` — the identical
  pattern applies one level up whenever workspace-level sharing is
  actually needed; nothing here would need to change to add it, just new
  endpoints calling the same `EntityAccessService`.
- **Ownership transfer.** `EntityAccessService.share()` explicitly refuses
  to grant `role="owner"` — see "Why sharing requires owner" above.
