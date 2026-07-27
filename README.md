# rm-auth-tenant

Tenant-scoped identity & policy-driven authorization for Django — split out
of `rm-auth` so tenant-specific data (`User`, `Role`, `Persona`, `Permission`,
`PolicyRule`, `RoleAssignment`, refresh tokens, login/security audit events)
can live in per-tenant Postgres schemas (Tier B isolation), while `rm-auth`
itself stays the shared, platform-wide app (`Tenant`, `Domain`, `Action`).

See `rm_workflow_store/docs/tier-b-implementation-plan.md`, section 0/0.1,
for the full rationale and the exact classification behind this split.

## Relationship to `rm-auth`

This app **depends on** `rm-auth` (installed as a normal wheel dependency,
same pattern `rm-auth` itself uses for `drf-base`) for:
- `Tenant`/`Domain` lookups (`rm_auth.tenants.repositories.TenantRepository`)
- `TenantResolutionMiddleware` and `SecurityContextMiddleware`
  (`rm_auth.middleware`) — both stay shared/cross-cutting
- `Action` (the global action vocabulary) — `Permission` here has one
  deliberate cross-app foreign key into it (see
  `rm_auth_tenant/permissions/models.py`'s docstring)

`rm-auth` must never import from this app — enforced by an `import-linter`
`forbidden` contract in `rm-auth`'s own `pyproject.toml`.

## Use it as a library

Add both apps to a consuming project's `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...,
    "rm_auth",
    "rm_auth_tenant",
]
```

In a full schema-per-tenant deployment, `rm_auth` is a `SHARED_APPS` entry
and `rm_auth_tenant` is a `TENANT_APPS` entry (see the Tier B plan doc,
section 2, for the exact `django-tenants` settings).

## Local development

This repo's own `config/settings.py`/`manage.py` are a standalone test
harness only (matching `rm_auth_project`'s own harness pattern) — a
consuming platform project would not use this file directly.

```
pip install -e ".[dev]"
python manage.py migrate
python manage.py test
```
