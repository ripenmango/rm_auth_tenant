"""
Per-tenant Casbin Enforcer cache (§6 of design doc: in-memory per-tenant
enforcer, TTL + pub/sub invalidation).

Enforcers hold policy state in memory for fast `enforce()` calls -- rebuilding
one means re-reading every PolicyRule row for that tenant from Postgres via
TenantScopedPolicyAdapter, so we don't want to do that on every request.

Two invalidation paths, matching the design doc:
  - TTL: entries expire after ENFORCER_CACHE_TTL_SECONDS and are rebuilt lazily.
  - Explicit invalidation: call `invalidate(tenant_id)` after any policy write
    (RoleService.assign_role, policy rule changes, persona updates). In a
    multi-process deployment this function is the natural place to also
    publish an invalidation event (e.g. over the same Redis pub/sub channel
    platform_core.tenancy.registry already uses for tenant-registry refresh)
    so *other* processes drop their cached enforcer too -- wire that publish
    call in here once the pub/sub transport is chosen (see design doc §13).
"""

import threading
import time

import casbin
from rm_auth_tenant.policy.adapters import TenantScopedPolicyAdapter
from rm_auth_tenant.conf import rm_auth_tenant_settings

_lock = threading.Lock()
_cache: dict[
    str, tuple[casbin.Enforcer, float]
] = {}  # tenant_id -> (enforcer, expires_at)


def _ttl_seconds() -> int:
    return rm_auth_tenant_settings.enforcer_cache_ttl_seconds


def _model_path() -> str:
    return rm_auth_tenant_settings.casbin_model_path


def _build_enforcer(tenant_id: str) -> casbin.Enforcer:
    adapter = TenantScopedPolicyAdapter(tenant_id)
    enforcer = casbin.Enforcer(_model_path(), adapter)
    enforcer.load_policy()
    return enforcer


def get_enforcer(tenant_id: str) -> casbin.Enforcer:
    now = time.monotonic()
    with _lock:
        cached = _cache.get(tenant_id)
        if cached and cached[1] > now:
            return cached[0]
    enforcer = _build_enforcer(tenant_id)
    with _lock:
        _cache[tenant_id] = (enforcer, now + _ttl_seconds())
    return enforcer


def invalidate(tenant_id: str) -> None:
    """Drop the cached enforcer for a tenant so the next request rebuilds it."""
    with _lock:
        _cache.pop(tenant_id, None)
    # TODO(§13): publish an invalidation event here once the pub/sub transport
    # for cross-process cache invalidation is chosen, e.g.:
    #   redis_client.publish(f"rm_auth:policy:invalidate:{tenant_id}", "1")


def warm(tenant_id: str) -> None:
    """Pre-build and cache the enforcer -- used right after login (§14.1)."""
    get_enforcer(tenant_id)
