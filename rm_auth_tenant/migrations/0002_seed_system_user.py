"""
Provisions the "system" sentinel user -- what RMAuditModel.save() falls back
to as created_by/updated_by when there's no request-scoped AuditContext
actor (management commands, Celery tasks, pre-auth writes like a failed
login attempt). See drf_base_app.models.base._resolve_system_user_id() and
audit-context-design-discussion.md.

Split out of the old rm_auth/migrations/0002_seed_system_user.py (deleted --
see the "Tier B Implementation Plan" doc's correction note) as part of the
Tier B app split: User now lives here, in rm_auth_tenant, not rm_auth, so
this half of that old migration moved with it. The other half (seeding the
default Tenant) is now fully independent -- see
rm_auth/migrations/0002_seed_default_tenant.py -- since Tenant no longer
requires a User to exist first (it dropped RMAuditModel's created_by/
updated_by entirely, see that doc's section 0.2).
"""

from django.contrib.auth.hashers import make_password
from django.db import migrations
from rm_auth_tenant.conf import rm_auth_tenant_settings

SYSTEM_TENANT_ID = "__system__"  # reserved pseudo-tenant for the system user itself


def seed_system_user(apps, schema_editor):
    User = apps.get_model("rm_auth_tenant", "User")

    system_username = rm_auth_tenant_settings.audit_system_username
    if User.objects.filter(username=system_username).exists():
        return

    # tenant_id="__system__": User.tenant_id is a plain CharField (no FK to
    # Tenant), so this doesn't require a matching Tenant row to exist.
    # is_active=False + unusable password: can never log in through the
    # normal flow (AccountRepository.get_user filters is_active=True) --
    # exists purely as an audit-trail actor, not a real account.
    User.objects.create(
        tenant_id=SYSTEM_TENANT_ID,
        username=system_username,
        slug=system_username,
        email="",
        password=make_password(None),
        is_active=False,
        is_superuser=False,
    )


def unseed_system_user(apps, schema_editor):
    User = apps.get_model("rm_auth_tenant", "User")
    system_username = rm_auth_tenant_settings.audit_system_username
    User.objects.filter(username=system_username, tenant_id=SYSTEM_TENANT_ID).delete()


class Migration(migrations.Migration):
    # Assumes the regenerated rm_auth_tenant migration history names its
    # first migration "0001_initial" (Django's default naming) -- adjust
    # this dependency if yours came out differently.
    dependencies = [("rm_auth_tenant", "0001_initial")]

    operations = [
        migrations.RunPython(seed_system_user, unseed_system_user),
    ]
