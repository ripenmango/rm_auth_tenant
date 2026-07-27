"""
manage.py create_role --tenant acme --name "Branch Manager" \\
    --description "Can manage branch workflows" \\
    --grant workflow:edit --grant workflow:view

Creates a Role for a tenant and, optionally, grants it one or more
resource:action permissions in the same call. This is the manual/scriptable
equivalent of `POST /api/auth/roles` (see api/views.py's RoleViewSet) plus
RoleService.grant_permission -- useful for bootstrapping a new tenant's
first roles before anyone holds the `role:manage` permission needed to call
the API (see role-creation-and-tenant-model.md's "bootstrap gap" section).

This runs outside any HTTP request, so RMAuditModel.save() attributes the
new rows to the "system" sentinel user by default (see
audit-context-design-discussion.md). Pass --as-user to attribute them to a
specific real admin instead.

--tenant is optional -- omit it to create the role in the configured
default tenant (see default-tenant-and-persona.md), auto-created if needed.
"""
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser

from drf_base_app.audit.context import AuditContext

from rm_auth_tenant.accounts.repositories import AccountRepository
from rm_auth_tenant.services.role_service import RoleService, RoleServiceError
from rm_auth.tenants.models import Tenant


class Command(BaseCommand):
    help = "Creates a Role for a tenant, optionally granting it permissions immediately."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--tenant",
            default=None,
            help="Tenant id the role belongs to. Omit to use the configured "
                 "default tenant -- see default-tenant-and-persona.md.",
        )
        parser.add_argument("--name", required=True, help="Role name (unique per tenant)")
        parser.add_argument("--description", default="", help="Optional description")
        parser.add_argument(
            "--grant",
            action="append",
            default=[],
            metavar="RESOURCE:ACTION",
            help="Grant a permission immediately, e.g. --grant workflow:edit. Repeatable.",
        )
        parser.add_argument(
            "--as-user",
            default=None,
            metavar="USERNAME",
            help="Attribute this write to an existing user for --tenant, instead of "
                 "the 'system' sentinel user.",
        )

    def handle(self, *args, **options):
        tenant_id = options["tenant"] or settings.RM_AUTH.get("DEFAULT_TENANT_ID", "default")
        name = options["name"]
        description = options["description"]
        grants = options["grant"]
        as_username = options["as_user"]

        if not Tenant.objects.filter(id=tenant_id).exists():
            if tenant_id == settings.RM_AUTH.get("DEFAULT_TENANT_ID", "default"):
                Tenant.objects.get_or_create(
                    id=tenant_id, defaults={"name": tenant_id, "jwt_algorithm": "HS256"}
                )
            else:
                raise CommandError(
                    f"Tenant {tenant_id!r} doesn't exist yet. Create it first, e.g.:\n"
                    f'  Tenant.objects.create(id="{tenant_id}", name="{tenant_id}")'
                )

        actor_user_id = None
        if as_username:
            user = AccountRepository().get_user(tenant_id, as_username)
            if user is None:
                raise CommandError(f"No user {as_username!r} found for tenant {tenant_id!r}")
            actor_user_id = user.id

        parsed_grants: list[tuple[str, str]] = []
        for grant in grants:
            if ":" not in grant:
                raise CommandError(f"--grant {grant!r} must be in RESOURCE:ACTION form")
            resource, action = grant.split(":", 1)
            parsed_grants.append((resource, action))

        service = RoleService()

        def _create():
            try:
                role = service.create_role(tenant_id, name, description)
            except Exception as exc:  # surfaces IntegrityError (duplicate name) etc. plainly
                raise CommandError(f"Could not create role {name!r}: {exc}") from exc
            for resource, action in parsed_grants:
                service.grant_permission(tenant_id, role, resource=resource, action=action)
            return role

        if actor_user_id is not None:
            with AuditContext.use(actor_user_id):
                role = _create()
        else:
            role = _create()

        grant_summary = (
            f", granted: {', '.join(f'{r}:{a}' for r, a in parsed_grants)}"
            if parsed_grants
            else " (no permissions granted -- role has no effect until you grant some)"
        )
        self.stdout.write(self.style.SUCCESS(
            f"Created role {role.name!r} (id={role.id}) for tenant {tenant_id!r}{grant_summary}"
        ))
