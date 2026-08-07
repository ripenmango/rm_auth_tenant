"""
manage.py grant_permission --role platform_admin --resource workflow --action manage
manage.py grant_permission --tenant acme --role branch_manager --resource workflow --action edit
manage.py grant_permission --role platform_admin --resource workflow --action manage --revoke

Grants (or, with --revoke, revokes) a resource:action permission on an
EXISTING Role -- the manual/scriptable equivalent of the "grant a
permission to a role" endpoint that doesn't exist yet in api/views.py (see
RoleViewSet's docstring: "a separate endpoint/flow, not implemented here").

Thin wrapper around RoleService.grant_permission/revoke_permission -- the
exact same service method an HTTP endpoint would call if/when one is added
(see api/views.py's RoleViewSet for where that would live), so this command
doubles as the sanctioned path today and needs no rework later if it's ever
wrapped in an API view instead.

--tenant is optional -- omit it to use the configured default tenant (see
default-tenant-and-persona.md). --role is looked up by NAME, not id, since
that's what's convenient from a shell.

Like create_role.py/create_user.py, this runs outside any HTTP request, so
RMAuditModel-backed writes (the permission Grant row) are attributed to the
"system" sentinel user unless --as-user is given.
"""
from django.core.management.base import BaseCommand, CommandError, CommandParser

from drf_base_app.audit.context import AuditContext
from drf_base_app.tenancy.settings import get_default_tenant_id

from rm_auth_tenant.accounts.repositories import AccountRepository
from rm_auth_tenant.services.role_service import RoleService, RoleServiceError


class Command(BaseCommand):
    help = "Grants or revokes a resource:action permission on an existing Role."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--tenant",
            default=None,
            help="Tenant id the role belongs to. Omit to use the configured "
                 "default tenant -- see default-tenant-and-persona.md.",
        )
        parser.add_argument(
            "--role", required=True, metavar="ROLE_NAME", help="Existing role name."
        )
        parser.add_argument("--resource", required=True)
        parser.add_argument("--action", required=True)
        parser.add_argument(
            "--revoke",
            action="store_true",
            help="Revoke this permission instead of granting it.",
        )
        parser.add_argument(
            "--as-user",
            default=None,
            metavar="USERNAME",
            help="Attribute this write to an existing user for --tenant, instead of "
                 "the 'system' sentinel user.",
        )

    def handle(self, *args, **options):
        tenant_id = options["tenant"] or get_default_tenant_id()
        role_name = options["role"]
        resource = options["resource"]
        action = options["action"]
        revoke = options["revoke"]
        as_username = options["as_user"]

        service = RoleService()
        try:
            role = service.get_role_by_name(tenant_id, role_name)
        except RoleServiceError as exc:
            raise CommandError(str(exc))

        actor_user_id = None
        if as_username:
            user = AccountRepository().get_user(tenant_id, as_username)
            if user is None:
                raise CommandError(f"No user {as_username!r} found for tenant {tenant_id!r}")
            actor_user_id = user.id

        def _apply():
            if revoke:
                service.revoke_permission(tenant_id, role, resource=resource, action=action)
            else:
                service.grant_permission(tenant_id, role, resource=resource, action=action)

        if actor_user_id is not None:
            with AuditContext.use(actor_user_id):
                _apply()
        else:
            _apply()

        verb = "Revoked" if revoke else "Granted"
        preposition = "from" if revoke else "to"
        self.stdout.write(self.style.SUCCESS(
            f"{verb} {resource}:{action} {preposition} role {role.name!r} "
            f"(tenant {tenant_id!r})"
        ))
