"""
manage.py set_default_persona --username rm_administrator --persona "Platform Admin"

Marks an ALREADY-assigned persona as a user's default -- the one /login uses
when the request omits `persona_id`, even if the user has more than one
eligible persona (see UserPersonaAssignment.is_default /
default-tenant-and-persona.md). The persona must already be assigned to the
user (via create_user.py's --persona, the API's persona_ids, or
RoleService.assign_persona) -- this command only changes which existing
assignment is flagged default, it does not assign a new one.

Typical use: fixing up a user who ended up with several personas and no
default set (e.g. from seed_roles --with-demo-persona, or any user created
before this feature existed).
"""
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser

from rm_auth_tenant.accounts.repositories import AccountRepository
from rm_auth_tenant.services.role_service import RoleService, RoleServiceError


class Command(BaseCommand):
    help = "Marks an already-assigned persona as a user's default persona for login."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--tenant",
            default=None,
            help="Tenant id the user belongs to. Omit to use the configured "
                 "default tenant -- see default-tenant-and-persona.md.",
        )
        parser.add_argument("--username", required=True)
        parser.add_argument(
            "--persona",
            required=True,
            metavar="PERSONA_NAME",
            help="Name of a persona already assigned to this user.",
        )

    def handle(self, *args, **options):
        tenant_id = options["tenant"] or settings.RM_AUTH.get("DEFAULT_TENANT_ID", "default")
        username = options["username"]
        persona_name = options["persona"]

        accounts = AccountRepository()
        user = accounts.get_user(tenant_id, username)
        if user is None:
            raise CommandError(f"No user {username!r} found for tenant {tenant_id!r}")

        role_service = RoleService()
        try:
            persona = role_service.get_persona_by_name(tenant_id, persona_name)
        except RoleServiceError as exc:
            raise CommandError(str(exc))

        try:
            role_service.set_default_persona(tenant_id, user.id, persona)
        except RoleServiceError as exc:
            raise CommandError(str(exc))

        self.stdout.write(self.style.SUCCESS(
            f"{username!r}'s default persona for tenant {tenant_id!r} is now "
            f"{persona.name!r} -- /login will use it whenever persona_id is omitted."
        ))
