"""
manage.py create_user --username jdoe --email jdoe@acme.com --password 'ChangeMe123!'
manage.py create_user --tenant acme --username jdoe --email jdoe@acme.com \\
    --password 'ChangeMe123!' --persona "Branch Manager"

Creates a User for a tenant and, optionally, assigns one or more existing
personas. There's no public self-registration endpoint in this API (see
api/views.py) -- this is the manual/scriptable way to create a tenant's
first real users, e.g. right after `create_role`/persona creation, before
any user exists to call the API themselves.

--tenant is optional -- omit it (non-enterprise / self-serve case) and the
configured default tenant is used, auto-created if needed (see
default-tenant-and-persona.md). --persona is also optional: if omitted, the
user is assigned that tenant's lazily-created "Default" persona (zero
permissions until an admin grants some) instead of being left with no
eligible persona at all -- this is what lets them log in without
specifying `persona_id`, same as the API's UserService.create_user.

Like create_role.py, this runs outside any HTTP request, so writes to
RMAuditModel-backed tables (e.g. the persona assignment) are attributed to
the "system" sentinel user unless --as-user is given.
"""
from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.core.validators import validate_email

from drf_base_app.audit.context import AuditContext

from rm_auth_tenant.accounts.repositories import AccountRepository
from rm_auth_tenant.services.role_service import RoleService, RoleServiceError
from rm_auth.tenants.models import Tenant


class Command(BaseCommand):
    help = "Creates a User for a tenant, optionally assigning one or more existing personas."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--tenant",
            default=None,
            help="Tenant id the user belongs to. Omit to use the configured "
                 "default tenant (see default-tenant-and-persona.md) -- it's "
                 "auto-created if it doesn't exist yet.",
        )
        parser.add_argument("--username", required=True)
        parser.add_argument("--email", required=True)
        parser.add_argument("--password", required=True)
        parser.add_argument(
            "--persona",
            action="append",
            default=[],
            metavar="PERSONA_NAME",
            help="Existing persona name to assign (must already exist for --tenant, "
                 "see create_role.py + RoleService.create_persona). Repeatable. "
                 "Omit entirely to auto-assign the tenant's \"Default\" persona "
                 "instead (auto-created if needed, zero permissions until an "
                 "admin grants some) -- see default-tenant-and-persona.md.",
        )
        parser.add_argument(
            "--default-persona",
            default=None,
            metavar="PERSONA_NAME",
            help="Which of the assigned personas (from --persona, or the "
                 "auto-assigned Default one) /login should use when the login "
                 "request omits persona_id -- see "
                 "UserPersonaAssignment.is_default / default-tenant-and-persona.md. "
                 "Must be one of the personas actually being assigned. If omitted "
                 "and only one persona is being assigned, that one becomes the "
                 "default automatically; if omitted with several --persona flags, "
                 "no default is set and /login will require an explicit persona_id "
                 "until one is set later (see set_default_persona.py).",
        )
        parser.add_argument(
            "--superuser",
            action="store_true",
            help="Also grant Django is_superuser/is_staff for /admin/ access -- "
                 "independent of personas, see the Django-admin-vs-platform_admin "
                 "distinction in auth-library-architecture.md. Use sparingly.",
        )
        parser.add_argument(
            "--as-user",
            default=None,
            metavar="USERNAME",
            help="Attribute the persona-assignment write to an existing user for "
                 "--tenant, instead of the 'system' sentinel user.",
        )

    def handle(self, *args, **options):
        tenant_id = options["tenant"] or settings.RM_AUTH.get("DEFAULT_TENANT_ID", "default")
        username = options["username"]
        email = options["email"]
        password = options["password"]
        persona_names = options["persona"]
        make_superuser = options["superuser"]
        as_username = options["as_user"]

        try:
            validate_email(email)
        except DjangoValidationError:
            raise CommandError(f"--email {email!r} is not a valid email address.")

        if not Tenant.objects.filter(id=tenant_id).exists():
            if tenant_id == settings.RM_AUTH.get("DEFAULT_TENANT_ID", "default"):
                # Auto-create the default tenant lazily -- normally provisioned
                # by the 0003_seed_default_tenant migration already, but this
                # covers a settings override that changed the id after migrate.
                Tenant.objects.get_or_create(
                    id=tenant_id, defaults={"name": tenant_id, "jwt_algorithm": "HS256"}
                )
            else:
                raise CommandError(
                    f"Tenant {tenant_id!r} doesn't exist yet. Create it first, e.g.:\n"
                    f'  Tenant.objects.create(id="{tenant_id}", name="{tenant_id}")'
                )

        accounts = AccountRepository()
        if accounts.get_user(tenant_id, username) is not None:
            raise CommandError(f"User {username!r} already exists for tenant {tenant_id!r}")

        actor_user_id = None
        if as_username:
            actor = accounts.get_user(tenant_id, as_username)
            if actor is None:
                raise CommandError(f"No user {as_username!r} found for tenant {tenant_id!r}")
            actor_user_id = actor.id

        role_service = RoleService()
        resolved_personas = []
        for persona_name in persona_names:
            try:
                resolved_personas.append(role_service.get_persona_by_name(tenant_id, persona_name))
            except RoleServiceError as exc:
                raise CommandError(str(exc))

        used_default_persona = False
        if not resolved_personas:
            # No explicit --persona given -- fall back to the tenant's Default
            # persona (auto-created if needed) rather than leaving the user
            # with zero eligible personas. See default-tenant-and-persona.md.
            resolved_personas = [role_service.get_or_create_default_persona(tenant_id)]
            used_default_persona = True

        default_persona_name = options["default_persona"]
        if default_persona_name:
            resolved_default = next(
                (p for p in resolved_personas if p.name == default_persona_name), None
            )
            if resolved_default is None:
                raise CommandError(
                    f"--default-persona {default_persona_name!r} must be one of the "
                    f"assigned personas: {[p.name for p in resolved_personas]}"
                )
        elif used_default_persona or len(resolved_personas) == 1:
            resolved_default = resolved_personas[0]
        else:
            resolved_default = None  # multiple personas, no default -- login requires persona_id

        # User creation itself isn't an RMAuditModel write (User has no
        # created_by/updated_by -- see accounts/models.py), so --as-user only
        # affects the persona-assignment rows below, not this call.
        user = accounts.create_user(tenant_id, username, password, email=email)
        if make_superuser:
            user.is_superuser = True
            user.is_staff = True
            user.save(update_fields=["is_superuser", "is_staff"])

        def _assign_personas():
            for persona in resolved_personas:
                role_service.assign_persona(
                    tenant_id, user.id, persona, is_default=(persona == resolved_default)
                )

        if actor_user_id is not None:
            with AuditContext.use(actor_user_id):
                _assign_personas()
        else:
            _assign_personas()

        summary = f"Created user {username!r} (id={user.id}) for tenant {tenant_id!r}"
        if make_superuser:
            summary += ", is_superuser=True"
        persona_label = "default persona" if used_default_persona else "personas"
        summary += f", {persona_label}: {', '.join(p.name for p in resolved_personas)}"
        if resolved_default is not None:
            summary += f" (default: {resolved_default.name!r})"
        else:
            summary += " (no default set -- /login will require persona_id)"
        self.stdout.write(self.style.SUCCESS(summary))
