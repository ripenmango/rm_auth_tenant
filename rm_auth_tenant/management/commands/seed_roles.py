from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.core.validators import validate_email
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction

from drf_base_app.tenancy.settings import get_default_tenant_id
from rm_auth_tenant.accounts.repositories import AccountRepository
from rm_auth_tenant.services.role_service import RoleService
from rm_auth.tenants.models import Domain, Tenant
from rm_auth_tenant.conf import rm_auth_tenant_settings


class Command(BaseCommand):
    help = (
        "Seeds a tenant with a bootstrap admin user + role/persona data, so "
        "the API can be exercised immediately after `migrate`.\n\n"
        "The admin user is given a `platform_admin` persona (role:manage, "
        "persona:manage, user:manage, execution:create, execution:view, "
        "execution:resume -- see RoleViewSet/PersonaViewSet/UserViewSet and "
        "rm_engine_app's ExecutionListCreateView/ExecutionDetailView/"
        "NodeExecutionResumeView in their respective api/views.py) so it can "
        "administer roles/personas/users AND drive/resume workflow executions "
        "through the API without needing Django's is_superuser. This is "
        "DELIBERATELY separate from Django admin-site access (see "
        "auth-library-architecture.md -- `is_superuser` and Casbin-backed API "
        "permissions are two independent systems; this command only sets up "
        "the latter). Create a Django superuser separately, with "
        "`manage.py createsuperuser`, if you also need /admin/ access.\n\n"
        "Safe to run more than once against an already-seeded tenant -- role/"
        "persona lookups fall back to get-or-create rather than an "
        "unconditional create (see RoleService.get_or_create_role/"
        "get_or_create_persona/ensure_role_in_persona), and grant_permission "
        "is already idempotent on its own. Re-running is how a newly added "
        "permission (e.g. this command's own execution:resume, added "
        "alongside Sprint 7's resume endpoint) reaches an existing tenant's "
        "admin role/persona -- for granting ONE new permission to a role that "
        "already exists, `manage.py grant_permission` is the more surgical "
        "tool and doesn't touch personas/users at all; use this command when "
        "you want the full bootstrap set applied/topped-up in one call.\n\n"
        "By default the admin user gets exactly ONE persona (`Platform Admin`), so "
        "`/login` auto-selects it and never requires `persona_id` in the request "
        "(see authorization-request-flow.md §2 -- login auto-selects when there's "
        "exactly one eligible persona). Pass --with-demo-persona to also create a "
        "`workflow_editor` role + `Branch Manager` persona and assign BOTH to the "
        "admin user, if you specifically want to exercise the multi-persona "
        "selection flow instead -- `Platform Admin` is still marked as the "
        "user's DEFAULT persona either way (see UserPersonaAssignment.is_default / "
        "default-tenant-and-persona.md), so `/login` continues to work without "
        "`persona_id` even with --with-demo-persona; pass persona_id explicitly "
        "or use SwitchPersonaView to act as `Branch Manager` instead."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--tenant",
            default=None,
            help="Tenant id to seed. Omit to use the configured default tenant "
            "(settings.RM_AUTH['DEFAULT_TENANT_ID'], normally 'rm_community' -- "
            "see default-tenant-and-persona.md) rather than inventing a "
            "separate one; only pass this explicitly for a real, distinct "
            "(e.g. enterprise) tenant.",
        )
        parser.add_argument(
            "--admin-username",
            default="rm_admin",
            help="Username for the seeded admin user (default: rm_admin -- "
            "avoid 'admin', it's a common brute-force target and easy to "
            "confuse with Django's own superuser convention)",
        )
        parser.add_argument(
            "--admin-email",
            default="rm_admin@example.com",
            help="Email for the seeded admin user. Required -- this is a real "
            "account a person will register/reset a password against, not "
            "just internal demo data.",
        )
        parser.add_argument(
            "--admin-password",
            default="ChangeMe123!",
            help="Password for the seeded admin user (default: ChangeMe123! -- change it)",
        )
        parser.add_argument(
            "--with-demo-persona",
            action="store_true",
            help="Also create a `workflow_editor` role + `Branch Manager` persona and "
            "assign it to the admin user alongside `Platform Admin`, to exercise "
            "the multi-persona login/selection flow. Off by default so a freshly "
            "seeded admin has exactly one persona and can log in without "
            "`persona_id` -- see default-tenant-and-persona.md.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        tenant_id = options["tenant"] or rm_auth_tenant_settings.default_tenant_id
        admin_username = options["admin_username"]
        admin_email = options["admin_email"]
        admin_password = options["admin_password"]
        with_demo_persona = options["with_demo_persona"]

        if not admin_email:
            raise CommandError(
                "--admin-email is required (this seeds a real admin account, "
                "not throwaway demo data)."
            )
        try:
            validate_email(admin_email)
        except DjangoValidationError:
            raise CommandError(
                f"--admin-email {admin_email!r} is not a valid email address."
            )

        # schema_name="public" is the default, shared-schema home for every
        # tenant that hasn't been explicitly promoted to a dedicated schema --
        # see "Tier B Implementation Plan" doc, sections 1 and 7.1. Ordinary
        # tenant creation stays exactly this cheap; promotion to a dedicated
        # schema is a separate, explicit, later step
        # (promote_tenant_to_dedicated_schema), never implicit here.
        tenant, _ = Tenant.objects.get_or_create(
            id=tenant_id,
            defaults={
                "name": tenant_id,
                "jwt_algorithm": "HS256",
                "schema_name": "public",
            },
        )
        # django-tenants requires at least one Domain row per tenant even
        # though this platform doesn't resolve tenants by hostname (see the
        # Domain model's own docstring) -- this is a placeholder, not a real,
        # DNS-resolving domain.
        Domain.objects.get_or_create(
            tenant=tenant,
            domain=f"{tenant_id}.rm.internal",
            defaults={"is_primary": True},
        )

        role_service = RoleService()

        # -- Bootstrap admin: role/persona administration via the API itself,
        # plus driving/resuming workflow executions (Sprint 7) --
        # get_or_create_role/get_or_create_persona/ensure_role_in_persona
        # (rather than create_role/create_persona directly) is what makes this
        # command safe to re-run against a tenant it already seeded -- see
        # this command's own docstring.
        admin_role = role_service.get_or_create_role(
            tenant_id, "platform_admin", "Can administer roles and personas"
        )
        for resource, action in [
            ("role", "manage"),
            ("persona", "manage"),
            ("user", "manage"),
            # Sprint 7: lets the seeded admin exercise rm_engine_app's
            # Execution API (start/view/resume) out of the box, the same way
            # it already can administer roles/personas/users. grant_permission
            # is idempotent on its own (Permission.objects.get_or_create +
            # Casbin add_policy, a no-op on an existing policy tuple), so
            # these are safe to re-grant every time this command runs.
            ("execution", "create"),
            ("execution", "view"),
            ("execution", "resume"),
        ]:
            role_service.grant_permission(
                tenant_id, admin_role, resource=resource, action=action
            )
        admin_persona = role_service.get_or_create_persona(tenant_id, "Platform Admin")
        role_service.ensure_role_in_persona(tenant_id, admin_persona, admin_role)

        editor_persona = None
        if with_demo_persona:
            # -- Optional demo data: exercises a second persona + the login
            # persona-selection flow. Off by default -- see --with-demo-persona
            # help text and default-tenant-and-persona.md for why a freshly
            # seeded admin having exactly one persona is the better default.
            editor_role = role_service.get_or_create_role(
                tenant_id, "workflow_editor", "Can edit workflows"
            )
            for resource, action in [("workflow", "edit"), ("workflow", "view")]:
                role_service.grant_permission(
                    tenant_id, editor_role, resource=resource, action=action
                )
            editor_persona = role_service.get_or_create_persona(tenant_id, "Branch Manager")
            role_service.ensure_role_in_persona(tenant_id, editor_persona, editor_role)

        accounts = AccountRepository()
        user = accounts.get_user(tenant_id, admin_username)
        if user is None:
            user = accounts.create_user(
                tenant_id, admin_username, admin_password, email=admin_email
            )
        elif user.email != admin_email:
            user.email = admin_email
            user.save(update_fields=["email"])

        role_service.assign_persona(tenant_id, user.id, admin_persona, is_default=True)
        if editor_persona is not None:
            role_service.assign_persona(tenant_id, user.id, editor_persona)

        persona_summary = (
            f"{admin_persona.name!r} (role:manage, persona:manage, user:manage, "
            f"execution:create, execution:view, execution:resume) [default]"
        )
        if editor_persona is not None:
            persona_summary += (
                f", {editor_persona.name!r} (workflow:edit, workflow:view)"
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded tenant={tenant_id!r}\n"
                f"  admin user: username={admin_username!r} email={admin_email!r} "
                f"password={admin_password!r}\n"
                f"  personas: {persona_summary}\n"
                f"  NOTE: this user has no Django is_superuser access -- run "
                f"`manage.py createsuperuser` separately if /admin/ access is also needed."
            )
        )
