from django.db import transaction

from rm_auth_tenant.roles.models import Persona, PersonaRole, Role, UserPersonaAssignment


class RoleRepository:
    def get_role(self, tenant_id: str, name: str) -> Role | None:
        return Role.objects.filter(tenant_id=tenant_id, name=name).first()

    def get_role_by_id(self, tenant_id: str, role_id: int) -> Role | None:
        return Role.objects.filter(tenant_id=tenant_id, id=role_id).first()

    def get_roles_by_ids(self, tenant_id: str, role_ids: list[int]) -> list[Role]:
        return list(Role.objects.filter(tenant_id=tenant_id, id__in=role_ids))

    def list_roles(self, tenant_id: str) -> list[Role]:
        return list(Role.objects.filter(tenant_id=tenant_id).order_by("name"))

    def create_role(self, tenant_id: str, name: str, description: str = "") -> Role:
        return Role.objects.create(tenant_id=tenant_id, name=name, description=description)

    def get_persona(self, tenant_id: str, name: str) -> Persona | None:
        return Persona.objects.filter(tenant_id=tenant_id, name=name).prefetch_related("roles").first()

    def get_persona_by_id(self, tenant_id: str, persona_id: int) -> Persona | None:
        return Persona.objects.filter(tenant_id=tenant_id, id=persona_id).prefetch_related("roles").first()

    def list_personas(self, tenant_id: str) -> list[Persona]:
        return list(
            Persona.objects.filter(tenant_id=tenant_id).prefetch_related("roles").order_by("name")
        )

    def create_persona(self, tenant_id: str, name: str, roles: list[Role]) -> Persona:
        persona = Persona.objects.create(tenant_id=tenant_id, name=name)
        # Not persona.roles.set(roles) -- that goes through Django's bulk M2M
        # manager, which bulk_create()s the through rows and bypasses
        # RMAuditModel.save() (same class of gotcha as the Casbin adapter's
        # bulk_create issue), leaving created_by_id/updated_by_id NULL against
        # a NOT NULL column. Creating each row explicitly runs save() normally.
        for role in roles:
            PersonaRole.objects.get_or_create(persona=persona, role=role)
        return persona

    def add_role_to_persona(self, persona: Persona, role: Role) -> None:
        """Bundles an additional Role into an ALREADY-EXISTING Persona --
        unlike create_persona's roles=[...] (creation-time only), this is for
        attaching a role to a persona that may already have users assigned
        (e.g. RoleService._sync_default_persona_permissions topping up the
        lazily-created default persona). get_or_create, same as
        create_persona's loop above -- idempotent, safe to call repeatedly."""
        PersonaRole.objects.get_or_create(persona=persona, role=role)

    def user_ids_with_role(self, tenant_id: str, role_name: str) -> list[int]:
        """Users eligible for any persona that bundles the named role."""
        return list(
            UserPersonaAssignment.objects.filter(tenant_id=tenant_id, persona__roles__name=role_name)
            .values_list("user_id", flat=True)
            .distinct()
        )

    def eligible_personas(self, tenant_id: str, user_id: int) -> list[Persona]:
        assignments = UserPersonaAssignment.objects.filter(
            tenant_id=tenant_id, user_id=user_id
        ).select_related("persona").prefetch_related("persona__roles")
        return [a.persona for a in assignments]

    def get_default_persona(self, tenant_id: str, user_id: int) -> Persona | None:
        """The persona /login uses when `persona_id` is omitted, even if the
        user has more than one eligible persona -- see UserPersonaAssignment's
        docstring. Returns None if no persona has been marked default yet."""
        assignment = (
            UserPersonaAssignment.objects.filter(
                tenant_id=tenant_id, user_id=user_id, is_default=True
            )
            .select_related("persona")
            .first()
        )
        return assignment.persona if assignment else None

    @transaction.atomic
    def assign_persona(
        self, tenant_id: str, user_id: int, persona: Persona, is_default: bool = False
    ) -> UserPersonaAssignment:
        if is_default:
            # At most one default per (tenant_id, user_id) -- clear any
            # existing one first, inside the same transaction as the write
            # below, so a concurrent read never sees two defaults at once.
            UserPersonaAssignment.objects.filter(
                tenant_id=tenant_id, user_id=user_id, is_default=True
            ).exclude(persona=persona).update(is_default=False)

        assignment, created = UserPersonaAssignment.objects.get_or_create(
            tenant_id=tenant_id,
            user_id=user_id,
            persona=persona,
            defaults={"is_default": is_default},
        )
        if not created and is_default and not assignment.is_default:
            assignment.is_default = True
            assignment.save(update_fields=["is_default"])
        return assignment

    @transaction.atomic
    def set_default_persona(
        self, tenant_id: str, user_id: int, persona: Persona
    ) -> UserPersonaAssignment | None:
        """Marks an ALREADY-assigned persona as the user's default, without
        re-assigning it. Returns None if the persona isn't assigned to this
        user yet -- callers (RoleService) turn that into a clear error rather
        than silently assigning it as a side effect of setting a default."""
        assignment = UserPersonaAssignment.objects.filter(
            tenant_id=tenant_id, user_id=user_id, persona=persona
        ).first()
        if assignment is None:
            return None

        UserPersonaAssignment.objects.filter(
            tenant_id=tenant_id, user_id=user_id, is_default=True
        ).exclude(pk=assignment.pk).update(is_default=False)

        if not assignment.is_default:
            assignment.is_default = True
            assignment.save(update_fields=["is_default"])
        return assignment

    def revoke_persona(self, tenant_id: str, user_id: int, persona: Persona) -> None:
        UserPersonaAssignment.objects.filter(
            tenant_id=tenant_id, user_id=user_id, persona=persona
        ).delete()
