from rm_auth_tenant.conf import rm_auth_tenant_settings

print("1. DEFAULT_PERSONA_PERMISSIONS setting:")
print("  ", rm_auth_tenant_settings.default_persona_permissions)

print("2. DEFAULT_TENANT_ID / DEFAULT_PERSONA_NAME settings:")
print("   tenant:", rm_auth_tenant_settings.default_tenant_id)
print("   persona:", rm_auth_tenant_settings.default_persona_name)

from rm_auth_tenant.roles.models import Persona, Role

print("3. Personas that actually exist for tenant_id='rm_community':")
for p in Persona.objects.filter(tenant_id="rm_community"):
    print(
        "   -", repr(p.name), "slug=", p.slug, "roles=", [r.name for r in p.roles.all()]
    )

print("4. Roles that actually exist for tenant_id='rm_community':")
for r in Role.objects.filter(tenant_id="rm_community"):
    print("   -", repr(r.name), "slug=", r.slug)

print("5. Now calling RoleService().get_or_create_default_persona('rm_community') ...")
from rm_auth_tenant.services.role_service import RoleService

try:
    persona = RoleService().get_or_create_default_persona("rm_community")
    print(
        "   OK -- persona:",
        persona.name,
        "id=",
        persona.id,
        "roles=",
        [r.name for r in persona.roles.all()],
    )
except Exception as exc:
    import traceback

    print("   EXCEPTION:", repr(exc))
    traceback.print_exc()

print("6. Policy rows for rm_community after the call:")
from rm_auth_tenant.policy.models import PolicyRule

for row in PolicyRule.objects.filter(tenant_id="rm_community"):
    print("   -", row.subject, row.resource, row.action)
