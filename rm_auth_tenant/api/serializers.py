from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from drf_base_app.rest_framework import serializers 


class LoginSerializer(serializers.RMSerializer):
    # Optional -- omit for the non-enterprise / self-serve case and the
    # configured default tenant is used (see default-tenant-and-persona.md).
    # Enterprise tenants should still pass this explicitly (or rely on
    # X-Tenant-Id/subdomain resolution upstream, if the deployment resolves
    # tenant that way instead of via the login body).
    tenant = serializers.CharField(required=False)
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    persona_id = serializers.IntegerField(required=False)


class RefreshSerializer(serializers.RMSerializer):
    # Optional for the same reason as LoginSerializer.tenant above -- a
    # refresh call for a default-tenant session shouldn't need to repeat it.
    tenant = serializers.CharField(required=False)
    refresh_token = serializers.CharField()


class LogoutSerializer(serializers.RMSerializer):
    refresh_token = serializers.CharField(required=False)


class ChangePasswordSerializer(serializers.RMSerializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)


class SwitchPersonaSerializer(serializers.RMSerializer):
    persona_id = serializers.IntegerField()


class PersonaSerializer(serializers.RMSerializer):
    """Lightweight persona shape used in the login/persona-selection flow
    (see LoginView) -- id + name only. For the full administrative
    representation (used by PersonaViewSet), see PersonaDetailSerializer
    below."""

    id = serializers.IntegerField()
    name = serializers.CharField()


class TokenPairSerializer(serializers.RMSerializer):
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()


class UserSerializer(serializers.RMSerializer):
    id = serializers.IntegerField()
    username = serializers.CharField()
    email = serializers.EmailField()
    is_active = serializers.BooleanField()
    # True for every user except one created via public signup while
    # RM_AUTH["SIGNUP_EMAIL_VERIFICATION_ENABLED"] is on and still pending
    # verification (see SignupSerializer/SignupView/
    # EmailVerificationService).
    is_email_verified = serializers.BooleanField()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()


class CreateUserSerializer(serializers.RMSerializer):
    username = serializers.CharField()
    email = serializers.EmailField(required=False, default="", allow_blank=True)
    password = serializers.CharField(write_only=True)
    # Both optional -- omit entirely and the tenant's lazily-created "Default"
    # persona is assigned automatically (see UserService.create_user /
    # default-tenant-and-persona.md). Pass persona_ids to assign specific,
    # already-existing personas instead; default_persona_id (must be one of
    # persona_ids) marks which one /login uses when persona_id is omitted.
    persona_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, default=list
    )
    default_persona_id = serializers.IntegerField(required=False)


class SignupSerializer(serializers.RMSerializer):
    """
    Public, unauthenticated self-registration for the community edition --
    used by SignupView, NOT by UserViewSet (that still requires
    `RequiresPermission("user", "manage")`, which a brand-new anonymous
    caller can never have). Same shape as CreateUserSerializer, except:

      - `email` is required (it's the primary identifier for signup) and
        `username` is optional -- SignupView defaults `username` to
        `email` when omitted, then delegates to the exact same
        UserService.create_user() as POST /users, so `tenant`,
        `persona_ids`, and `default_persona_id` all default exactly the
        same way (see CreateUserSerializer above / default-tenant-and-
        persona.md).
      - `password` is validated against Django's configured
        AUTH_PASSWORD_VALIDATORS (POST /users -- an authenticated,
        permissioned action -- deliberately leaves that judgment call to
        the caller; a public self-serve signup can't).
    """

    email = serializers.EmailField()
    username = serializers.CharField(required=False, allow_blank=True, default="")
    password = serializers.CharField(write_only=True)
    # Optional -- omit for the non-enterprise / self-serve case and the
    # configured default/shared tenant is used, same as Login/Refresh (see
    # default-tenant-and-persona.md).
    tenant = serializers.CharField(required=False)
    # Both optional, same semantics as CreateUserSerializer -- omit entirely
    # and the tenant's lazily-created "Default" persona is assigned
    # automatically.
    persona_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, default=list
    )
    default_persona_id = serializers.IntegerField(required=False)

    def validate_password(self, value):
        try:
            validate_password(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages))
        return value


class UpdateUserSerializer(serializers.RMSerializer):
    email = serializers.EmailField(required=False)
    is_active = serializers.BooleanField(required=False)


class VerifyEmailSerializer(serializers.RMSerializer):
    """Input for POST /verify-email -- the signed token from the link sent
    by EmailVerificationService.send_verification_email."""

    token = serializers.CharField()


class RoleSerializer(serializers.RMSerializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    description = serializers.CharField()
    slug = serializers.CharField()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()


class CreateRoleSerializer(serializers.RMSerializer):
    name = serializers.CharField()
    description = serializers.CharField(required=False, default="", allow_blank=True)


class PersonaDetailSerializer(serializers.RMSerializer):
    """Full persona representation, including its bundled Roles -- used by
    PersonaViewSet (create/list/retrieve). See PersonaSerializer above for
    the lighter shape used during login."""

    id = serializers.IntegerField()
    name = serializers.CharField()
    slug = serializers.CharField()
    roles = RoleSerializer(many=True)
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()


class CreatePersonaSerializer(serializers.RMSerializer):
    name = serializers.CharField()
    # Roles this persona bundles together (§5 design doc). Optional -- a
    # persona with zero roles is valid (e.g. created before its roles are
    # decided), it just won't grant any permissions until roles are added.
    role_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, default=list
    )
