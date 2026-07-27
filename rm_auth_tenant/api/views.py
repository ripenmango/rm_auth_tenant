from django.conf import settings
from django.db import IntegrityError
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, NotFound, ValidationError

from drf_base_app.rest_framework.permissions import IsAuthenticated
from drf_base_app.views import (
    RMAPIView,
    RMModelViewSet,
)  # stand-in for platform_core.api.base_views.RMAPIView / RMModelViewSet
from drf_base_app.rest_framework import (
    Response,
    envelope,
)  # stand-in for platform_core.api.responses.envelope
from drf_base_app.swagger.responses import (
    envelope_response,
    error_response,
)
from drf_base_app.swagger.decorators import (
    rm_swagger,
)  # stand-in for platform_core.api.swagger.decorators.rm_swagger

from rm_auth_tenant.api.serializers import (
    ChangePasswordSerializer,
    CreatePersonaSerializer,
    CreateRoleSerializer,
    CreateUserSerializer,
    LoginSerializer,
    LogoutSerializer,
    PersonaDetailSerializer,
    RefreshSerializer,
    RoleSerializer,
    SwitchPersonaSerializer,
    TokenPairSerializer,
    UpdateUserSerializer,
    UserSerializer,
)
from rm_auth_tenant.authorization.policy_permission import RequiresPermission
from rm_auth_tenant.services.authentication_service import (
    AuthenticationError,
    AuthenticationService,
    PersonaSelectionRequired,
)
from rm_auth_tenant.services.role_service import RoleService, RoleServiceError
from rm_auth_tenant.services.user_service import UserService, UserServiceError
from drf_base_app.logging import get_logger

logger = get_logger(__name__)


def _token_pair_payload(token_pair, persona):
    return {
        "access_token": token_pair.access_token,
        "refresh_token": token_pair.refresh_token,
        "persona": {"id": persona.id, "name": persona.name},
    }


def _resolve_tenant_id(data: dict) -> str:
    """Non-enterprise / self-serve simplification -- see
    default-tenant-and-persona.md. `tenant` is optional on Login/Refresh; if
    omitted, callers land in the configured default tenant rather than
    needing to know or supply a tenant id at all."""
    return data.get("tenant") or settings.RM_AUTH.get("DEFAULT_TENANT_ID", "default")


class LoginView(RMAPIView):
    """POST /api/auth/login -- §14.1 sequence diagram."""

    @rm_swagger(
        summary="Authenticate a user and issue a token pair",
        description=(
            "Validates username/password within a tenant. `tenant` is optional -- "
            "omit it to use the configured default tenant (non-enterprise / "
            "self-serve case); enterprise deployments should pass it explicitly. "
            "If the user has exactly one eligible persona, returns an "
            "access/refresh token pair for that persona directly (this is the "
            "common case for a newly-created user, which is auto-assigned a "
            "single 'Default' persona -- see default-tenant-and-persona.md). "
            "If the user has multiple eligible personas and none was specified, "
            'returns `meta.step == "select_persona"` with the list of eligible '
            "personas instead -- call this endpoint again with `persona_id` set "
            "to complete login."
        ),
        request=LoginSerializer,
        success=TokenPairSerializer,
        meta={"step": serializers.CharField()},
        responses={
            200: envelope_response(
                TokenPairSerializer,
                description=(
                    "Either a token pair (login complete) or a persona-selection "
                    "prompt (see `meta.step`)."
                ),
            ),
            401: error_response("Invalid tenant, username, or password."),
        },
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        service = AuthenticationService()
        try:
            token_pair, persona = service.login(
                tenant_id=_resolve_tenant_id(data),
                username=data["username"],
                password=data["password"],
                persona_id=data.get("persona_id"),
            )
        except PersonaSelectionRequired as exc:
            personas = [{"id": p.id, "name": p.name} for p in exc.eligible_personas]
            return envelope(
                data={"personas": personas}, meta={"step": "select_persona"}, status=200
            )
        except AuthenticationError as exc:
            raise AuthenticationFailed(str(exc))

        return envelope(data=_token_pair_payload(token_pair, persona))


class RefreshView(RMAPIView):
    """POST /api/auth/refresh -- §14.3 sequence diagram."""

    @rm_swagger(
        summary="Exchange a refresh token for a new token pair",
        description=(
            "Issues a new access/refresh token pair for the same tenant and "
            "persona bound to the supplied refresh token. `tenant` is optional, "
            "same as on /login -- see default-tenant-and-persona.md."
        ),
        request=RefreshSerializer,
        success=TokenPairSerializer,
        responses={
            200: envelope_response(TokenPairSerializer, description="New token pair."),
            401: error_response("Refresh token is invalid, expired, or revoked."),
        },
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        service = AuthenticationService()
        try:
            token_pair, persona = service.refresh(
                _resolve_tenant_id(data), data["refresh_token"]
            )
        except AuthenticationError as exc:
            raise AuthenticationFailed(str(exc))

        return envelope(data=_token_pair_payload(token_pair, persona))


class LogoutView(RMAPIView):
    permission_classes = [IsAuthenticated]

    @rm_swagger(
        summary="Log out the current session",
        description=(
            "Revokes the caller's current session. If `refresh_token` is "
            "supplied, that specific refresh token is revoked; otherwise the "
            "current access token's session is invalidated."
        ),
        request=LogoutSerializer,
        success={"logged_out": serializers.BooleanField()},
        responses={
            200: envelope_response(
                {"logged_out": serializers.BooleanField()},
                description="Logout confirmed.",
            ),
            401: error_response(),
        },
        tags=["Authentication"],
        auth=["Bearer"],
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        context = request.security_context
        service = AuthenticationService()
        service.logout(
            tenant_id=context.tenant_id,
            user_id=context.user_id,
            refresh_jti=serializer.validated_data.get("refresh_token"),
        )
        return envelope(data={"logged_out": True})


class ChangePasswordView(RMAPIView):
    permission_classes = [IsAuthenticated]

    @rm_swagger(
        summary="Change the current user's password",
        description=(
            "Verifies `old_password` before setting `new_password`. Existing "
            "sessions/tokens are invalidated as a side effect (token version "
            "bump), so the caller will need to log in again afterward."
        ),
        request=ChangePasswordSerializer,
        success={"password_changed": serializers.BooleanField()},
        responses={
            200: envelope_response(
                {"password_changed": serializers.BooleanField()},
                description="Password changed.",
            ),
            401: error_response("Not authenticated, or `old_password` is incorrect."),
        },
        tags=["Authentication"],
        auth=["Bearer"],
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        context = request.security_context
        service = AuthenticationService()
        try:
            service.change_password(
                tenant_id=context.tenant_id,
                user_id=context.user_id,
                old_password=data["old_password"],
                new_password=data["new_password"],
            )
        except AuthenticationError as exc:
            raise AuthenticationFailed(str(exc))

        return envelope(data={"password_changed": True})


class SwitchPersonaView(RMAPIView):
    """POST /api/auth/switch-persona -- issues a brand-new token pair (§5/§7 decision)."""

    permission_classes = [IsAuthenticated]

    @rm_swagger(
        summary="Switch the active persona for the current user",
        description=(
            "Issues a brand-new access/refresh token pair bound to "
            "`persona_id`, provided the current user is eligible for that "
            "persona. The previous token pair is invalidated."
        ),
        request=SwitchPersonaSerializer,
        success=TokenPairSerializer,
        responses={
            200: envelope_response(
                TokenPairSerializer,
                description="New token pair for the requested persona.",
            ),
            401: error_response(
                "Not authenticated, or persona is not eligible for this user."
            ),
        },
        tags=["Authentication"],
        auth=["Bearer"],
    )
    def post(self, request):
        serializer = SwitchPersonaSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        context = request.security_context
        service = AuthenticationService()
        try:
            token_pair, persona = service.switch_persona(
                tenant_id=context.tenant_id,
                user_id=context.user_id,
                new_persona_id=serializer.validated_data["persona_id"],
            )
        except AuthenticationError as exc:
            raise AuthenticationFailed(str(exc))

        return envelope(data=_token_pair_payload(token_pair, persona))


class UserViewSet(RMModelViewSet):
    """
    /api/auth/users, /api/auth/users/<user_id> -- CRUD for tenant users.

    ModelViewSet's generic mixins assume `serializer.save()` performs the
    ORM write directly -- that's at odds with this package's layering rule
    (UserService/AccountRepository own every write -- password hashing,
    ver-bump + token revocation on deactivate, tenant scoping) and with
    using different serializers for input vs. output (Create/Update input
    shapes don't carry `id`/`created_at`/etc). So `get_queryset`,
    `get_object`, `create`, `update`, and `destroy` are overridden to route
    through UserService instead of `perform_create`/`perform_update`/
    `perform_destroy` + serializer.save(). `list`/`retrieve` keep the
    inherited mixin behavior since they're pure reads.
    """

    permission_classes = [RequiresPermission("user", "manage")]
    lookup_url_kwarg = "user_id"

    def get_serializer_class(self):
        if self.action == "create":
            return CreateUserSerializer
        if self.action in ("update", "partial_update"):
            return UpdateUserSerializer
        return UserSerializer

    def get_queryset(self):
        return UserService().list_users(self.request.security_context.tenant_id)

    def get_object(self):
        try:
            return UserService().get_user(
                self.request.security_context.tenant_id,
                self.kwargs[self.lookup_url_kwarg],
            )
        except UserServiceError as exc:
            raise NotFound(str(exc))

    @rm_swagger(
        summary="List users for the current tenant",
        success=UserSerializer(many=True),
        tags=["Users"],
        auth=["Bearer"],
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @rm_swagger(
        summary="Retrieve a user",
        success=UserSerializer,
        responses={404: error_response("User not found.")},
        tags=["Users"],
        auth=["Bearer"],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @rm_swagger(
        summary="Create a user",
        description=(
            "Creates a user for the current tenant. `persona_ids` and "
            "`default_persona_id` are both optional -- omit them entirely and "
            "the tenant's lazily-created 'Default' persona is assigned "
            "automatically (see default-tenant-and-persona.md). Pass "
            "`persona_ids` to assign specific existing personas instead; "
            "`default_persona_id` (must be one of `persona_ids`) marks which "
            "one `/login` uses when the login request omits `persona_id`."
        ),
        request=CreateUserSerializer,
        success=UserSerializer,
        responses={400: error_response("Invalid payload, or unknown persona id(s).")},
        tags=["Users"],
        auth=["Bearer"],
    )
    def create(self, request, *args, **kwargs):
        logger.info("Creating user for tenant %s", request.security_context.tenant_id)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        tenant_id = request.security_context.tenant_id

        persona_ids = data.get("persona_ids") or []
        personas = None
        default_persona = None
        if persona_ids:
            role_service = RoleService()
            try:
                personas = [
                    role_service.get_persona(tenant_id, pid) for pid in persona_ids
                ]
            except RoleServiceError as exc:
                raise ValidationError(str(exc))

            default_persona_id = data.get("default_persona_id")
            if default_persona_id is not None:
                default_persona = next(
                    (p for p in personas if p.id == default_persona_id), None
                )
                if default_persona is None:
                    raise ValidationError(
                        "default_persona_id must be one of persona_ids"
                    )

        user = UserService().create_user(
            tenant_id=tenant_id,
            username=data["username"],
            password=data["password"],
            email=data.get("email", ""),
            personas=personas,
            default_persona=default_persona,
        )
        return Response(UserSerializer(user).data, status=201)

    @rm_swagger(
        summary="Update a user",
        request=UpdateUserSerializer,
        success=UserSerializer,
        responses={404: error_response("User not found.")},
        tags=["Users"],
        auth=["Bearer"],
    )
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(
            data=request.data, partial=kwargs.get("partial", False)
        )
        serializer.is_valid(raise_exception=True)

        user = UserService().update_user(
            request.security_context.tenant_id, instance.id, **serializer.validated_data
        )
        return Response(UserSerializer(user).data)

    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    @rm_swagger(
        summary="Deactivate a user",
        success={"deactivated": serializers.BooleanField()},
        responses={404: error_response("User not found.")},
        tags=["Users"],
        auth=["Bearer"],
    )
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        UserService().deactivate_user(request.security_context.tenant_id, instance.id)
        return Response({"deactivated": True})


class RoleViewSet(RMModelViewSet):
    """
    /api/auth/roles, /api/auth/roles/<role_id> -- Role administration
    (§5 of auth-library-architecture.md).

    Create/list/retrieve only. Update/delete aren't exposed yet --
    RoleService has no update_role/delete_role (deleting a role that's
    already bundled into Personas and granted Casbin `p` rows needs a
    deliberate cascade story, not a bare ORM delete), so rather than expose
    an unguarded default ModelViewSet update/destroy that would bypass
    RoleService, PUT/PATCH/DELETE are excluded via `http_method_names`.

    Creating a Role has no Casbin side effect by itself -- see
    casbin-flow-architecture.md §1: only granting a permission to it (a
    separate endpoint/flow, not implemented here) writes a Casbin `p` row.
    """

    permission_classes = [RequiresPermission("role", "manage")]
    lookup_url_kwarg = "role_id"
    http_method_names = ["get", "post", "head", "options"]

    def get_serializer_class(self):
        if self.action == "create":
            return CreateRoleSerializer
        return RoleSerializer

    def get_queryset(self):
        return RoleService().list_roles(self.request.security_context.tenant_id)

    def get_object(self):
        try:
            return RoleService().get_role(
                self.request.security_context.tenant_id,
                self.kwargs[self.lookup_url_kwarg],
            )
        except RoleServiceError as exc:
            raise NotFound(str(exc))

    @rm_swagger(
        summary="List roles for the current tenant",
        success=RoleSerializer(many=True),
        tags=["Roles"],
        auth=["Bearer"],
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @rm_swagger(
        summary="Retrieve a role",
        success=RoleSerializer,
        responses={404: error_response("Role not found.")},
        tags=["Roles"],
        auth=["Bearer"],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @rm_swagger(
        summary="Create a role",
        description=(
            "Creates a Role -- a named, tenant-scoped bundle that permissions "
            "are later granted to (see RoleService.grant_permission)."
        ),
        request=CreateRoleSerializer,
        success=RoleSerializer,
        responses={
            400: error_response(
                "Invalid payload, or role name already exists for this tenant."
            )
        },
        tags=["Roles"],
        auth=["Bearer"],
    )
    def create(self, request, *args, **kwargs):
        logger.info("Creating role for tenant %s", request.security_context.tenant_id)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            role = RoleService().create_role(
                tenant_id=request.security_context.tenant_id,
                name=data["name"],
                description=data.get("description", ""),
            )
        except IntegrityError:
            raise ValidationError(
                f"Role '{data['name']}' already exists for this tenant."
            )

        return Response(RoleSerializer(role).data, status=201)


class PersonaViewSet(RMModelViewSet):
    """
    /api/auth/personas, /api/auth/personas/<persona_id> -- Persona
    administration (§5 of auth-library-architecture.md).

    Create/list/retrieve only, for the same reason as RoleViewSet -- no
    RoleService.update_persona/delete_persona exists, so PUT/PATCH/DELETE
    are excluded via `http_method_names` rather than left to fall through to
    an unguarded default ModelViewSet write.

    Assigning a persona to a user (the Casbin `g` row -- see
    casbin-flow-architecture.md §3) is a separate concern from creating the
    Persona itself and isn't handled by this ViewSet; see
    RoleService.assign_persona.
    """

    permission_classes = [RequiresPermission("persona", "manage")]
    lookup_url_kwarg = "persona_id"
    http_method_names = ["get", "post", "head", "options"]

    def get_serializer_class(self):
        if self.action == "create":
            return CreatePersonaSerializer
        return PersonaDetailSerializer

    def get_queryset(self):
        return RoleService().list_personas(self.request.security_context.tenant_id)

    def get_object(self):
        try:
            return RoleService().get_persona(
                self.request.security_context.tenant_id,
                self.kwargs[self.lookup_url_kwarg],
            )
        except RoleServiceError as exc:
            raise NotFound(str(exc))

    @rm_swagger(
        summary="List personas for the current tenant",
        success=PersonaDetailSerializer(many=True),
        tags=["Personas"],
        auth=["Bearer"],
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @rm_swagger(
        summary="Retrieve a persona",
        success=PersonaDetailSerializer,
        responses={404: error_response("Persona not found.")},
        tags=["Personas"],
        auth=["Bearer"],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @rm_swagger(
        summary="Create a persona",
        description=(
            "Creates a Persona -- a named bundle of existing Roles a user can "
            "act as (§5 design doc). `role_ids` must reference Roles that "
            "already exist for this tenant. Creating a Persona has no Casbin "
            "side effect by itself -- a `g` row is only written once the "
            "persona is assigned to a user (see RoleService.assign_persona)."
        ),
        request=CreatePersonaSerializer,
        success=PersonaDetailSerializer,
        responses={
            400: error_response(
                "Invalid payload, unknown role id(s), or persona name already "
                "exists for this tenant."
            ),
        },
        tags=["Personas"],
        auth=["Bearer"],
    )
    def create(self, request, *args, **kwargs):
        logger.info(
            "Creating persona for tenant %s", request.security_context.tenant_id
        )
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        tenant_id = request.security_context.tenant_id

        service = RoleService()
        role_ids = data.get("role_ids") or []
        try:
            roles = service.get_roles(tenant_id, role_ids) if role_ids else []
        except RoleServiceError as exc:
            raise ValidationError(str(exc))

        try:
            persona = service.create_persona(
                tenant_id=tenant_id, name=data["name"], roles=roles
            )
        except IntegrityError:
            raise ValidationError(
                f"Persona '{data['name']}' already exists for this tenant."
            )

        return Response(PersonaDetailSerializer(persona).data, status=201)
