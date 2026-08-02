from django.urls import path
from rest_framework.routers import SimpleRouter

from rm_auth_tenant.api.views import (
    ChangePasswordView,
    LoginView,
    LogoutView,
    PersonaViewSet,
    RefreshView,
    RoleViewSet,
    SignupView,
    SwitchPersonaView,
    UserViewSet,
    VerifyEmailView,
)

# trailing_slash=False to match this app's other endpoints ("login", not
# "login/"). No DefaultRouter -- we don't want its auto-generated API root
# view mixed in with the hand-written auth paths below.
router = SimpleRouter(trailing_slash=False)
router.register("users", UserViewSet, basename="rm_auth_user")
router.register("roles", RoleViewSet, basename="rm_auth_role")
router.register("personas", PersonaViewSet, basename="rm_auth_persona")

urlpatterns = [
    path("signup", SignupView.as_view(), name="rm_auth_signup"),
    path("verify-email", VerifyEmailView.as_view(), name="rm_auth_verify_email"),
    path("login", LoginView.as_view(), name="rm_auth_login"),
    path("refresh", RefreshView.as_view(), name="rm_auth_refresh"),
    path("logout", LogoutView.as_view(), name="rm_auth_logout"),
    path("change-password", ChangePasswordView.as_view(), name="rm_auth_change_password"),
    path("switch-persona", SwitchPersonaView.as_view(), name="rm_auth_switch_persona"),
    *router.urls,
]
