from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    # path("admin/", admin.site.urls),
    # path("api/", include("rm_auth.urls")),
    path("api/rm_auth_tenant/", include("rm_auth_tenant.api.urls")),
    path(
        "api/docs/swagger.json",
        SpectacularAPIView.as_view(),
        name="schema-json",
    ),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema-json"),
        name="schema-swagger-ui",
    ),
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(url_name="schema-json"),
        name="schema-redoc",
    ),
]
