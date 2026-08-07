"""
Django system checks for rm_auth_tenant. Registered in AppConfig.ready()
(see apps.py) so `python manage.py check` (CI-blocking) picks them up.
"""
from django.core.checks import CheckMessage, Error, register
from django.urls import URLPattern, URLResolver, get_resolver


def _iter_url_patterns(patterns):
    for entry in patterns:
        if isinstance(entry, URLResolver):
            yield from _iter_url_patterns(entry.url_patterns)
        elif isinstance(entry, URLPattern):
            yield entry


def _view_classes_for_pattern(pattern: URLPattern):
    """
    A URLPattern's callback is either a class-based view's dispatch closure
    (`.cls` set by View.as_view(), including DRF ViewSets routed through a
    Router) or a plain function-based view (no `.cls` -- e.g.
    @api_view-decorated functions like rm_platform's health_check). Only
    the former is in scope for this check -- see check's docstring for why
    function-based views need a separate lint rule instead.
    """
    view_class = getattr(pattern.callback, "cls", None)
    if view_class is not None:
        yield view_class


@register()
def check_every_view_declares_access(app_configs, **kwargs) -> list[CheckMessage]:
    """
    Layer 3 of the "developer can't forget permission_classes" safeguard
    (see authorization/DESIGN.md for the full three-layer design: this
    check, AccessDeclarationRequiredMixin's __init_subclass__ guard in
    drf_base_app, and REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] as a
    deny-by-default net).

    AccessDeclarationRequiredMixin already catches this at import time for
    any class actually built on RMAPIView/RMModelViewSet -- so in the
    common case this check finds nothing new. It exists as a second,
    independent pass over the ACTUAL, LIVE URL configuration (not "every
    class Python happened to import this run") -- CI-blocking via
    `python manage.py check`, and immune to that mixin ever being
    bypassed, removed, or not applying to some future base class that
    doesn't go through RMAPIView/RMModelViewSet at all.

    Deliberately does NOT flag plain function-based views (`@api_view`) --
    those have no `permission_classes`/`is_public` concept to check in the
    first place; `@permission_classes([...])` is the equivalent contract
    for them, and enforcing ITS presence would need a different check
    (an AST/source scan, not introspection of a live class). rm_platform's
    health_check is exactly this shape today and is out of scope here.
    """
    errors: list[CheckMessage] = []
    seen: set[type] = set()

    for pattern in _iter_url_patterns(get_resolver().url_patterns):
        for view_class in _view_classes_for_pattern(pattern):
            if view_class in seen:
                continue
            seen.add(view_class)

            has_own_permission_classes = "permission_classes" in view_class.__dict__
            is_public = view_class.__dict__.get("is_public", False)
            if not has_own_permission_classes and not is_public:
                errors.append(
                    Error(
                        f"{view_class.__module__}.{view_class.__qualname__} is "
                        f"wired to URL pattern {pattern.pattern!r} but declares "
                        f"neither its own `permission_classes` nor "
                        f"`is_public = True`.",
                        hint=(
                            "Add an explicit permission_classes list, or "
                            "is_public = True + permission_classes = [AllowAny] "
                            "if this endpoint is genuinely meant to be public "
                            "(e.g. signup/login)."
                        ),
                        obj=view_class,
                        id="rm_auth_tenant.E001",
                    )
                )

    return errors
