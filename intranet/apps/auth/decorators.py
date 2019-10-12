"""Decorators that restrict views to certain types of users."""
import functools
import time
from typing import Container, Optional

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import redirect, render
from django.urls import reverse


def admin_required(group):
    """Decorator that requires the user to be in a certain admin group.

    For example, @admin_required("polls") would check whether a user is
    in the "admin_polls" group or in the "admin_all" group.

    """

    def in_admin_group(user):
        return user.is_authenticated and user.has_admin_permission(group)

    return user_passes_test(in_admin_group)


#: Restrict the wrapped view to eighth admins
eighth_admin_required = admin_required("eighth")

#: Restrict the wrapped view to announcements admins
announcements_admin_required = admin_required("announcements")

#: Restrict the wrapped view to events admins
events_admin_required = admin_required("events")

#: Restrict the wrapped view to board admins
board_admin_required = admin_required("board")

#: Restrict the wrapped view to users who can take attendance
attendance_taker_required = user_passes_test(lambda u: not u.is_anonymous and u.is_attendance_taker)


def deny_restricted(wrapped):
    def inner(*args, **kwargs):
        request = args[0]  # request is the first argument in a view
        if not request.user.is_anonymous and not request.user.is_restricted:
            return wrapped(*args, **kwargs)
        else:
            messages.error(request, "You are not authorized to access that page.")
            return redirect("index")

    return inner


def reauthentication_required(wrapped):
    def inner(*args, **kwargs):
        # *** WARNING: Any changes to this MUST update restrict_access() below too ***

        request = args[0]  # request is the first argument in a view
        if (
            isinstance(request.session.get("reauthenticated_at", None), float)
            and 0 <= (time.time() - request.session["reauthenticated_at"]) <= settings.REAUTHENTICATION_EXPIRE_TIMEOUT
        ):
            return wrapped(*args, **kwargs)
        else:
            return redirect("{}?next={}".format(reverse("reauth"), request.path))

    return inner


def restrict_access(
    *,
    redirect_denied_to_index: bool = False,
    access_denied_message: Optional[str] = "You are not authorized to view this page.",
    deny_all_anonymous: bool = True,
    deny_all_restricted: bool = True,
    require_reauthentication: bool = False,
    allow_all_auth_non_restricted: bool = False,
    allow_all_auth_even_restricted: bool = False,
    allow_admin_types: Optional[Container[str]] = None,
    allow_superuser: bool = True,
    allow_internal_ips: bool = False
):
    """Restrict access to users based on the given specification.

    The goal of this function is to unify all of the authentication decorators to avoid duplication and
    forgetting of decorators.

    The arguments to this function, or those arguments' behavior should NOT be changed unless it can be
    proven that there will be no change in the behavior of any cases in which this function is used. If
    necessary, this may mean auditing each use manually. (The *only* exception is adding new options
    that are disabled by default and thus have no effect.)

    A formal description of the options follows, but here is a more informal description of what they signify:
    - The "require"/"deny" options (deny_all_anonymous, deny_all_restricted, require_reauthentication) are all checked
      first. If any of them specify a condition which is not met by a particular request, that request is
      denied.
    - Next, the "allow" options are checked. The wrapped view will only be called for a particular request if one of
      these options specifies a condition that is met by that request.

    Args:
        redirect_denied_to_index: If this is set to True (default False), requests which are denied access will be
            redirected to the index page (be that the dashboard or the login page for them) instead of being shown the
            403 page.
        access_denied_message: The message to show when a user is denied access. If redirect_denied_to_index is
            False, this will be shown on the 403 page. If redirect_denied_to_index is True, it will be shown using
            Django's built-in messaging system (which we show using the Messenger library).
            This can be None, in which case no message will be shown.
        deny_all_anonymous: If this is set to True (default), all unauthenticated requests will be denied access,
            regardless of any other options being set.
        deny_all_restricted: If this is set to True (default), all authenticated requests from users for whom
            ``user.is_restricted`` is True will be denied access. This does NOT imply ``deny_all_anonymous = True``; it
            only takes effect if the user is authenticated. This is designed to permit, for example, denying restricted
            users while also allowing login from all internal IPs without authentication.
        require_reauthentication: If this is set to True (default is False), users will be required to reauthenticate
            through the "reauth" view. Implies ``deny_all_anonymous = True``, but does not imply anything else.
        allow_all_auth_non_restricted: If this is set to True, all requests which have passed the anonymous/restricted/reauth
            restrictions and which come from a *NON-RESTRICTED* logged-in user will be allowed access.
        allow_all_auth_even_restricted: If this is set to True, all requests which have passed the anonymous/restricted/reauth
            restrictions and which come from a logged-in user will be allowed access, even if that user's account is
            restricted.
        allow_admin_types: If this is set, all requests which have passed the anonymous/restricted/reauth restrictions which
            come from a logged-in user who has ANY of the given admin permissions will be allowed access. Example:
            ``["eighth", "events"]``
        allow_superuser: If this is set to True (default), all requests which have passed the anonymous/restricted/reauth
            restrictions which come from a logged-in user who has ``is_superuser = True`` will be allowed access.
        allow_internal_ips: If this is set to True, all requests which have passed the anonymous/restricted/reauth
            restrictions and come from an IP that is ``in settings.INTERNAL_IPS`` will be allowed access.

    """

    # We define things here because we want to make the actual wrapper as fast as possible.

    if require_reauthentication:
        # Later down, we assume that deny_all_anonymous is True if require_reauthentication is True. Do not remove this casually.
        deny_all_anonymous = True

    if redirect_denied_to_index:

        def not_authorized(request):
            if access_denied_message is not None:
                messages.error(request, access_denied_message)

            return redirect("index")

    else:

        def not_authorized(request):
            return render(request, "error/403.html", {"reason": access_denied_message}, status=403)

    def wrap(func):
        @functools.wraps(func)
        def wrapped(request, *args, **kwargs):
            # deny_restricted is, by design, essentially ignored if the user is not logged in
            if (deny_all_anonymous and not request.user.is_authenticated) or (
                deny_all_restricted and request.user.is_authenticated and request.user.is_restricted
            ):
                return not_authorized(request)

            # *** WARNING: Any changes to this MUST update reauthentication_required() above too ***
            if require_reauthentication:
                if not (
                    isinstance(request.session.get("reauthenticated_at", None), float)
                    and 0 <= (time.time() - request.session["reauthenticated_at"]) <= settings.REAUTHENTICATION_EXPIRE_TIMEOUT
                ):
                    return redirect("{}?next={}".format(reverse("reauth"), request.path))

            if request.user.is_authenticated and (
                allow_all_auth_even_restricted
                or (allow_all_auth_non_restricted and not request.user.is_restricted)
                or (allow_superuser and request.user.is_superuser)
                or (allow_admin_types and any(request.user.has_admin_permission(perm) for perm in allow_admin_types))
            ):
                return func(request, *args, **kwargs)

            if allow_internal_ips:
                remote_addr = request.META["HTTP_X_REAL_IP"] if "HTTP_X_REAL_IP" in request.META else request.META.get("REMOTE_ADDR", "")
                if remote_addr in settings.INTERNAL_IPS:
                    return func(request, *args, **kwargs)

            return not_authorized(request)

        return wrapped

    return wrap
