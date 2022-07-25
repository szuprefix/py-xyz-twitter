# -*- coding:utf-8 -*- 
from functools import wraps

from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponseRedirect, HttpResponseForbidden
try:
    from django.utils.decorators import available_attrs
except:
    from functools import WRAPPER_ASSIGNMENTS
    def available_attrs(fn):
        return WRAPPER_ASSIGNMENTS

from . import helper
from django.contrib import auth

def get_twitter_login_context(request):
    ov = request.GET.get("oauth_verifier")
    if v:
        state = state[len(STATE_PREFIX):]
        from django.core.cache import cache
        context = cache.get(state)
        if not context:
            context = {'login_type': state}
        return context

def user_passes_test(test_func):
    u"""
      重写user_passes_test是因为django.contrib.auth.decorators.user_passes_test里面的redirect_to_login会把url参数
      的顺序给打乱，但微信的安全检验又是限定了参数顺序的，不兼容。
      同时也是因为从外部登录完回来时，要处理一下django的登录事宜。
    """

    def decorator(view_func):
        @wraps(view_func, assigned=available_attrs(view_func))
        def _wrapped_view(request, *args, **kwargs):
            ot = request.GET.get("oauth_token")
            ov = request.GET.get("oauth_verifier")
            if ov is not None:
                user = auth.authenticate(open_auth=ot, oauth_verifier=ov)
                if user and not isinstance(user, AnonymousUser):
                    auth.login(request, user)
                    return view_func(request, *args, **kwargs)
                else:
                    return HttpResponseForbidden()
            if test_func(request.user):
                return view_func(request, *args, **kwargs)
            api = helper.Api()
            login_url = api.get_auth_url(request.build_absolute_uri(request.META.get('TENANT_REQUEST_URI')))
            return HttpResponseRedirect(login_url)

        return _wrapped_view

    return decorator


def twitter_login_required(function=None):
    """
    Decorator for views that checks that the user is logged in, redirecting
    to the log-in page if necessary.
    """
    actual_decorator = user_passes_test(
        lambda u: u.is_authenticated and hasattr(u, 'as_twitter_user'),
    )
    if function:
        return actual_decorator(function)
    return actual_decorator
