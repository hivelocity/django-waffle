from django.conf import settings
from django.utils.encoding import smart_str
from django.contrib.auth.models import User

from waffle import COOKIE_NAME, TEST_COOKIE_NAME
from waffle.models import Flag


class WaffleMiddleware(object):
    def process_request(self, request):
        try:
            if request.user.is_authenticated():
                for cookie in request.COOKIES:
                    if Flag.objects.filter(name=cookie.strip('dwf_')).exists():
                        pk = request.user.pk
                        flag = Flag.objects.get(name=cookie.strip('dwf_'))
                        if flag.rollout is True:
                            if pk not in flag.user_pks and request.COOKIES.get("dwf_" + flag.name) == 'True':
                                flag.user_pks.append(request.user.pk)
                                flag.save()
                        for pk in flag.user_pks:
                            if not User.objects.filter(pk=pk).exists():
                                flag.user_pks.remove(pk)
                                flag.save()
        except AttributeError:
            pass

    def process_response(self, request, response):
        secure = getattr(settings, 'WAFFLE_SECURE', False)
        max_age = getattr(settings, 'WAFFLE_MAX_AGE', 2592000)  # 1 month

        if hasattr(request, 'waffles'):
            for k in request.waffles:
                name = smart_str(COOKIE_NAME % k)
                active, rollout = request.waffles[k]
                if rollout and not active:
                    # "Inactive" is a session cookie during rollout mode.
                    age = None
                else:
                    age = max_age
                response.set_cookie(name, value=active, max_age=age,
                                    secure=secure)
        if hasattr(request, 'waffle_tests'):
            for k in request.waffle_tests:
                name = smart_str(TEST_COOKIE_NAME % k)
                value = request.waffle_tests[k]
                response.set_cookie(name, value=value)

        # give user cookie true if in database for flag
        try:
            if request.user.is_authenticated():
                pk = request.user.pk
                flags = Flag.objects.all()
                for flag in flags:
                    if pk in flag.user_pks:
                        try:
                            response.delete_cookie(str('dwf_' + flag.name))
                        except:
                            pass
                        response.set_cookie(str('dwf_' + flag.name), value=True,
                                            max_age=2592000, secure=secure)
        except AttributeError:
            pass
        return response
