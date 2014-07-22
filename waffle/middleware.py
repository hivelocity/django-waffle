from django.conf import settings
from django.utils.encoding import smart_str
from django.contrib.auth.models import User

from waffle import COOKIE_NAME, TEST_COOKIE_NAME
from waffle.models import Flag


class WaffleMiddleware(object):
    def process_request(self, request):
        if request.user.is_authenticated():
            for cookie in request.COOKIES:
                if Flag.objects.filter(name=cookie.strip('dwf_')).exists():
                    flag = Flag.objects.get(name=cookie.strip('dwf_'))
                    pk = request.user.pk
                    if flag.rollout is True:
                        if pk not in flag.user_pks:
                            # Add user pk to db
                            flag.user_pks.append(request.user.pk)
                            flag.save()
                        else:
                            # Give user the proper cookie
                            request.COOKIES[cookie] = True

                    else:
                        if pk in flag.user_pks:
                            flag.user_pks.remove(pk)
                            flag.save()
                    for pk in flag.user_pks:
                        if not User.objects.filter(pk=pk).exists():
                            flag.user_pks.remove(pk)
                            flag.save()

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

        return response
