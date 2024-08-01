import datetime
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.conf import settings

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            last_activity = request.session.get('last_activity', None)
            if last_activity:
                last_activity = datetime.datetime.strptime(last_activity, '%Y-%m-%d %H:%M:%S')
                if (datetime.datetime.now() - last_activity).seconds > 1200: # 20 minutos para cierre de sesión
                    logout(request)
                    return redirect(settings.LOGIN_URL)
            request.session['last_activity'] = current_time
        response = self.get_response(request)
        return response