from functools import wraps
from django.shortcuts import redirect


def auth0_login_required(f):
    @wraps(f)
    def decorated_function(request, *args, **kwargs):
        if 'user' not in request.session:
            return redirect('index')  # Replace 'index' with the name of the view you want to redirect unauthenticated users to
        return f(request, *args, **kwargs)
    return decorated_function
