from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps

def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('authentication:login')
            if request.user.role not in roles:
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('dashboard:home')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

def login_and_any_role(view_func):
    """All authenticated users can access — just must be logged in."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('authentication:login')
        return view_func(request, *args, **kwargs)
    return wrapper