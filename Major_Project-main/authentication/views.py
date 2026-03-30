from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .forms import LoginForm, RegisterForm

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')
    
    form = LoginForm(request, data=request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            ip = request.META.get('REMOTE_ADDR')
            user.last_login_ip = ip
            user.save()
            messages.success(request, f'Welcome back, {user.first_name or user.username}!')
            if user.role == 'admin':
                return redirect('dashboard:admin_home')
            return redirect('dashboard:home')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'authentication/login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out successfully.')
    return redirect('authentication:login')

@login_required
def profile_view(request):
    return render(request, 'authentication/profile.html', {'user': request.user})