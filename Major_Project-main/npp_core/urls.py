from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect

def root_redirect(request):
    return redirect('authentication:login')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', root_redirect),
    path('auth/', include('authentication.urls')),
    path('dashboard/', include('dashboard.urls')),
    path('threats/', include('threats.urls')),
    path('risk-assessment/', include('risk_assessment.urls')),
    path('security-controls/', include('security_controls.urls')),
    path('reports/', include('reports.urls')),
    path('users/', include('user_management.urls')),
    path('resources/', include('resource_allocation.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)