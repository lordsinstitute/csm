from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('', views.reports_home, name='home'),
    path('generate-pdf/', views.generate_pdf_report, name='generate_pdf'),
    path('admin-monitor/', views.admin_monitor, name='admin_monitor'),
]