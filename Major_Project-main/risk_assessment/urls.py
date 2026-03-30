from django.urls import path
from . import views

app_name = 'risk_assessment'

urlpatterns = [
    path('', views.assessment_list, name='list'),
    path('<int:pk>/', views.assessment_detail, name='detail'),
    path('run/', views.run_assessment, name='run'),
    path('<int:pk>/edit/', views.edit_assessment, name='edit'),
    path('<int:pk>/delete/', views.delete_assessment, name='delete'),
]