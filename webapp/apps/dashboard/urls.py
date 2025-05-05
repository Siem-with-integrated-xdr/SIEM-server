from django.urls import path
from . import views


urlpatterns = [
    path('homepage/', views.home, name="homepage"),
    path("agents/", views.computer_list, name="agents"),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('charts/', views.charts_view, name='charts'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('critical/', views.critical_view, name='critical'),
    path('high/', views.high_view, name='high'),
    path('moderate/', views.moderate_view, name='moderate'),
    path('low/', views.low_view, name='low'),
    path('agent/<str:agent_id>', views.agent_detail, name='agent'),
]

