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
    path('report/', views.report, name='report'),
    path('report/agent/<str:agent_id>/', views.export_agent_report, name='export_agent_report'),
    path("dashboard/reports/multi/",views.multi_agent_report, name="multi_agent_report"),
    path('dashboard/api/realtime-network/', views.realtime_network_api, name='realtime_network_api'),
    path('dashboard/api/agent/<str:agent_id>/realtime-network/', views.agent_realtime_network, name='agent_realtime_network_api'),
]

