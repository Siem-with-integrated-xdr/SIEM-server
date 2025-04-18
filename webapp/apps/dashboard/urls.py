from django.urls import path
from . import views

urlpatterns = [
    path('homepage/', views.home),
    path("agents/", views.computer_list, name="computer_list"),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('charts/', views.charts_view, name='charts'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('critical/', views.critical_view, name='critical'),
    path('high/', views.high_view, name='high'),
    path('moderate/', views.moderate_view, name='moderate'),
    path('low/', views.low_view, name='low'),

]

