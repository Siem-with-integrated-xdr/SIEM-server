from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.forms import UserCreationForm
from django.http import JsonResponse




def home(request):
    return render(request, 'dashboard/homepage.html')

from django.shortcuts import render

def computer_list(request):
    computers = [
        {"id": 1, "name": "PC-101", "username": "user1", "status": True},
        {"id": 2, "name": "PC-102", "username": "user2", "status": False},
        {"id": 3, "name": "PC-103", "username": "user3", "status": True},
        {"id": 4, "name": "PC-104", "username": "user4", "status": False},
        {"id": 5, "name": "PC-105", "username": "user5", "status": True},
    ]
    return render(request, "dashboard/agents.html", {"computers": computers})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('homepage')
    else:
        form = AuthenticationForm()
    return render(request, 'dashboard/login.html', {'form': form})


def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('homepage')  # Replace with your desired redirect
    else:
        form = UserCreationForm()
    return render(request, 'dashboard/signup.html', {'form': form})

def charts_view(request):
    """View for the analytics charts page"""
    return render(request, 'dashboard/charts.html')

def alerts_view(request):
    return render(request, 'dashboard/alerts.html')

def critical_view(request):
    return render(request, 'dashboard/critical_alerts.html')

def high_view(request):
    return render(request, 'dashboard/high_alerts.html')

def moderate_view(request):
    return render(request, 'dashboard/moderate_alerts.html')

def low_view(request):
    return render(request, 'dashboard/low_alerts.html')

def agent_view(request):
    return render(request, 'dashboard/agent.html')
