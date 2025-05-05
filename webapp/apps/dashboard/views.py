from django.shortcuts import redirect, render, get_object_or_404
import requests 
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.forms import UserCreationForm
from django.http import JsonResponse
from elasticsearch import Elasticsearch, ConnectionError
import time
import json
from datetime import datetime, timedelta




def home(request):
    return render(request, 'dashboard/homepage.html')

from django.shortcuts import render

def computer_list(request):

    return render(request, "dashboard/agents.html")

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


def agent_detail(request, agent_id):
    # interpolate agent_id directly (not the literal “{agent_id}”)
    api_url = f"https://3ecf-46-152-4-125.ngrok-free.app/agent/{agent_id}"
    try:
        resp = requests.get(api_url, timeout=10)
        resp.raise_for_status()       # 4xx/5xx → HTTPError
        agent = resp.json()           # parse JSON into dict
    except requests.RequestException as e:
        # on network error, timeout, non-200 status, etc.
        agent = {'error': str(e)}
    return render(request, 'dashboard/agent_detail.html', {'agent': agent["agent"]})



def alerts_dashboard(request):
    """Render the HTML template"""
    return render(request, 'alerts/dashboard.html')