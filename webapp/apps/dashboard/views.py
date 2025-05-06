from django.shortcuts import redirect, render, get_object_or_404
import requests 
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.forms import UserCreationForm
from django.http import JsonResponse,HttpResponse
from elasticsearch import Elasticsearch, ConnectionError
import time
import json
from datetime import datetime, timedelta
from django.utils.dateparse import parse_datetime
from datetime import timezone
from django.template.loader import get_template
from xhtml2pdf import pisa
from django.utils.timezone import now
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import io

def home(request):
    api_url = "https://3ecf-46-152-4-125.ngrok-free.app/overview"

    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception:
        data = {
            "security_alerts": {"critical": 0, "high": 0, "moderate": 0, "low": 0},
            "system_health": {
                "cpu": {"usage": 0, "trend_value": 0}, 
                "memory": {"usage": 0, "trend_value": 0},
                "disk": {"usage": 0, "trend_value": 0},
                "uptime": {"days": 0, "hours": 0}
            },
            "top_agents": [],
            "network_protocols": {"labels": [], "data": []}
        }

    # 🔧 Modify trend_value to be absolute
    for metric in ["cpu", "memory", "disk"]:
        if metric in data.get("system_health", {}) and "trend_value" in data["system_health"][metric]:
            data["system_health"][metric]["trend_value"] = abs(data["system_health"][metric]["trend_value"])

    # Prepare alert cards
    severity_map = [
        ("critical", "Critical", "danger"),
        ("high", "High", "warning"),
        ("moderate", "Moderate", "info"),
        ("low", "Low", "success"),
    ]

    alert_cards = []
    for key, label, color in severity_map:
        alert_cards.append({
            "key": key,
            "label": label,
            "color": color,
            "count": data["security_alerts"].get(key, 0)
        })

    context = {
        "alert_cards": alert_cards,
        "health": data.get("system_health", {}),
        "top_agents": data.get("top_agents", []),
        "protocols": data.get("network_protocols", {}),
        "metrics": ["cpu", "memory", "disk"],
    }
    return render(request, "dashboard/homepage.html", context)


def computer_list(request):
    API_URL = "https://3ecf-46-152-4-125.ngrok-free.app/agents"
    
    try:
        response = requests.get(API_URL, headers={"ngrok-skip-browser-warning": "1"}, timeout=5)
        response.raise_for_status()
        data = response.json()
        agents = data.get("agents", [])

        # Ensure datetime objects are parsed for humanize
        for agent in agents:
            if "last_checkin" in agent and agent["last_checkin"]:
                dt = parse_datetime(agent["last_checkin"])
                if dt is not None:
                    agent["last_checkin"] = dt.replace(tzinfo=timezone.utc)

    except requests.RequestException:
        agents = []

    return render(request, "dashboard/agents.html", {"agents": agents})

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

import requests
import json
from django.shortcuts import render

def charts_view(request):
    api_url = "https://3ecf-46-152-4-125.ngrok-free.app/charts"

    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception:
        data = {
            "internet_usage": {"labels": [], "total_traffic_mb": []},
            "resource_usage": {"labels": [], "cpu_usage_percent": [], "ram_usage_percent": [], "disk_usage_percent": []},
            "user_activity": {"labels": [], "counts": []},
            "security_alerts": {"labels": [], "counts": []},
            "network_distribution": {"labels": [], "packet_counts_by_source_continent": []},
            "region_distribution": {"labels": [], "incident_counts": []},
        }

    context = {
        "internet_labels": json.dumps(data["internet_usage"].get("labels", [])),
        "internet_traffic": json.dumps(data["internet_usage"].get("total_traffic_mb", [])),

        "resource_labels": json.dumps(data["resource_usage"].get("labels", [])),
        "cpu_usage": json.dumps([v if v is not None else 0 for v in data["resource_usage"].get("cpu_usage_percent", [])]),
        "ram_usage": json.dumps([v if v is not None else 0 for v in data["resource_usage"].get("ram_usage_percent", [])]),
        "disk_usage": json.dumps([v if v is not None else 0 for v in data["resource_usage"].get("disk_usage_percent", [])]),

        "activity_labels": json.dumps(data["user_activity"].get("labels", [])),
        "activity_counts": json.dumps(data["user_activity"].get("counts", [])),

        "alerts_labels": json.dumps(data["security_alerts"].get("labels", [])),
        "alerts_counts": json.dumps(data["security_alerts"].get("counts", [])),

        "network_distribution": {
            "labels": data["network_distribution"].get("labels", []),
            "packet_counts_by_source_continent": data["network_distribution"].get("packet_counts_by_source_continent", [])
        },


        "region_labels": json.dumps(data["region_distribution"].get("labels", [])),
        "region_counts": json.dumps(data["region_distribution"].get("incident_counts", [])),
    }
    print(context)
    return render(request, "dashboard/charts.html", context)



def alerts_view(request):
    API_URL = 'https://3ecf-46-152-4-125.ngrok-free.app/alerts/'
    # 1. get requested page
    page = int(request.GET.get('page', 1))

    # 2. call the external API
    try:
        resp = requests.get(
            API_URL,
            params={'page': page},
            headers={
                'ngrok-skip-browser-warning': '1',
                'Accept': 'application/json'
            },
            timeout=5
        )
        resp.raise_for_status()
        data = resp.json()
        error_message = None
    except requests.RequestException:
        # fallback on error
        data = {
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'alerts': [],
            'pagination': {'current_page': page, 'total_pages': 1, 'total_alerts': 0}
        }
        error_message = "Failed to fetch alerts. Please try again later."

    # 3. extract and normalize
    summary    = data.get('summary', {})
    alerts     = data.get('alerts', [])
    pagination = data.get('pagination', {})

    current = pagination.get('current_page', page)
    total   = pagination.get('total_pages', 1)

    # 4. build a smart page-range (just like your JS did)
    start = max(2, current-2)
    end   = min(total-1, current+2)
    page_numbers = list(range(start, end+1)) if total > 1 else []

    show_left_ellipsis  = start > 2
    show_right_ellipsis = end < total-1

    # 5. render
    return render(request, 'dashboard/alerts.html', {
        'summary': summary,
        'alerts': alerts,
        'pagination': pagination,
        'page_numbers': page_numbers,
        'show_left_ellipsis': show_left_ellipsis,
        'show_right_ellipsis': show_right_ellipsis,
        'error_message': error_message,
    })

def critical_view(request):
    page = int(request.GET.get("page", 1))
    api_url = "https://3ecf-46-152-4-125.ngrok-free.app/alerts"

    try:
        response = requests.get(
            api_url,
            params={"page": page, "severity": "critical"},
            headers={"ngrok-skip-browser-warning": "1"},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        error_message = None
    except Exception:
        data = {
            "alerts": [],
            "summary": {},
            "pagination": {"current_page": 1, "total_pages": 1, "total_alerts": 0}
        }
        error_message = "Failed to load critical alerts. Please try again."

    alerts = data.get("alerts", [])
    summary = data.get("summary", {})
    pagination = data.get("pagination", {"current_page": 1, "total_pages": 1})
    alert_count = summary.get("critical", 0)

    current = pagination.get("current_page", page)
    total = pagination.get("total_pages", 1)

    start = max(2, current - 2)
    end = min(total - 1, current + 2)
    page_numbers = list(range(start, end + 1)) if total > 1 else []

    show_left_ellipsis = start > 2
    show_right_ellipsis = end < total - 1

    context = {
        "alerts": alerts,
        "alert_count": alert_count,
        "pagination": pagination,
        "page_numbers": page_numbers,
        "show_left_ellipsis": show_left_ellipsis,
        "show_right_ellipsis": show_right_ellipsis,
        "error_message": error_message,
    }

    return render(request, 'dashboard/critical_alerts.html', context)

def high_view(request):
    API_URL = 'https://3ecf-46-152-4-125.ngrok-free.app/alerts'
    page = int(request.GET.get('page', 1))

    try:
        resp = requests.get(
            API_URL,
            params={'page': page, 'severity': 'high'},
            headers={
                'ngrok-skip-browser-warning': '1',
                'Accept': 'application/json'
            },
            timeout=5
        )
        resp.raise_for_status()
        data = resp.json()
        error_message = None
    except requests.RequestException:
        data = {
            'alerts': [],
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'pagination': {'current_page': page, 'total_pages': 1, 'total_alerts': 0}
        }
        error_message = "Failed to fetch high alerts."

    alerts = data.get('alerts', [])
    pagination = data.get('pagination', {})
    summary = data.get('summary', {})

    current = pagination.get('current_page', page)
    total = pagination.get('total_pages', 1)

    start = max(2, current - 2)
    end = min(total - 1, current + 2)
    page_numbers = list(range(start, end + 1)) if total > 1 else []

    show_left_ellipsis = start > 2
    show_right_ellipsis = end < total - 1

    return render(request, 'dashboard/high_alerts.html', {
        'alerts': alerts,
        'summary': summary,
        'pagination': pagination,
        'page_numbers': page_numbers,
        'show_left_ellipsis': show_left_ellipsis,
        'show_right_ellipsis': show_right_ellipsis,
        'error_message': error_message,
    })

def moderate_view(request):
    API_URL = 'https://3ecf-46-152-4-125.ngrok-free.app/alerts'
    page = int(request.GET.get('page', 1))

    try:
        resp = requests.get(
            API_URL,
            params={'page': page, 'severity': 'medium'},
            headers={
                'ngrok-skip-browser-warning': '1',
                'Accept': 'application/json'
            },
            timeout=5
        )
        resp.raise_for_status()
        data = resp.json()
        error_message = None
    except requests.RequestException:
        data = {
            'alerts': [],
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'pagination': {'current_page': page, 'total_pages': 1, 'total_alerts': 0}
        }
        error_message = "Failed to fetch moderate alerts."

    alerts = data.get('alerts', [])
    pagination = data.get('pagination', {})
    summary = data.get('summary', {})

    current = pagination.get('current_page', page)
    total = pagination.get('total_pages', 1)

    start = max(2, current - 2)
    end = min(total - 1, current + 2)
    page_numbers = list(range(start, end + 1)) if total > 1 else []

    show_left_ellipsis = start > 2
    show_right_ellipsis = end < total - 1

    return render(request, 'dashboard/moderate_alerts.html', {
        'alerts': alerts,
        'summary': summary,
        'pagination': pagination,
        'page_numbers': page_numbers,
        'show_left_ellipsis': show_left_ellipsis,
        'show_right_ellipsis': show_right_ellipsis,
        'error_message': error_message,
    })


def low_view(request):
    page = int(request.GET.get("page", 1))
    url = "https://3ecf-46-152-4-125.ngrok-free.app/alerts"

    try:
        response = requests.get(
            url,
            params={"page": page, "severity": "low"},
            headers={"ngrok-skip-browser-warning": "1"},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        error_message = None
    except Exception:
        data = {"alerts": [], "summary": {}, "pagination": {"current_page": 1, "total_pages": 1, "total_alerts": 0}}
        error_message = "Failed to fetch low alerts."

    alerts = data.get("alerts", [])
    summary = data.get("summary", {})
    pagination = data.get("pagination", {"current_page": 1, "total_pages": 1})
    alert_count = summary.get("low", 0)

    current = pagination.get("current_page", page)
    total = pagination.get("total_pages", 1)

    start = max(2, current - 2)
    end = min(total - 1, current + 2)
    page_numbers = list(range(start, end + 1)) if total > 1 else []

    show_left_ellipsis = start > 2
    show_right_ellipsis = end < total - 1

    context = {
        "alerts": alerts,
        "alert_count": alert_count,
        "pagination": pagination,
        "page_numbers": page_numbers,
        "show_left_ellipsis": show_left_ellipsis,
        "show_right_ellipsis": show_right_ellipsis,
        "error_message": error_message,
    }

    return render(request, 'dashboard/low_alerts.html', context)


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
    ltime = datetime.fromisoformat(agent["agent"]["lastCheckin"]).replace(tzinfo=timezone.utc)
    agent["agent"]["lastCheckin"] = ltime
    print(agent)
    return render(request, 'dashboard/agent_detail.html', {'agent': agent})

def report(request):
    API_URL = "https://3ecf-46-152-4-125.ngrok-free.app/agents"
    
    try:
        response = requests.get(API_URL, headers={"ngrok-skip-browser-warning": "1"}, timeout=5)
        response.raise_for_status()
        data = response.json()
        agents = data.get("agents", [])

        # Ensure datetime objects are parsed for humanize
        for agent in agents:
            if "last_checkin" in agent and agent["last_checkin"]:
                dt = parse_datetime(agent["last_checkin"])
                if dt is not None:
                    agent["last_checkin"] = dt.replace(tzinfo=timezone.utc)

    except requests.RequestException:
        agents = []
    return render(request, 'dashboard/report.html',{'agents':agents})

def generate_base64_chart(fig):
    buffer = BytesIO()
    fig.savefig(buffer, format='png', bbox_inches='tight')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    buffer.close()
    plt.close(fig)
    return image_base64

def export_agent_report(request, agent_id):
    api_url = f"https://3ecf-46-152-4-125.ngrok-free.app/agent/{agent_id}"

    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        agent_data = response.json()
    except requests.RequestException:
        return HttpResponse("Failed to fetch agent data", status=500)

    # Convert lastCheckin to datetime
    checkin = agent_data["agent"].get("lastCheckin")
    if checkin:
        parsed = parse_datetime(checkin)
        if parsed:
            agent_data["agent"]["lastCheckin"] = parsed

    # Create threat detection chart
    threat_data = agent_data["threatDetection"]["timeline"]
    fig1 = plt.figure(figsize=(6, 3))
    plt.plot(threat_data["labels"], threat_data["critical"], label='Critical', color='red')
    plt.plot(threat_data["labels"], threat_data["high"], label='High', color='orange')
    plt.plot(threat_data["labels"], threat_data["medium"], label='Medium', color='blue')
    plt.plot(threat_data["labels"], threat_data["low"], label='Low', color='green')
    plt.title('Threat Detection Timeline')
    plt.xlabel('Date')
    plt.ylabel('Alerts')
    plt.legend()
    plt.tight_layout()
    threat_chart = generate_base64_chart(fig1)

    # Create network activity chart
    net_data = agent_data["networkActivity"]
    fig2 = plt.figure(figsize=(6, 3))
    plt.plot(net_data["labels"], net_data["inboundMB"], label='Inbound MB', color='blue')
    plt.plot(net_data["labels"], net_data["outboundMB"], label='Outbound MB', color='purple')
    plt.title('Network Activity Over Time')
    plt.xlabel('Time')
    plt.ylabel('MB Transferred')
    plt.xticks(rotation=45, ha='right')  # rotate labels and align them properly
    plt.legend()
    plt.tight_layout()
    network_chart = generate_base64_chart(fig2)

    # Render template
    timestamp = now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f'{agent_id}_report_{timestamp}.pdf'
    template = get_template("dashboard/report_template.html")
    html = template.render({
        "agent": agent_data,
        "threat_chart": threat_chart,
        "network_chart": network_chart
    })

    # Generate PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    pisa_status = pisa.CreatePDF(html, dest=response)
    if pisa_status.err:
        return HttpResponse("Error generating PDF", status=500)
    return response

def multi_agent_report(request):
    selected_ids = request.POST.getlist("agents")
    if not selected_ids:
        return HttpResponse("No agents selected", status=400)

    try:
        overview = requests.get("https://3ecf-46-152-4-125.ngrok-free.app/overview").json()
        charts = requests.get("https://3ecf-46-152-4-125.ngrok-free.app/charts").json()

        # Rename conflicting key in overview before merging
        overview["overview_alerts"] = overview.pop("security_alerts")

        # Merge the two dictionaries
        merged = {**charts, **overview}
    except Exception:
        return HttpResponse("Error fetching API data", status=500)

    charts_images = {}

    # Internet Usage
    fig1, ax1 = plt.subplots()
    ax1.plot(merged["internet_usage"]["labels"], merged["internet_usage"]["total_traffic_mb"])
    ax1.set_title("Internet Usage")
    ax1.set_ylabel("MB")
    ax1.set_ylim(bottom=0)
    ax1.tick_params(axis='x', rotation=45)
    charts_images["internet_usage"] = generate_base64_chart(fig1)

    # Resource Usage
    fig2, ax2 = plt.subplots()
    ax2.plot(merged["resource_usage"]["labels"], merged["resource_usage"]["cpu_usage_percent"], label="CPU")
    ax2.plot(merged["resource_usage"]["labels"], merged["resource_usage"]["ram_usage_percent"], label="Memory")
    ax2.plot(merged["resource_usage"]["labels"], merged["resource_usage"]["disk_usage_percent"], label="Disk")
    ax2.set_title("Resource Usage")
    ax2.set_ylim(bottom=0)
    ax2.set_ylabel("%")
    ax2.legend()
    ax2.tick_params(axis='x', rotation=45)
    charts_images["resource_usage"] = generate_base64_chart(fig2)

    # User Activity
    fig3, ax3 = plt.subplots()
    ax3.bar(merged["user_activity"]["labels"], merged["user_activity"]["counts"])
    ax3.set_title("User Activity (Last 30 Days)")
    ax3.set_ylim(bottom=0)
    ax3.tick_params(axis='x', rotation=45)
    fig3.tight_layout()
    charts_images["user_activity"] = generate_base64_chart(fig3)

    # Security Alerts (from CHARTS)
    fig4, ax4 = plt.subplots()
    ax4.bar(merged["security_alerts"]["labels"], merged["security_alerts"]["counts"], color='tomato')
    ax4.set_ylim(bottom=0)
    ax4.set_title("Security Alerts")
    charts_images["security_alerts"] = generate_base64_chart(fig4)

    # Network Distribution (Radar)
    from math import pi
    labels = merged["network_distribution"]["labels"]
    values = merged["network_distribution"]["packet_counts_by_source_continent"]
    values += values[:1]
    angles = [n / float(len(labels)) * 2 * pi for n in range(len(labels))]
    angles += angles[:1]
    fig5, ax5 = plt.subplots(subplot_kw=dict(polar=True))
    ax5.plot(angles, values, linewidth=2)
    ax5.fill(angles, values, alpha=0.4)
    ax5.set_xticks(angles[:-1])
    ax5.set_xticklabels(labels)
    ax5.set_title("Network Distribution")
    charts_images["network_distribution"] = generate_base64_chart(fig5)

    # Attacks Distribution
    fig6, ax6 = plt.subplots()
    ax6.barh(merged["region_distribution"]["labels"], merged["region_distribution"]["incident_counts"])
    ax6.set_xlim(left=0)
    ax6.set_title("Attacks Distribution")
    charts_images["attacks_distribution"] = generate_base64_chart(fig6)

    # Network Protocol Distribution
    fig7, ax7 = plt.subplots()
    ax7.ticklabel_format(style='plain', axis='y')
    ax7.bar(merged["network_protocols"]["labels"], merged["network_protocols"]["data"],color='blue')
    ax7.set_ylim(bottom=0)
    ax7.set_title("Network Protocol Usage")
    charts_images["protocol_distribution"] = generate_base64_chart(fig7)

    # Fetch individual agents and generate their charts
    agents = []
    for agent_id in selected_ids:
        res = requests.get(f"https://3ecf-46-152-4-125.ngrok-free.app/agent/{agent_id}")
        if res.status_code == 200:
            a = res.json()
            if "lastCheckin" in a["agent"]:
                parsed = parse_datetime(a["agent"]["lastCheckin"])
                if parsed:
                    a["agent"]["lastCheckin"] = parsed

            # Generate Threat Detection Chart
            if "threatDetection" in a and "timeline" in a["threatDetection"]:
                timeline = a["threatDetection"]["timeline"]
                labels = timeline["labels"]
                x = range(len(labels))  # Base positions for groups

                width = 0.2  # Width of each bar

                fig_threat, ax_threat = plt.subplots()
                ax_threat.bar([i - 1.5*width for i in x], timeline["critical"], width=width, label="Critical", color="darkred")
                ax_threat.bar([i - 0.5*width for i in x], timeline["high"], width=width, label="High", color="orangered")
                ax_threat.bar([i + 0.5*width for i in x], timeline["medium"], width=width, label="Medium", color="gold")
                ax_threat.bar([i + 1.5*width for i in x], timeline["low"], width=width, label="Low", color="lightgreen")

                ax_threat.set_title("Threat Detection Timeline")
                ax_threat.set_xticks(x)
                ax_threat.set_xticklabels(labels, rotation=45)
                ax_threat.legend()
                fig_threat.tight_layout()

                a["threat_chart"] = generate_base64_chart(fig_threat)
            else:
                a["threat_chart"] = ""


            # Generate Network Activity Chart
            if "networkActivity" in a:
                net = a["networkActivity"]
                fig_net, ax_net = plt.subplots()
                
                ax_net.plot(net["labels"], net["inboundMB"], label="Inbound", color="blue")
                ax_net.plot(net["labels"], net["outboundMB"], label="Outbound", color="green")

                ax_net.set_title("Network Activity")
                ax_net.set_ylabel("MB")
                ax_net.tick_params(axis='x', rotation=45)
                ax_net.legend()
                fig_net.tight_layout()

                a["network_chart"] = generate_base64_chart(fig_net)
            else:
                a["network_chart"] = ""


            agents.append(a)

    context = {
        "charts": charts_images,
        "overview": merged,
        "timestamp": now().strftime("%Y-%m-%d %H:%M"),
        "agents": agents,
    }

    html = get_template("dashboard/multi_agents_report_template.html").render(context)
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="multi_agent_report_{context["timestamp"]}.pdf"'
    pisa.CreatePDF(io.StringIO(html), dest=response)
    return response

def realtime_network_api(request):
    try:
        res = requests.get("https://3ecf-46-152-4-125.ngrok-free.app/overview", timeout=5)
        data = res.json()
        return JsonResponse(data["realtime_network"])
    except Exception:
        return JsonResponse({"usage_kb": 0})
    
def agent_realtime_network(request, agent_id):
    api_url = f"https://3ecf-46-152-4-125.ngrok-free.app/agent/{agent_id}"

    try:
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()
        data = response.json()
        return JsonResponse({
            "usage_mb": data.get("realtime_network", {}).get("usage_mb", 0)
        })
    except Exception as e:
        return JsonResponse({"usage_mb": 0, "error": str(e)}, status=500)
