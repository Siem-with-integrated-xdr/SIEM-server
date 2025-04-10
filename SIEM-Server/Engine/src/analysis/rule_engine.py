from Engine.src.analysis.rules.event_rules import rules
from Engine.src.analysis.rules.process import PROCESS_RULES

# Event processing function
def process_event(event_data):
    alerts = []
    
    # Iterate through each rule
    for rule in rules:
        event_id = rule.get('event_id')
        description = rule.get('description')
        alert_level = rule.get('alert')
        category = rule.get('category')

        # Check if the event matches the rule by event_id
        if event_data.get("event_id") == event_id:
            # For each matched rule, check the condition
            alert_message = f"Alert: {description}, Severity: {alert_level}, Category: {category}"
            
            # Check rule conditions (example check)
            if rule.get('id') == "malware_scan_failed" and event_data.get("status") == "failed":
                alerts.append(alert_message)
            elif rule.get('id') == "task_created" and event_data.get("task_name") == "suspicious_task":
                alerts.append(alert_message)
            # Add other condition checks as needed

    # Return all collected alerts
    return alerts

# Example Event Data to simulate processing
event_data = {
    "event_id": "1005",
    "status": "failed",
    "task_name": "suspicious_task",
}

# Running the event through the engine
alerts = process_event(event_data)

# Print the alerts
print(*alerts,sep='\n')



def apply_rules(log):
    alerts = []
    if log.get("category") == "process":
        for rule in PROCESS_RULES:
            result = rule(log)  # Apply the rule function to the log
            if result:
                alerts.append(result)
    print(*alerts,sep='\n')


process_data = {
	"timestamp":	"2025-04-09 22:45:47.264995",
	"category":	"process",
	"process":	{
		"pid":	29560,
		"ppid":	26880,
		"name":	"docker.exe",
		"path":	"C:\\Program\\Docker\\Docker\\resources\\bin\\docker.exe",
		"command_line":	"\"C:\\Program\\Docker\\Docker\\resources\\bin\\docker.exe\" base64 --all --no-trunc --no-stream --format \"{{ json .}}\"",
		"working_set":	"199999999999999999999",
		"thread_count":	150,
		"owner":	"LAPTOP-RQFSGLS1\\MD_55",
		"kernel_time":	0.109375,
		"user_time":	0.03125,
		"module_count":	12
	}
}
apply_rules(process_data)