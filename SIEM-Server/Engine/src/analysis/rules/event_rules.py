from .category import CATEGORY

rules = [
    # Malware & Defender Events
    { "id": "malware_scan_stopped", "event_id": "1002", "description": "Malware scan stopped before completing scan", "alert": "Moderate", "category": CATEGORY["malware"] },
    { "id": "malware_scan_paused", "event_id": "1003", "description": "Malware scan paused", "alert": "Low", "category": CATEGORY["malware"] },
    { "id": "malware_scan_failed", "event_id": "1005", "description": "Malware scan failed", "alert": "Moderate", "category": CATEGORY["malware"] },
    { "id": "malware_detected", "event_id": "1006", "description": "Malware or unwanted software detected", "alert": "High", "category": CATEGORY["malware"] },
    { "id": "unwanted_software_detected", "event_id": "1116", "description": "Malware or unwanted software detected", "alert": "High", "category": CATEGORY["malware"] },
    { "id": "protection_action_performed", "event_id": "1007", "description": "Action to protect system performed", "alert": "Moderate", "category": CATEGORY["malware"] },
    { "id": "protection_action_performed_2", "event_id": "1117", "description": "Action to protect system performed", "alert": "Moderate", "category": CATEGORY["malware"] },
    { "id": "protection_action_failed", "event_id": "1008", "description": "Action to protect system failed", "alert": "High", "category": CATEGORY["malware"] },
    { "id": "protection_action_failed_2", "event_id": "1118", "description": "Action to protect system failed", "alert": "High", "category": CATEGORY["malware"] },
    { "id": "restored_from_quarantine", "event_id": "1009", "description": "Item restored from quarantine", "alert": "Moderate", "category": CATEGORY["malware"] },
    { "id": "delete_quarantine_failed", "event_id": "1012", "description": "Unable to delete item in quarantine", "alert": "Moderate", "category": CATEGORY["malware"] },
    { "id": "suspicious_behavior_detected", "event_id": "1015", "description": "Suspicious behavior detected", "alert": "High", "category": CATEGORY["malware"] },
    { "id": "critical_protection_error", "event_id": "1119", "description": "Critical error occurred when taking action", "alert": "Critical", "category": CATEGORY["malware"] },

    # PowerShell Events
    { "id": "powershell_module_logging", "event_id": "4103", "description": "PowerShell Module Logging", "alert": "Low", "category": CATEGORY["powershell"] },
    { "id": "powershell_scriptblock_logging", "event_id": "4104", "description": "PowerShell Script Block Logging", "alert": "Moderate", "category": CATEGORY["powershell"] },

    # Object Access / File Handling Events
    { "id": "object_access_request", "event_id": "4656", "description": "Request to handle or access an object", "alert": "Low", "category": CATEGORY["object_access"] },
    { "id": "object_handle_closed", "event_id": "4658", "description": "Handle to an object was closed", "alert": "Low", "category": CATEGORY["object_access"] },
    { "id": "object_handle_delete_request", "event_id": "4659", "description": "Handle to an object requested with intent to delete", "alert": "Moderate", "category": CATEGORY["object_access"] },
    { "id": "object_deleted", "event_id": "4660", "description": "Object deleted", "alert": "Moderate", "category": CATEGORY["object_access"] },
    { "id": "object_access_attempt", "event_id": "4663", "description": "Attempt to access object was made", "alert": "Low", "category": CATEGORY["object_access"] },
    { "id": "hard_link_creation_attempt", "event_id": "4664", "description": "Attempt to create a hard link was made", "alert": "Moderate", "category": CATEGORY["object_access"] },
    { "id": "object_permissions_changed", "event_id": "4670", "description": "Object permissions were changed", "alert": "Moderate", "category": CATEGORY["object_access"] },

    # Privilege-Related Events
    { "id": "special_privilege_assigned", "event_id": "4672", "description": "Special Privileges Assigned to New Logon", "alert": "High", "category": CATEGORY["privilege_use"] },
    { "id": "privileged_service_called", "event_id": "4673", "description": "Calling privileged service", "alert": "High", "category": CATEGORY["privilege_use"] },
    { "id": "privileged_object_operation", "event_id": "4674", "description": "Attempted operation on a privileged object", "alert": "High", "category": CATEGORY["privilege_use"] },

    # Other Security-Relevant Events
    { "id": "transaction_state_change", "event_id": "4985", "description": "Transaction state change", "alert": "Low", "category": CATEGORY["object_access"] },
    { "id": "indirect_object_access", "event_id": "4691", "description": "Indirect access to an object was requested", "alert": "Low", "category": CATEGORY["object_access"] },

    # Scheduled Task Events
    { "id": "task_created", "event_id": "4698", "description": "A scheduled task was created", "alert": "Moderate", "category": CATEGORY["scheduled_tasks"] },
    { "id": "task_deleted", "event_id": "4699", "description": "A scheduled task was deleted", "alert": "Moderate", "category": CATEGORY["scheduled_tasks"] },
    { "id": "task_enabled", "event_id": "4700", "description": "A scheduled task was enabled", "alert": "Low", "category": CATEGORY["scheduled_tasks"] },
    { "id": "task_disabled", "event_id": "4701", "description": "A scheduled task was disabled", "alert": "Low", "category": CATEGORY["scheduled_tasks"] },
    { "id": "task_updated", "event_id": "4702", "description": "A scheduled task was updated", "alert": "Moderate", "category": CATEGORY["scheduled_tasks"] },

    # File Virtualization Event
    { "id": "file_virtualized", "event_id": "5051", "description": "File was virtualized", "alert": "Low", "category": CATEGORY["object_access"] },
]
