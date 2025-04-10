
def SUSPICIOUS_PATH_RULE(log):
    #if log.get("category") != "PROCESS":
    #  return None

    process = log.get("process", {})
    name = process.get("name", "")
    path = process.get("path", "")

    if name and not path.startswith("C:\\Program Files"):
        return {
            "rule_name": "Suspicious Process Path",
            "severity": "medium",
            "details": f"{name} executed from {path}"
        }
    return None
