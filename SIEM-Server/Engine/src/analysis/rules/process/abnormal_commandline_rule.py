from Engine.src.config.config import SUSPICIOUS_KEYWORDS


def ABNORMAL_COMMANDLINE_RULE(log):
    suspicious_keywords = SUSPICIOUS_KEYWORDS
    command_line = log.get("process", {}).get("command_line", "")
    
    for keyword in suspicious_keywords:
        if keyword in command_line:
            return f"Suspicious command line argument found: {keyword}"
    
    return None
