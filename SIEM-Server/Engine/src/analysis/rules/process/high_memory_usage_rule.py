from Engine.src.config.config import HIGH_MEMORY_THRESHOLD

def HIGH_MEMORY_USAGE_RULE(log):
    memory_usage = log.get("process", {}).get("working_set", 0)
    
    if int(memory_usage) > HIGH_MEMORY_THRESHOLD:
        return f"High memory usage detected: {int(memory_usage) / (1024 * 1024):.2f} MB"
    
    return None