from Engine.src.config.config import MAX_THREAD_COUNT

def MULTIPLE_THREADS_RULE(log):
    thread_count = log.get("process", {}).get("thread_count", 0)
    
    if thread_count > MAX_THREAD_COUNT:
        return f"Unusual thread count detected: {thread_count}"
    
    return None