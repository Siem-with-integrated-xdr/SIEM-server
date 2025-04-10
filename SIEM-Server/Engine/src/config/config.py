# Engine/src/config/config.py

# Abnormal Command Line Rule
SUSPICIOUS_KEYWORDS = ["--eval", "--exec", "-e", "base64"]

# High Memory Usage Rule
HIGH_MEMORY_THRESHOLD = 50 * 1024 * 1024  # 50MB threshold

# Multiple Threads Rule
MAX_THREAD_COUNT = 100  # Threshold for thread count
