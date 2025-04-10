from .suspicious_path_rule import SUSPICIOUS_PATH_RULE
from .abnormal_commandline_rule import ABNORMAL_COMMANDLINE_RULE
from .high_memory_usage_rule import HIGH_MEMORY_USAGE_RULE
from .multiable_threads_rule import MULTIPLE_THREADS_RULE

PROCESS_RULES = [
    SUSPICIOUS_PATH_RULE,
    ABNORMAL_COMMANDLINE_RULE,
    HIGH_MEMORY_USAGE_RULE,
    MULTIPLE_THREADS_RULE
]
