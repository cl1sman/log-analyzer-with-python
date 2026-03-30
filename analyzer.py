import re
from collections import Counter

log_file = "access.log"

pattern = r'(\d+\.\d+\.\d+\.\d+).*(\[.*]).*"(GET|POST|PUT|DELETE) (.*?) HTTP.*" (\d{3})'

ips = []
timestamp = []
method = []
endpoints = []
status_code = []

suspicious_keywords = ["admin", "login", "wp", "config", "backup"]

with open('access.log', 'r') as f:
    lines = f.readlines()

    for line in lines:
        match = re.search(pattern, line)

        if match:
            ips.append(match.group(1))
            timestamp.append(match.group(2))
            method.append(match.group(3))
            endpoints.append(match.group(4))
            status_code.append(match.group(5))

# Analysis
top_ips = Counter(ips).most_common(5)
top_endpoints = Counter(endpoints).most_common(5)
top_status_code = Counter(status_code).most_common(5)
