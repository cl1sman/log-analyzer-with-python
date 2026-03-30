import re
from collections import Counter

LOG_FILE = "access.log"

# Regex pattern for Combined Log Format:
# <ip> <logname> <user> [<timestamp>] "<method> <endpoint> <protocol>" <status> <size>
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[.*?\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d{3}) \S+'
)

SUSPICIOUS_ENDPOINTS = {"/admin", "/login"}


def parse_log(filepath):
    """Parse log file and return a list of extracted fields."""
    entries = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                match = LOG_PATTERN.match(line)
                if match:
                    entries.append({
                        "ip": match.group("ip"),
                        "method": match.group("method"),
                        "endpoint": match.group("endpoint"),
                        "status": match.group("status"),
                    })
    except FileNotFoundError:
        print(f"Error: Log file '{filepath}' not found.")
        raise
    except IOError as e:
        print(f"Error reading log file '{filepath}': {e}")
        raise
    return entries


def most_active_ips(entries, top_n=5):
    """Return the top N most active IP addresses."""
    ip_counts = Counter(entry["ip"] for entry in entries)
    return ip_counts.most_common(top_n)


def suspicious_requests(entries):
    """Return entries that accessed suspicious endpoints."""
    return [e for e in entries if e["endpoint"] in SUSPICIOUS_ENDPOINTS]


def status_code_summary(entries):
    """Return a count of each HTTP status code."""
    status_counts = Counter(entry["status"] for entry in entries)
    return dict(sorted(status_counts.items()))


def print_report(entries):
    """Print a formatted analysis report."""
    print("=" * 50)
    print("         LOG ANALYSIS REPORT")
    print("=" * 50)

    print(f"\nTotal requests parsed: {len(entries)}\n")

    print("--- Top 5 Most Active IPs ---")
    for ip, count in most_active_ips(entries):
        print(f"  {ip}: {count} requests")

    print("\n--- HTTP Status Code Summary ---")
    for status, count in status_code_summary(entries).items():
        print(f"  {status}: {count} occurrences")

    suspicious = suspicious_requests(entries)
    print(f"\n--- Suspicious Endpoint Requests ({len(suspicious)} total) ---")
    for entry in suspicious:
        print(f"  [{entry['status']}] {entry['method']} {entry['endpoint']} from {entry['ip']}")

    print("\n" + "=" * 50)


if __name__ == "__main__":
    entries = parse_log(LOG_FILE)
    print_report(entries)
