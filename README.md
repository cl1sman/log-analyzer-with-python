# Log Analyzer (Python)

This project is a simple log analysis tool built in Python to parse, filter, and analyze web server logs.

## Features
- Extract IP addresses, endpoints, and status codes
- Identify most active IPs
- Detect suspicious endpoints (e.g., /admin, /login)
- Simple and readable output

## Technologies
- Python
- Regex
- Collections (Counter)

## How to Run
```bash
python analyzer.py
```

## Data Source

The log file used in this project was obtained from a public dataset:

- https://github.com/elastic/examples
- https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs

This dataset contains sample Apache logs for testing and educational purposes
