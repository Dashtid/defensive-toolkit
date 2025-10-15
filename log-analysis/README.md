# Log Analysis & Anomaly Detection

Automated log parsing, normalization, and anomaly detection tools for security log analysis.

## Overview

This category provides tools for:
- **Universal Log Parser**: Parse syslog, JSON, Apache/Nginx, Windows Event Logs
- **Field Extraction**: Normalize logs into structured data
- **Anomaly Detection**: Statistical and pattern-based anomaly detection
- **Baseline Deviation**: Detect unusual activity patterns
- **Pattern Matching**: Find security-relevant patterns in logs
- **Log Correlation**: Connect related log entries

## Directory Structure

```
log-analysis/
├── parsers/                     # Log parsing and normalization
│   ├── log-parser.py           # Universal log parser (multiple formats)
│   └── windows-event-parser.py # Windows Event Log parser
└── analysis/                    # Log analysis and detection
    ├── anomaly-detector.py     # Statistical anomaly detection
    └── pattern-matcher.py      # Pattern matching and correlation
```

## Quick Start

### Parse Logs

```bash
# Auto-detect format and parse
python log-analysis/parsers/log-parser.py --file /var/log/syslog --format auto

# Parse Apache access log
python log-analysis/parsers/log-parser.py --file access.log --format apache --output parsed.json

# Parse JSON logs
python log-analysis/parsers/log-parser.py --file app.log --format json

# Parse syslog
python log-analysis/parsers/log-parser.py --file /var/log/messages --format syslog
```

### Detect Anomalies

```bash
# Create baseline from historical logs
python log-analysis/analysis/anomaly-detector.py \\
    --create-baseline \\
    --input historical-logs.json \\
    --output baseline.json

# Detect anomalies in current logs
python log-analysis/analysis/anomaly-detector.py \\
    --detect \\
    --input current-logs.json \\
    --baseline baseline.json \\
    --output anomalies.txt

# Detect without baseline (pattern-based only)
python log-analysis/analysis/anomaly-detector.py \\
    --detect \\
    --input logs.json
```

## Universal Log Parser

### Supported Formats

1. **Syslog (RFC 3164/5424)**
   ```
   Oct 15 10:30:25 server1 sshd[1234]: Failed password for root from 192.168.1.100
   ```

2. **JSON**
   ```json
   {"timestamp": "2025-10-15T10:30:25Z", "level": "error", "message": "Login failed"}
   ```

3. **Apache Combined Log**
   ```
   192.168.1.100 - - [15/Oct/2025:10:30:25 +0000] "GET /admin HTTP/1.1" 401 1234
   ```

4. **Nginx**
   ```
   192.168.1.100 - - [15/Oct/2025:10:30:25 +0000] "POST /api/login" 403 567
   ```

5. **Windows Event Log** (via windows-event-parser.py)

### Structured Output

All logs are normalized to this structure:

```python
{
    "timestamp": "2025-10-15T10:30:25",
    "hostname": "server1",
    "process": "sshd",
    "pid": 1234,
    "severity": "error",
    "message": "Failed password for root",
    "source_ip": "192.168.1.100",
    "dest_ip": None,
    "user": "root",
    "event_id": None,
    "raw": "..."  # Original log line
}
```

### Usage Examples

#### Parse Multiple Formats

```bash
# Parse syslog
python log-parser.py --file /var/log/auth.log --format syslog --output auth-parsed.json

# Parse web server logs
python log-parser.py --file /var/log/nginx/access.log --format nginx --output web-parsed.json

# Parse application JSON logs
python log-parser.py --file /var/log/app/application.json --format json --output app-parsed.json
```

#### Filter During Parsing

```bash
# Parse and filter for specific keyword
python log-parser.py \\
    --file /var/log/syslog \\
    --format auto \\
    --filter "failed" \\
    --output failed-logins.json

# Parse limited number of lines
python log-parser.py --file large.log --format auto --max-lines 10000
```

#### Python API

```python
from log_analysis.parsers.log_parser import LogParser

# Create parser
parser = LogParser(log_format='auto')

# Parse single line
entry = parser.parse_line("Oct 15 10:30:25 server1 sshd[1234]: Failed password")

# Parse entire file
entries = parser.parse_file('/var/log/syslog')

# Convert to dict
for entry in entries:
    print(entry.to_dict())
```

## Anomaly Detection

### Detection Methods

1. **Frequency-Based**: Detect unusually frequent events
2. **Pattern-Based**: Identify failure bursts and suspicious patterns
3. **Statistical**: Compare against baseline using standard deviation
4. **Rate-Based**: Detect unusual activity rates by time

### Anomaly Types Detected

- **High Frequency**: Processes or IPs appearing too often
- **Failure Bursts**: Clustering of error/failure events
- **Statistical Deviations**: Activity exceeding baseline by threshold
- **Process Spikes**: Sudden increase in process activity
- **Rate Anomalies**: Unusual event rates per hour

### Creating Baselines

```bash
# Parse historical logs first
python parsers/log-parser.py --file /var/log/syslog.1 --output historical.json

# Create baseline from 7 days of logs
cat day{1..7}-logs.json | python analysis/anomaly-detector.py \\
    --create-baseline \\
    --input /dev/stdin \\
    --output 7day-baseline.json
```

### Detecting Anomalies

```bash
# Parse current logs
python parsers/log-parser.py --file /var/log/syslog --output current.json

# Detect anomalies
python analysis/anomaly-detector.py \\
    --detect \\
    --input current.json \\
    --baseline 7day-baseline.json \\
    --threshold 2.0 \\
    --output-format text \\
    --output anomalies.txt
```

### Anomaly Report Example

```
================================================================================
Log Anomaly Detection Report
================================================================================
Timestamp: 2025-10-15T12:00:00
Anomalies Detected: 5

HIGH SEVERITY ANOMALIES
--------------------------------------------------------------------------------

[!] High Frequency IP
    Source IP "192.168.1.50" appears 2,345 times (45.2%)
    ip: 192.168.1.50
    count: 2345
    frequency: 0.45

[!] Failure Burst
    Burst of "failed" events detected
    keyword: failed
    count: 127
    avg_gap: 3.2

MEDIUM SEVERITY ANOMALIES
--------------------------------------------------------------------------------

[!] Process Spike
    Process "apache2" activity is 4.2x above baseline
    process: apache2
    baseline: 120
    current: 504
    ratio: 4.20
```

### Adjusting Detection Threshold

```bash
# More sensitive (1 std dev)
python anomaly-detector.py --detect --input logs.json --threshold 1.0

# Less sensitive (3 std devs)
python anomaly-detector.py --detect --input logs.json --threshold 3.0

# Default (2 std devs)
python anomaly-detector.py --detect --input logs.json --threshold 2.0
```

## Pattern Matching

### Common Security Patterns

The pattern matcher can identify:
- Failed authentication attempts
- Privilege escalation attempts
- Suspicious file access
- Network scanning activity
- Data exfiltration indicators
- Command injection attempts
- SQL injection patterns

### Pattern Definitions

```python
patterns = {
    'failed_ssh': r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
    'sudo_usage': r'sudo:.* COMMAND=(.*)$',
    'port_scan': r'Connection attempt from (\d+\.\d+\.\d+\.\d+) port \d+ repeated',
    'privilege_escalation': r'USER=root.* COMMAND=',
}
```

## End-to-End Workflow

### 1. Collect and Parse Logs

```bash
# Parse various log sources
python parsers/log-parser.py --file /var/log/auth.log --format syslog --output auth.json
python parsers/log-parser.py --file /var/log/apache2/access.log --format apache --output web.json
python parsers/log-parser.py --file /var/log/app.json --format json --output app.json

# Combine parsed logs
jq -s 'add' auth.json web.json app.json > all-logs.json
```

### 2. Baseline Creation (First Time)

```bash
# Create baseline from first week of operation
python analysis/anomaly-detector.py \\
    --create-baseline \\
    --input all-logs.json \\
    --output baseline.json
```

### 3. Daily Anomaly Detection

```bash
#!/bin/bash
# daily-log-analysis.sh

DATE=$(date +%Y-%m-%d)

# Parse today's logs
python parsers/log-parser.py \\
    --file /var/log/syslog \\
    --format syslog \\
    --output today-$DATE.json

# Detect anomalies
python analysis/anomaly-detector.py \\
    --detect \\
    --input today-$DATE.json \\
    --baseline baseline.json \\
    --output anomalies-$DATE.txt

# Alert if anomalies found
if [ $? -ne 0 ]; then
    echo "Anomalies detected on $DATE" | mail -s "Log Anomalies" security@company.com
fi
```

### 4. Update Baseline (Monthly)

```bash
# Recreate baseline from last 30 days
cat logs-{01..30}.json | python analysis/anomaly-detector.py \\
    --create-baseline \\
    --input /dev/stdin \\
    --output baseline-$(date +%Y%m).json
```

## Integration with Detection Rules

### Convert Anomalies to Sigma Rules

```python
# Example: Convert detected anomaly to Sigma rule
anomaly = {
    "type": "high_frequency_ip",
    "ip": "192.168.1.50",
    "count": 2345
}

# Generate Sigma rule
sigma_rule = f"""
title: Suspicious High-Frequency Activity from {anomaly['ip']}
status: experimental
logsource:
    category: authentication
detection:
    selection:
        src_ip: {anomaly['ip']}
    timeframe: 1h
    condition: selection | count() > 100
level: high
"""
```

## Integration with SIEM

### Forward Parsed Logs to SIEM

```bash
# Parse and forward to Elasticsearch
python log-parser.py --file /var/log/syslog --format syslog --output - | \\
    curl -XPOST 'localhost:9200/logs/_bulk' --data-binary @-

# Parse and forward to Splunk
python log-parser.py --file /var/log/syslog --format syslog --output - | \\
    splunk add oneshot -
```

### Send Anomaly Alerts to SIEM

```bash
# Detect anomalies and send to SIEM
python anomaly-detector.py \\
    --detect \\
    --input current.json \\
    --baseline baseline.json \\
    --output-format json | \\
    curl -XPOST 'siem.company.com/api/alerts' --data-binary @-
```

## Log Sources and Collection

### Linux Log Locations

```bash
# System logs
/var/log/syslog          # General system logs
/var/log/auth.log        # Authentication logs
/var/log/kern.log        # Kernel logs
/var/log/daemon.log      # Daemon logs

# Application logs
/var/log/apache2/        # Apache web server
/var/log/nginx/          # Nginx web server
/var/log/mysql/          # MySQL database
/var/log/postgresql/     # PostgreSQL database

# Security logs
/var/log/audit/audit.log # Auditd logs
/var/log/fail2ban.log    # Fail2ban logs
```

### Windows Log Locations

```powershell
# Event logs (via Event Viewer)
Application           # Application events
Security              # Security events
System                # System events
Setup                 # Setup/installation events

# File locations
C:\Windows\System32\winevt\Logs\
```

### Centralized Log Collection

```bash
# Configure rsyslog to forward logs
cat >> /etc/rsyslog.conf <<EOF
*.* @@logserver.company.com:514
EOF
service rsyslog restart

# Configure syslog-ng to forward logs
cat >> /etc/syslog-ng/syslog-ng.conf <<EOF
destination d_logserver { network("logserver.company.com" port(514)); };
log { source(s_src); destination(d_logserver); };
EOF
service syslog-ng restart
```

## Best Practices

### Log Management

1. **Retention**: Keep at least 90 days of logs for analysis
2. **Rotation**: Use logrotate to prevent disk fills
3. **Compression**: Compress old logs to save space
4. **Centralization**: Forward logs to central log server
5. **Parsing**: Parse logs as close to real-time as possible

### Baseline Management

1. **Initial Baseline**: Create from 7-14 days of normal activity
2. **Regular Updates**: Update baseline monthly or after major changes
3. **Multiple Baselines**: Maintain baselines for different environments
4. **Version Control**: Track baseline changes over time
5. **Validation**: Verify baseline represents normal activity

### Anomaly Detection

1. **Threshold Tuning**: Adjust threshold to reduce false positives
2. **Context Awareness**: Consider time of day, day of week
3. **Whitelisting**: Exclude known-good anomalies
4. **Alert Prioritization**: Focus on high-severity anomalies first
5. **Investigation**: Always investigate detected anomalies

### Performance Optimization

1. **Incremental Parsing**: Parse new logs only, not entire files
2. **Parallel Processing**: Process multiple log files in parallel
3. **Sampling**: Sample large log volumes for anomaly detection
4. **Filtering**: Filter irrelevant logs early in pipeline
5. **Caching**: Cache parsed logs for repeated analysis

## Troubleshooting

### Common Issues

**Parser Not Detecting Format**:
```bash
# Explicitly specify format
python log-parser.py --file unknown.log --format syslog
```

**Memory Issues with Large Files**:
```bash
# Limit lines processed
python log-parser.py --file huge.log --max-lines 100000

# Process in chunks
split -l 50000 huge.log chunk-
for f in chunk-*; do
    python log-parser.py --file $f --output $f.json
done
```

**Timestamp Parsing Failures**:
```bash
# Check log format
head -5 /var/log/syslog

# Try different format
python log-parser.py --file /var/log/syslog --format auto --verbose
```

**High False Positive Rate**:
```bash
# Increase threshold
python anomaly-detector.py --detect --input logs.json --threshold 3.0

# Create better baseline
python anomaly-detector.py --create-baseline --input longer-history.json
```

## Examples

### Example 1: SSH Brute Force Detection

```bash
# Parse auth logs
python parsers/log-parser.py --file /var/log/auth.log --format syslog --output auth.json

# Detect anomalies (will catch unusual login attempts)
python analysis/anomaly-detector.py --detect --input auth.json --output brute-force.txt

# Look for high-frequency source IPs
grep "high_frequency_ip" brute-force.txt
```

### Example 2: Web Application Attack Detection

```bash
# Parse web server logs
python parsers/log-parser.py --file access.log --format apache --output web.json

# Detect unusual request patterns
python analysis/anomaly-detector.py --detect --input web.json --baseline web-baseline.json
```

### Example 3: Insider Threat Detection

```bash
# Parse user activity logs
python parsers/log-parser.py --file /var/log/audit/audit.log --format syslog --output audit.json

# Detect unusual user behavior
python analysis/anomaly-detector.py \\
    --detect \\
    --input audit.json \\
    --baseline user-baseline.json \\
    --threshold 1.5  # More sensitive for insider threats
```

## Additional Resources

- Syslog RFC 3164: https://tools.ietf.org/html/rfc3164
- Syslog RFC 5424: https://tools.ietf.org/html/rfc5424
- Apache Log Format: https://httpd.apache.org/docs/current/logs.html
- Windows Event Logs: https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging

---

**Last Updated**: 2025-10-15
**Maintainer**: Defensive Toolkit
**License**: MIT
