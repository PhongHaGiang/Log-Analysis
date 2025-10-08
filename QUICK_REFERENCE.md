# Quick Reference Guide

## Quick Start

```bash
# Analyze a log file
python log_analyzer.py sample_logs/auth.log

# Custom detection threshold
python log_analyzer.py sample_logs/auth.log --threshold 3 --window 5

# Get JSON output
python log_analyzer.py sample_logs/auth.log --json
```

## Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--threshold` | `-t` | Failed attempts to trigger alert | 5 |
| `--window` | `-w` | Time window in minutes | 10 |
| `--json` | `-j` | Output results in JSON format | false |
| `--help` | `-h` | Show help message | - |

## Severity Levels

| Level | Failed Attempts | Description |
|-------|----------------|-------------|
| LOW | 5-9 | Minor brute-force attempt |
| MEDIUM | 5-9 | Moderate brute-force attack |
| HIGH | 10-19 | Serious brute-force attack |
| CRITICAL | 20+ | Critical brute-force attack |

## Supported Log Formats

### SSH (auth.log)
```
Dec 10 06:55:48 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2
```

### Web Server (Apache/Nginx)
```
192.168.1.100 - - [10/Dec/2023:06:55:48 +0000] "POST /login HTTP/1.1" 401 512
```

### JSON
```json
{"timestamp": "2023-12-10T06:55:48", "ip": "192.168.1.100", "user": "admin", "status": "failed"}
```

## Common Use Cases

### Monitor SSH attacks
```bash
python log_analyzer.py /var/log/auth.log
```

### Monitor web login attempts
```bash
python log_analyzer.py /var/log/nginx/access.log
```

### Sensitive detection (3 attempts in 2 minutes)
```bash
python log_analyzer.py auth.log --threshold 3 --window 2
```

### Integration with monitoring tools
```bash
python log_analyzer.py auth.log --json | jq '.[] | select(.severity == "CRITICAL")'
```

## Testing

Run the test suite:
```bash
python run_tests.py
```

## Output Examples

### Human-Readable Report
```
================================================================================
BRUTE-FORCE ATTACK DETECTION REPORT
================================================================================

Total attacks detected: 2
Detection threshold: 5 failed attempts in 10 minutes

Attack #1
--------------------------------------------------------------------------------
Source IP: 192.168.1.100
Severity: HIGH
Failed attempts: 7
Time window: 2024-12-10T06:55:48 to 2024-12-10T06:56:02
Targeted usernames: admin, root, user, test
```

### JSON Output
```json
[
  {
    "ip": "192.168.1.100",
    "failed_attempts": 7,
    "time_window_start": "2023-12-10T06:55:48",
    "time_window_end": "2023-12-10T06:56:02",
    "targeted_usernames": ["admin", "root", "user", "test"],
    "severity": "HIGH"
  }
]
```

## Tips

1. **Regular Monitoring**: Run the analyzer periodically on your log files
2. **Adjust Thresholds**: Tune detection based on your environment
3. **Combine with Firewall**: Use detected IPs to update firewall rules
4. **Alert Integration**: Pipe JSON output to monitoring systems
5. **Historical Analysis**: Analyze old logs to find patterns

## Troubleshooting

### No attacks detected
- Check if log format is supported
- Lower the threshold: `--threshold 3`
- Increase time window: `--window 30`

### Too many false positives
- Increase threshold: `--threshold 10`
- Decrease time window: `--window 5`

### Log file not found
- Ensure you have read permissions
- Check the file path is correct
- Use absolute paths if needed
