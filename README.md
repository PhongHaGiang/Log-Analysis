# Log-Analysis

A Python-based log analysis tool that detects brute-force attacks by analyzing authentication logs. The tool identifies multiple failed login attempts from the same IP address within a specified time window and generates detailed reports.

## Features

- **Multi-format Support**: Parses SSH logs, web server logs (Apache/Nginx), and JSON-formatted logs
- **Configurable Detection**: Customizable thresholds for failed attempts and time windows
- **Severity Classification**: Automatically categorizes attacks as LOW, MEDIUM, HIGH, or CRITICAL
- **Detailed Reports**: Generates comprehensive reports with attack details including:
  - Source IP addresses
  - Number of failed attempts
  - Time windows of attacks
  - Targeted usernames
  - Severity levels
- **JSON Output**: Optional JSON output for integration with other tools

## Installation

No external dependencies required! The tool uses Python's standard library.

```bash
git clone https://github.com/PhongHaGiang/Log-Analysis.git
cd Log-Analysis
```

## Usage

### Basic Usage

Analyze a log file with default settings (5 failed attempts in 10 minutes):

```bash
python log_analyzer.py sample_logs/auth.log
```

### Custom Thresholds

Set custom detection thresholds:

```bash
# Detect 10 failed attempts within 5 minutes
python log_analyzer.py sample_logs/auth.log --threshold 10 --window 5

# More sensitive detection: 3 attempts within 2 minutes
python log_analyzer.py sample_logs/auth.log --threshold 3 --window 2
```

### JSON Output

Get results in JSON format for programmatic processing:

```bash
python log_analyzer.py sample_logs/auth.log --json
```

### Command Line Options

```
usage: log_analyzer.py [-h] [-t THRESHOLD] [-w WINDOW] [-j] log_file

positional arguments:
  log_file              Path to the log file to analyze

optional arguments:
  -h, --help            Show this help message and exit
  -t THRESHOLD, --threshold THRESHOLD
                        Number of failed attempts to trigger alert (default: 5)
  -w WINDOW, --window WINDOW
                        Time window in minutes (default: 10)
  -j, --json            Output results in JSON format
```

## Supported Log Formats

### 1. SSH Authentication Logs (auth.log)

```
Dec 10 06:55:48 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2
```

### 2. Web Server Logs (Apache/Nginx)

```
192.168.1.100 - - [10/Dec/2023:06:55:48 +0000] "POST /login HTTP/1.1" 401 512
```

### 3. JSON Format

```json
{"timestamp": "2023-12-10T06:55:48", "ip": "192.168.1.100", "user": "admin", "status": "failed"}
```

## Examples

### Example 1: SSH Log Analysis

```bash
$ python log_analyzer.py sample_logs/auth.log

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

Attack #2
--------------------------------------------------------------------------------
Source IP: 10.0.0.50
Severity: MEDIUM
Failed attempts: 8
Time window: 2024-12-10T08:20:10 to 2024-12-10T08:20:24
Targeted usernames: user1, user2, user3, user4, user5, user6, user7, user8
```

### Example 2: Web Server Log Analysis

```bash
$ python log_analyzer.py sample_logs/access.log --threshold 5 --window 10
```

### Example 3: JSON Output

```bash
$ python log_analyzer.py sample_logs/app.log --json
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

## Configuration

The `config.json` file allows you to customize detection settings:

```json
{
  "detection_settings": {
    "failed_attempts_threshold": 5,
    "time_window_minutes": 10,
    "severity_levels": {
      "low": 5,
      "medium": 5,
      "high": 10,
      "critical": 20
    }
  }
}
```

## How It Works

1. **Log Parsing**: The tool reads and parses log files line by line, extracting:
   - Timestamp
   - Source IP address
   - Username (if available)
   - Authentication status

2. **Attack Detection**: For each IP address, the tool:
   - Collects all failed login attempts
   - Checks for consecutive failures within the time window
   - Triggers an alert if the threshold is exceeded

3. **Severity Assessment**: Based on the number of failed attempts:
   - **LOW**: 5-9 attempts
   - **MEDIUM**: 5-9 attempts (configurable)
   - **HIGH**: 10-19 attempts
   - **CRITICAL**: 20+ attempts

4. **Report Generation**: Creates a detailed report with all detected attacks

## Use Cases

- **Security Monitoring**: Identify ongoing brute-force attacks in real-time
- **Log Analysis**: Analyze historical logs to find past attack patterns
- **Incident Response**: Quickly identify malicious IP addresses
- **Compliance**: Document security events for audit purposes
- **Integration**: Use JSON output to feed data into SIEM systems

## Sample Data

The repository includes sample log files in the `sample_logs/` directory:
- `auth.log` - SSH authentication logs with brute-force attempts
- `access.log` - Web server logs with authentication failures
- `app.log` - JSON-formatted application logs

## Requirements

- Python 3.6 or higher
- No external dependencies

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

PhongHaGiang

## Security Note

This tool is designed for legitimate security monitoring purposes. Always ensure you have proper authorization before analyzing logs or monitoring systems.