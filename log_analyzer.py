#!/usr/bin/env python3
"""
Log Analysis Tool for Brute-Force Attack Detection

This script analyzes authentication logs to detect potential brute-force attacks
by identifying multiple failed login attempts from the same IP address within a time window.
"""

import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple
import argparse


class BruteForceDetector:
    """Detects brute-force attacks in authentication logs."""
    
    def __init__(self, failed_attempts_threshold=5, time_window_minutes=10):
        """
        Initialize the detector.
        
        Args:
            failed_attempts_threshold: Number of failed attempts to trigger alert
            time_window_minutes: Time window in minutes to check for failed attempts
        """
        self.failed_attempts_threshold = failed_attempts_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        self.failed_attempts = defaultdict(list)  # IP -> list of timestamps
        self.alerts = []
        
    def parse_log_line(self, line: str) -> Tuple[datetime, str, str, str]:
        """
        Parse a log line to extract timestamp, IP, username, and status.
        
        Supports common log formats:
        - SSH logs (Linux auth.log)
        - Apache/Nginx access logs
        - Custom application logs
        
        Returns:
            Tuple of (timestamp, ip, username, status)
        """
        # SSH log format: Dec 10 06:55:48 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2
        ssh_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*(?:Failed password|authentication failure).*from\s+(\d+\.\d+\.\d+\.\d+)'
        
        # Apache/Nginx format with auth failure: 192.168.1.100 - - [10/Dec/2023:06:55:48 +0000] "POST /login" 401
        web_pattern = r'(\d+\.\d+\.\d+\.\d+).*\[([^\]]+)\].*POST.*(?:/login|/auth).*\s(401|403)'
        
        # Custom JSON format: {"timestamp": "2023-12-10T06:55:48", "ip": "192.168.1.100", "user": "admin", "status": "failed"}
        if line.strip().startswith('{'):
            try:
                data = json.loads(line)
                timestamp = datetime.fromisoformat(data.get('timestamp', '').replace('Z', '+00:00'))
                return timestamp, data.get('ip', ''), data.get('user', 'unknown'), data.get('status', '')
            except (json.JSONDecodeError, ValueError):
                pass
        
        # Try SSH pattern
        ssh_match = re.search(ssh_pattern, line)
        if ssh_match:
            time_str = ssh_match.group(1)
            ip = ssh_match.group(2)
            # Parse timestamp (assuming current year)
            try:
                timestamp = datetime.strptime(f"{datetime.now().year} {time_str}", "%Y %b %d %H:%M:%S")
            except ValueError:
                timestamp = datetime.now()
            
            # Extract username if present
            user_match = re.search(r'for\s+(\w+)\s+from', line)
            username = user_match.group(1) if user_match else 'unknown'
            
            return timestamp, ip, username, 'failed'
        
        # Try web log pattern
        web_match = re.search(web_pattern, line)
        if web_match:
            ip = web_match.group(1)
            time_str = web_match.group(2)
            status = web_match.group(3)
            
            try:
                timestamp = datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                timestamp = datetime.now()
            
            # Extract username from POST data if available
            user_match = re.search(r'user(?:name)?[=:](\w+)', line)
            username = user_match.group(1) if user_match else 'unknown'
            
            return timestamp, ip, username, 'failed'
        
        return None, None, None, None
    
    def analyze_log_file(self, log_file_path: str) -> List[Dict]:
        """
        Analyze a log file for brute-force attacks.
        
        Args:
            log_file_path: Path to the log file
            
        Returns:
            List of detected brute-force attacks
        """
        print(f"Analyzing log file: {log_file_path}")
        
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                timestamp, ip, username, status = self.parse_log_line(line)
                
                if timestamp and ip and status in ['failed', 'fail', '401', '403']:
                    self.failed_attempts[ip].append({
                        'timestamp': timestamp,
                        'username': username,
                        'line_num': line_num
                    })
        
        # Detect brute-force attacks
        self._detect_attacks()
        
        return self.alerts
    
    def _detect_attacks(self):
        """Detect brute-force attacks based on failed login attempts."""
        for ip, attempts in self.failed_attempts.items():
            # Sort attempts by timestamp
            attempts.sort(key=lambda x: x['timestamp'])
            
            # Check for consecutive failed attempts within time window
            for i in range(len(attempts)):
                window_attempts = []
                start_time = attempts[i]['timestamp']
                
                for j in range(i, len(attempts)):
                    if attempts[j]['timestamp'] <= start_time + self.time_window:
                        window_attempts.append(attempts[j])
                    else:
                        break
                
                if len(window_attempts) >= self.failed_attempts_threshold:
                    # Brute-force attack detected
                    usernames = set(attempt['username'] for attempt in window_attempts)
                    
                    alert = {
                        'ip': ip,
                        'failed_attempts': len(window_attempts),
                        'time_window_start': window_attempts[0]['timestamp'].isoformat(),
                        'time_window_end': window_attempts[-1]['timestamp'].isoformat(),
                        'targeted_usernames': list(usernames),
                        'severity': self._calculate_severity(len(window_attempts))
                    }
                    
                    # Avoid duplicate alerts for the same attack
                    if not any(a['ip'] == ip and a['time_window_start'] == alert['time_window_start'] 
                              for a in self.alerts):
                        self.alerts.append(alert)
                    break  # Move to next IP after finding first attack
    
    def _calculate_severity(self, attempt_count: int) -> str:
        """Calculate severity level based on number of attempts."""
        if attempt_count >= 20:
            return 'CRITICAL'
        elif attempt_count >= 10:
            return 'HIGH'
        elif attempt_count >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_report(self) -> str:
        """Generate a human-readable report of detected attacks."""
        if not self.alerts:
            return "No brute-force attacks detected."
        
        report = f"\n{'='*80}\n"
        report += f"BRUTE-FORCE ATTACK DETECTION REPORT\n"
        report += f"{'='*80}\n\n"
        report += f"Total attacks detected: {len(self.alerts)}\n"
        report += f"Detection threshold: {self.failed_attempts_threshold} failed attempts in {self.time_window.seconds // 60} minutes\n\n"
        
        for idx, alert in enumerate(self.alerts, 1):
            report += f"Attack #{idx}\n"
            report += f"{'-'*80}\n"
            report += f"Source IP: {alert['ip']}\n"
            report += f"Severity: {alert['severity']}\n"
            report += f"Failed attempts: {alert['failed_attempts']}\n"
            report += f"Time window: {alert['time_window_start']} to {alert['time_window_end']}\n"
            report += f"Targeted usernames: {', '.join(alert['targeted_usernames'])}\n"
            report += f"\n"
        
        return report


def main():
    """Main function to run the log analyzer."""
    parser = argparse.ArgumentParser(
        description='Detect brute-force attacks in authentication logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py auth.log
  python log_analyzer.py auth.log --threshold 10 --window 5
  python log_analyzer.py auth.log --json
        """
    )
    
    parser.add_argument('log_file', help='Path to the log file to analyze')
    parser.add_argument('-t', '--threshold', type=int, default=5,
                        help='Number of failed attempts to trigger alert (default: 5)')
    parser.add_argument('-w', '--window', type=int, default=10,
                        help='Time window in minutes (default: 10)')
    parser.add_argument('-j', '--json', action='store_true',
                        help='Output results in JSON format')
    
    args = parser.parse_args()
    
    # Create detector and analyze log file
    detector = BruteForceDetector(
        failed_attempts_threshold=args.threshold,
        time_window_minutes=args.window
    )
    
    try:
        alerts = detector.analyze_log_file(args.log_file)
        
        if args.json:
            print(json.dumps(alerts, indent=2))
        else:
            print(detector.generate_report())
            
    except FileNotFoundError:
        print(f"Error: Log file '{args.log_file}' not found.")
        return 1
    except Exception as e:
        print(f"Error analyzing log file: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
