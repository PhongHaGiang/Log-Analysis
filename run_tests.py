#!/usr/bin/env python3
"""
Test script for the brute-force detection log analyzer.
"""

import subprocess
import json
import sys


def run_test(description, command):
    """Run a test command and display results."""
    print(f"\n{'='*80}")
    print(f"TEST: {description}")
    print(f"{'='*80}")
    print(f"Command: {command}")
    print(f"{'-'*80}")
    
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(result.stdout)
        print(f"✓ TEST PASSED")
    else:
        print(f"✗ TEST FAILED")
        print(f"Error: {result.stderr}")
        return False
    
    return True


def main():
    """Run all tests."""
    print("Starting Log Analyzer Tests...")
    
    tests = [
        ("SSH log analysis with default settings", 
         "python3 log_analyzer.py sample_logs/auth.log"),
        
        ("Web server log analysis",
         "python3 log_analyzer.py sample_logs/access.log"),
        
        ("JSON log analysis with JSON output",
         "python3 log_analyzer.py sample_logs/app.log --json"),
        
        ("Custom threshold (3 attempts in 5 minutes)",
         "python3 log_analyzer.py sample_logs/auth.log --threshold 3 --window 5"),
        
        ("High threshold (10 attempts in 10 minutes)",
         "python3 log_analyzer.py sample_logs/auth.log --threshold 10 --window 10"),
    ]
    
    passed = 0
    failed = 0
    
    for description, command in tests:
        if run_test(description, command):
            passed += 1
        else:
            failed += 1
    
    print(f"\n{'='*80}")
    print(f"TEST SUMMARY")
    print(f"{'='*80}")
    print(f"Total tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failed == 0:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {failed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
