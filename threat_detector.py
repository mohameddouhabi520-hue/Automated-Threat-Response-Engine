# Fichier : threat_detector.py
# Description : Moteur de détection de menaces et de réponse automatisée

import json
import time
import logging
from collections import defaultdict
from datetime import datetime
from typing import List, Dict

# Configuration du système de journalisation (Logging) comme dans un vrai SOC
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [SEC-OPS] - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)

class AutomatedResponseEngine:
    """
    Simulates automated actions taken by a SOAR (Security Orchestration, Automation, and Response) platform.
    """
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip_address: str, reason: str):
        """Simulates blocking an IP at the WAF or Firewall level (e.g., AWS WAF, Cloudflare)."""
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            logging.warning(f"ACTION TRIGGERED: Blocking IP {ip_address} at Firewall level. Reason: {reason}")
            # In a real scenario, this would be an API call to a Firewall/WAF:
            # requests.post("https://api.firewall.local/v1/block", json={"ip": ip_address})

    def send_slack_alert(self, alert_data: dict):
        """Simulates sending an alert to a Security Operations Slack channel."""
        logging.critical(f"ALERT SENT TO SOC TEAM: {json.dumps(alert_data)}")


class ThreatDetector:
    """
    Parses authentication logs and detects brute-force or credential stuffing attacks.
    """
    def __init__(self, failure_threshold: int = 5, time_window_seconds: int = 60):
        self.failure_threshold = failure_threshold
        self.time_window_seconds = time_window_seconds
        # Stores failed attempts: { 'ip_address': [timestamp1, timestamp2, ...] }
        self.failed_attempts = defaultdict(list)
        self.response_engine = AutomatedResponseEngine()

    def parse_logs(self, log_file_path: str):
        """Reads JSON structured logs line by line."""
        logging.info(f"Starting log ingestion from {log_file_path}...")
        try:
            with open(log_file_path, 'r') as file:
                logs = json.load(file)
                for log_entry in logs:
                    self.analyze_event(log_entry)
                    time.sleep(0.5) # Simulated delay for real-time processing feel
        except FileNotFoundError:
            logging.error(f"Log file {log_file_path} not found.")

    def analyze_event(self, event: Dict):
        """Analyzes a single security event."""
        ip_address = event.get("ip_address")
        status = event.get("status")
        timestamp_str = event.get("timestamp")
        
        # Convert ISO 8601 string to timestamp
        event_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()

        logging.info(f"Analyzing event: User {event.get('user')} from {ip_address} - Status: {status}")

        if status == "FAILED":
            self.failed_attempts[ip_address].append(event_time)
            self._check_threshold(ip_address, event_time)

    def _check_threshold(self, ip_address: str, current_time: float):
        """Checks if the failures for an IP exceed the threshold within the time window."""
        # Keep only recent failures within the time window
        recent_failures = [
            t for t in self.failed_attempts[ip_address] 
            if current_time - t <= self.time_window_seconds
        ]
        self.failed_attempts[ip_address] = recent_failures

        # If failures exceed the threshold, trigger incident response
        if len(recent_failures) >= self.failure_threshold:
            alert_payload = {
                "incident": "Brute-Force Attack Detected",
                "severity": "HIGH",
                "source_ip": ip_address,
                "failed_attempts": len(recent_failures),
                "time_window_secs": self.time_window_seconds
            }
            logging.error(f"THREAT DETECTED: Multiple failed logins from {ip_address}!")
            self.response_engine.send_slack_alert(alert_payload)
            self.response_engine.block_ip(ip_address, reason="Exceeded failed login threshold")
            
            # Clear history for this IP to avoid alert spamming after blocking
            self.failed_attempts[ip_address] = []

if __name__ == "__main__":
    # Initialize the detector: Alert if 4 failed logins occur within 60 seconds
    detector = ThreatDetector(failure_threshold=4, time_window_seconds=60)
    
    # Run the detector on our simulated log file
    detector.parse_logs("sample_logs.json")
```eof

```json
[
    {
        "timestamp": "2026-09-10T10:00:01Z",
        "ip_address": "192.168.1.50",
        "user": "admin",
        "event_type": "login",
        "status": "SUCCESS"
    },
    {
        "timestamp": "2026-09-10T10:01:15Z",
        "ip_address": "45.33.22.11",
        "user": "j.doe",
        "event_type": "login",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-09-10T10:01:20Z",
        "ip_address": "45.33.22.11",
        "user": "root",
        "event_type": "login",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-09-10T10:01:25Z",
        "ip_address": "45.33.22.11",
        "user": "admin",
        "event_type": "login",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-09-10T10:01:27Z",
        "ip_address": "10.0.0.5",
        "user": "m.douhabi",
        "event_type": "login",
        "status": "SUCCESS"
    },
    {
        "timestamp": "2026-09-10T10:01:30Z",
        "ip_address": "45.33.22.11",
        "user": "administrator",
        "event_type": "login",
        "status": "FAILED"
    },
    {
        "timestamp": "2026-09-10T10:02:00Z",
        "ip_address": "45.33.22.11",
        "user": "test",
        "event_type": "login",
        "status": "FAILED"
    }
]
```eof

```markdown
# Cloud-Native Automated Threat Detection & Response Engine

![Python Version](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Security](https://img.shields.io/badge/Security-Ops-red.svg)
![Build](https://img.shields.io/badge/Status-Operational-brightgreen.svg)

## 📌 Overview
This project is a lightweight, Python-based Security Information and Event Management (SIEM) and SOAR (Security Orchestration, Automation, and Response) engine. It was developed to demonstrate modern **Security Operations (SecOps)** practices, specifically tailored towards real-time log ingestion, threshold-based threat detection, and automated incident remediation.

In fast-paced fintech or SaaS environments, manual log review is insufficient. This engine automates the detection of brute-force attacks and credential stuffing, immediately isolating the threat without requiring human intervention.

## 🚀 Core Features
- **Real-Time Log Ingestion:** Parses JSON-structured authentication logs.
- **Dynamic Threshold Detection:** Identifies malicious behavior based on temporal correlation (e.g., X failed attempts within Y seconds from a single IP).
- **Automated Remediation (SOAR):** Simulates dynamic Firewall/WAF API calls to isolate and block attacking IP addresses instantly.
- **Incident Alerting:** Generates structured JSON alert payloads designed for integration with SOC communication channels (Slack, Jira, PagerDuty).

## 🛠️ Technical Architecture
1. `ThreatDetector`: The core engine that processes events, normalizes timestamps (ISO 8601), and evaluates behavior against security thresholds using efficient memory tracking (`collections.defaultdict`).
2. `AutomatedResponseEngine`: The remediation component that acts on alerts. It tracks blocked entities to prevent alert fatigue and redundant API calls.

## 💻 How to Run
No external dependencies are required. The script uses Python's standard library to ensure maximum compatibility.

1. Clone this repository.
2. Ensure you have Python 3.9+ installed.
3. Run the engine:
   
```bash
   python threat_detector.py
