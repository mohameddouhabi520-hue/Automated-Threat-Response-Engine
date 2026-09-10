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
