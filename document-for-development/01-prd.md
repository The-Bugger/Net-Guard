# Product Requirements Document (PRD)

# NetGuard
### Explainable Intrusion Detection & Prevention System

Version: 1.0

Prepared For:
MVIC Build Nepal Hackathon 2026

Prepared By:
Team NetGuard

---

# 1. Executive Summary

NetGuard is an enterprise-inspired Intrusion Detection and Prevention System (IDPS) designed to provide affordable cybersecurity for schools, colleges, startups, and small businesses.

Unlike traditional IDS solutions that simply block suspicious traffic, NetGuard explains every security decision in plain language, enabling non-security professionals to understand what happened, why it happened, and how the system responded.

The entire system runs locally without requiring cloud infrastructure, making it suitable for environments with limited internet connectivity and low hardware resources.

---

# 2. Problem Statement

Small organizations often lack dedicated cybersecurity infrastructure due to the high cost and complexity of enterprise security products.

Common challenges include:

- Expensive commercial IDS/IPS solutions
- Difficult installation and configuration
- No visibility into detected threats
- Limited understanding of attack causes
- No explainable security decisions
- Dependence on cloud services

These limitations leave educational institutions and small organizations vulnerable to common cyber attacks.

---

# 3. Vision

To build a lightweight, explainable, and affordable intrusion detection platform that anyone can deploy on a standard laptop while providing enterprise-like visibility into network attacks.

---

# 4. Mission

Provide real-time network monitoring, automatic threat detection, intelligent blocking, and understandable security explanations without requiring expensive hardware or cloud subscriptions.

---

# 5. Goals

Primary Goals

• Detect common network attacks in real time.

• Automatically block malicious IP addresses.

• Explain every security decision.

• Visualize attacks through a live dashboard.

• Operate completely offline.

• Be deployable by non-experts.

Secondary Goals

• Reduce false positives.

• Support customizable rules.

• Produce detailed incident logs.

• Generate professional reports.

---

# 6. Target Users

Primary Users

- Schools
- Colleges
- Small Businesses
- Local Organizations
- Startups

Secondary Users

- Students
- Security Researchers
- Network Administrators
- Hackathon Demonstrations

---

# 7. Scope

Included

✔ Live Packet Capture

✔ Intrusion Detection

✔ Automatic Blocking

✔ Dashboard

✔ Evidence Panel

✔ Severity Rating

✔ Logging

✔ Whitelist Management

✔ Explainable Decisions

✔ Local Deployment

Not Included

✘ Cloud Synchronization

✘ Machine Learning Detection

✘ Distributed IDS

✘ Multi-node Correlation

✘ SIEM Integration

These features are planned for future releases.

---

# 8. Key Features

## Real-Time Packet Monitoring

Continuously monitor incoming and outgoing network traffic.

---

## Threat Detection

Detect attacks including:

- SYN Flood
- Port Scan
- SQL Injection
- Brute Force Login
- ARP Spoofing

---

## Automatic Prevention

Automatically block malicious IP addresses using Linux firewall rules.

Temporary blocks automatically expire after the configured duration.

---

## Explainability Engine

Every detection includes:

- Detection reason
- Triggered rule
- Supporting evidence
- Packet statistics
- Severity level
- Recommended action

---

## Dashboard

Provide:

- Live Traffic
- Active Threats
- Blocked IPs
- Network Statistics
- Historical Events
- Detection Timeline

---

## Logging

Store all security events with timestamps and supporting evidence.

---

## Whitelist

Trusted IP addresses bypass automatic blocking while remaining visible in monitoring logs.

---

# 9. Success Metrics

The project will be considered successful if it achieves:

- Detects all supported attacks
- Blocks attacks within seconds
- Generates understandable explanations
- Displays live dashboard updates
- Completes the demonstration without failures
- Operates entirely offline

---

# 10. Functional Objectives

The system shall:

- Capture packets continuously
- Analyze packet behavior
- Detect attack signatures
- Assign threat severity
- Block malicious IPs
- Record security logs
- Display live statistics
- Explain every detection
- Support whitelist rules
- Automatically remove expired blocks

---

# 11. Non-Functional Objectives

Performance

- Low CPU usage
- Low memory usage
- Fast detection

Reliability

- Continuous monitoring
- Automatic recovery
- Stable operation

Security

- Secure logging
- Protected configuration
- Privileged operations only where required

Maintainability

- Modular architecture
- Clear documentation
- Easy rule updates

Scalability

- Support additional detection rules
- Future cloud deployment
- Future ML integration

---

# 12. Constraints

- Linux operating system required
- Python runtime required
- Administrative privileges required for firewall operations
- Local network access required for demonstrations
- Runs on standard student hardware

---

# 13. Assumptions

- Network traffic is accessible.
- Firewall commands are permitted.
- Users have basic Linux knowledge.
- Attack simulations occur within a controlled environment.

---

# 14. Risks

Potential risks include:

- False positives
- Packet loss under heavy traffic
- Firewall permission issues
- Interface selection errors
- Demo network instability

Mitigation strategies will be documented separately.

---

# 15. Future Enhancements

Future versions may include:

- AI-based anomaly detection
- Threat intelligence integration
- MITRE ATT&CK mapping
- Email alerts
- Mobile application
- Multi-device monitoring
- Cloud dashboard
- PDF incident reports
- Role-based authentication

---

# 16. Project Deliverables

The project will deliver:

- Detection Engine
- Prevention Engine
- Flask Backend
- Web Dashboard
- Explainability Engine
- Logging System
- Whitelist Manager
- Demonstration Toolkit
- Documentation
- Source Code

---

# 17. Hackathon Demonstration

The live demonstration will showcase:

1. System startup

2. Live packet monitoring

3. Attack launch

4. Detection

5. Automatic blocking

6. Evidence generation

7. Dashboard updates

8. Attack history

9. Explainability panel

10. Successful prevention

The complete demonstration is designed to finish within 90 seconds.

---

# 18. Conclusion

NetGuard demonstrates that enterprise-grade intrusion detection does not require expensive infrastructure.

By combining packet inspection, automatic response, explainable decision-making, and an intuitive dashboard, NetGuard delivers a practical cybersecurity solution suitable for educational institutions and small organizations while remaining simple enough to deploy on a standard laptop.