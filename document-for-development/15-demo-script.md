# Demo Script

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-DEMO-001

Presentation Length: 90 Seconds

Team Size: 4 Members

---

# Purpose

This document defines the official demonstration flow for NetGuard.

Objectives

- Clearly present the problem
- Demonstrate real-time detection
- Showcase explainability
- Highlight automatic prevention
- Leave judges with a memorable ending

---

# Demo Environment

Presenter Laptop

- Ubuntu 24.04
- NetGuard Running
- Dashboard Open
- Browser Full Screen

Attack Laptop

- Kali Linux
- Connected to same network
- Attack scripts prepared

Network

- Local Wi-Fi or Ethernet
- No Internet Required

---

# Pre-Demo Checklist

☐ Dashboard open

☐ Monitoring active

☐ Database connected

☐ Packet counter increasing

☐ Kali VM ready

☐ Attack commands tested

☐ Browser fullscreen

☐ Backup demo video available

---

# Team Roles

## Member 1

Role

Opening + Problem Statement

---

## Member 2

Role

Technical Demonstration

---

## Member 3

Role

Explainability & Dashboard

---

## Member 4

Role

Closing + Future Vision + Q&A

---

# 90 Second Timeline

| Time | Activity |
|--------|----------|
|0–15 sec|Problem|
|15–30 sec|Introduce NetGuard|
|30–60 sec|Live Attack Demo|
|60–75 sec|Explainability Panel|
|75–90 sec|Closing|

---

# Opening (0–15 Seconds)

### Member 1

> Every day, schools and small businesses face cyber threats but cannot afford enterprise security solutions. Existing open-source tools are powerful but difficult to understand, especially for non-experts. NetGuard bridges that gap by providing an affordable, explainable intrusion detection and prevention system that runs entirely on a standard laptop.

---

# Solution Overview (15–30 Seconds)

### Member 2

> NetGuard continuously monitors live network traffic using Scapy, detects malicious behavior through configurable detection rules, automatically blocks attackers using the Linux firewall, and most importantly explains every security decision in plain language.

Point to dashboard.

Show

- Monitoring Active

- Live Packet Counter

- Traffic Graph

---

# Live Attack (30–60 Seconds)

### Member 2

Run

```bash
hping3 -S --flood TARGET_IP
```

Dashboard should display

- Packet spike

- Alert notification

- New threat

- Automatic block

Say

> We have just launched a SYN Flood attack from another machine. Within seconds NetGuard detects abnormal behavior, evaluates the threat, and automatically blocks the attacker.

---

# Explainability (60–75 Seconds)

### Member 3

Open Evidence Panel.

Show

- Source IP

- Rule Triggered

- Packet Count

- Confidence

- Severity

- Recommendation

Say

> Unlike traditional intrusion detection systems, NetGuard doesn't simply tell you that an attack happened. It explains exactly why the decision was made, what evidence was collected, how confident the system is, and what action should be taken next.

---

# Closing (75–90 Seconds)

### Member 4

> NetGuard is lightweight, offline-first, open for future expansion, and designed for organizations that cannot afford enterprise security tools. Our roadmap includes machine-learning anomaly detection, threat intelligence integration, and multi-node monitoring. We believe cybersecurity should be accessible, understandable, and affordable.

Pause.

Smile.

Say

> Thank you.

---

# Demonstration Flow

```
Monitoring

↓

Launch Attack

↓

Traffic Spike

↓

Threat Detection

↓

Automatic Block

↓

Evidence Display

↓

Recommendation

↓

Questions
```

---

# Visual Checklist

Dashboard should visibly show

✓ Monitoring Active

✓ Live Packet Counter

✓ Traffic Graph

✓ Threat Notification

✓ Evidence Panel

✓ Blocked IP

✓ Confidence Score

✓ Severity

---

# Recommended Attack Order

Primary

1. SYN Flood

Secondary

2. Port Scan

Optional

3. SQL Injection

Avoid demonstrating more than two attack types within the 90-second presentation.

---

# Backup Plan

If packet capture fails

- Play pre-recorded demo video
- Continue explanation using recorded output

If firewall blocking fails

- Show detection and evidence
- Explain that blocking is disabled for safety in the demo environment

If dashboard disconnects

- Restart frontend
- Continue using backend logs if necessary

---

# Judge Questions & Suggested Answers

## Q: Why not use Snort or Suricata?

A:

They are powerful but require significant expertise to configure and interpret. NetGuard focuses on explainability and ease of deployment for smaller organizations.

---

## Q: What makes this different?

A:

Explainability. Every alert includes evidence, severity, confidence, and recommendations in plain language rather than just a rule ID.

---

## Q: Can it scale?

A:

Yes. The architecture is modular and can be extended with distributed sensors, cloud dashboards, threat intelligence feeds, and machine-learning detection.

---

## Q: How do you reduce false positives?

A:

Through configurable thresholds, cooldown periods, whitelist support, and confidence scoring.

---

## Q: Why Flask instead of Django?

A:

Flask is lightweight, easier to deploy locally, and sufficient for a hackathon prototype focused on real-time networking.

---

## Q: Why SQLite?

A:

SQLite is lightweight, portable, requires no setup, and is ideal for an offline demonstration.

---

# Presentation Tips

- Speak clearly and confidently.
- Let the dashboard update before talking about the alert.
- Avoid reading directly from slides.
- Keep explanations concise.
- Make eye contact with judges.
- Practice timing until consistently under 90 seconds.

---

# Success Criteria

The demo is successful if judges clearly observe:

✓ Live packet monitoring

✓ Real-time attack detection

✓ Automatic IP blocking

✓ Explainable evidence

✓ Professional dashboard

✓ Smooth team coordination

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial Demo Script |

---

End of Document