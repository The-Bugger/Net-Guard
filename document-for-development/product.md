# Product Steering

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

---

# Product Vision

NetGuard is an explainable Intrusion Detection and Prevention System (IDPS) designed for schools, colleges, startups, NGOs, and small businesses that cannot afford enterprise cybersecurity platforms.

Unlike traditional IDS solutions that only report alerts, NetGuard explains every security decision in clear, human-readable language.

The goal is to make cybersecurity:

- Affordable
- Explainable
- Offline-first
- Open-source
- Easy to deploy
- Easy to understand

---

# Mission

Protect networks using lightweight, transparent, and explainable security.

Every detection must answer four questions:

1. What happened?
2. Why was it detected?
3. How confident is the system?
4. What should the administrator do next?

---

# Target Users

Primary

- Schools
- Colleges
- Small Businesses
- NGOs
- Cybersecurity Students

Secondary

- SOC Analysts
- Researchers
- Developers

---

# Core Product Principles

## 1. Explainability First

Every alert must contain:

- Attack name
- Evidence
- Rule triggered
- Confidence score
- Severity
- Recommendation

Never show an unexplained alert.

---

## 2. Offline First

The system must continue operating without Internet access.

Cloud services are optional future enhancements.

---

## 3. Lightweight

Optimize for laptops with:

- 4–8 GB RAM
- Consumer CPUs
- No GPU required

---

## 4. Reliable Demo

Hackathon stability is more important than experimental features.

Avoid unnecessary complexity.

---

## 5. Security by Default

Default behavior should be secure.

Examples:

- Validate all inputs
- Restrict configuration changes
- Never expose secrets
- Log every critical action

---

## Product Goals

Short-Term

- Detect attacks
- Block attackers
- Display live dashboard
- Explain every alert

Medium-Term

- Improve detection accuracy
- Add AI summaries
- Export reports
- Better analytics

Long-Term

- Enterprise deployment
- Distributed monitoring
- Threat intelligence
- AI assistant

---

# Product Priorities

Priority 1

Reliable detection.

Priority 2

Reliable blocking.

Priority 3

Explainability.

Priority 4

Excellent dashboard.

Priority 5

Performance optimization.

---

# Features We Always Build

- Live monitoring
- Evidence generation
- Human-readable explanations
- Logging
- Configuration
- Dashboard
- Whitelist
- Rule management

---

# Features We Delay

- Cloud deployment
- Kubernetes
- Machine Learning
- Multi-node deployment
- SIEM integration

These belong after the MVP.

---

# UX Philosophy

Every screen should answer:

- What is happening?
- Is it dangerous?
- Why?
- What should I do?

Avoid unnecessary technical jargon where plain language is sufficient.

---

# Definition of Success

A successful product allows a non-expert user to understand:

- What attack occurred
- Why it was detected
- What action was taken
- What to do next

without reading documentation.

---

# Decision Rules

When choosing between two implementations:

Choose the one that is:

1. More reliable
2. Easier to explain
3. Easier to maintain
4. Easier to demonstrate

Do not optimize prematurely.

---

# Quality Standards

Every feature should be:

- Documented
- Tested
- Explainable
- Modular
- Secure

---

# Non-Goals

The MVP is NOT intended to replace:

- Splunk
- CrowdStrike
- Microsoft Defender XDR
- Palo Alto Cortex XDR
- Enterprise SIEM platforms

Instead, it demonstrates explainable intrusion detection for resource-constrained environments.

---

# End of Product Steering