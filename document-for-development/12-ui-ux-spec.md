# UI / UX Specification

# NetGuard
Explainable Intrusion Detection & Prevention System

Version: 1.0

Document ID: NG-UI-001

---

# Purpose

This document defines the complete user experience and interface design of NetGuard.

Goals

- Modern Security Operations Center (SOC) dashboard
- Real-time monitoring
- Explainable security decisions
- Easy for non-security users
- Responsive on laptops
- Professional appearance for hackathon demonstrations

---

# Design Principles

- Minimalist
- Dark Theme First
- Information Hierarchy
- Real-Time Updates
- Explainability Before Complexity
- Accessible
- Fast Navigation

---

# Target Users

### Primary

- School IT Administrators
- Small Business Owners
- Cybersecurity Students
- Hackathon Judges

### Secondary

- Network Administrators
- Security Analysts
- Researchers

---

# Design Language

Style

Modern Enterprise SOC Dashboard

Keywords

- Clean
- Professional
- Technical
- Trustworthy
- Responsive

---

# Color Palette

## Background

Primary

#0F172A

Secondary

#111827

Cards

#1E293B

Borders

#334155

---

## Status Colors

Success

#22C55E

Warning

#FACC15

Danger

#EF4444

Critical

#DC2626

Info

#3B82F6

Neutral

#94A3B8

---

# Typography

Primary Font

Inter

Fallback

Arial

Sans-serif

Sizes

Heading

32px

Section Title

24px

Card Title

18px

Body

16px

Small Text

14px

Caption

12px

---

# Icon Library

Recommended

Lucide Icons

or

Heroicons

Examples

Shield

Alert

Server

Database

Network

Clock

Activity

Settings

Search

User

---

# Application Layout

```
+--------------------------------------------------------------+
| Logo        NetGuard              Monitoring: ACTIVE         |
+--------------------------------------------------------------+

| Sidebar | Main Dashboard                                  |

|         | KPI Cards                                       |

|         |--------------------------------------------------|

|         | Traffic Graph                                   |

|         |--------------------------------------------------|

|         | Active Threats                                  |

|         |--------------------------------------------------|

|         | Evidence Panel                                  |

+--------------------------------------------------------------+
```

---

# Sidebar Navigation

Items

Dashboard

Threats

Blocked IPs

Whitelist

Logs

Rules

Settings

About

Icons included beside each menu item.

---

# Header

Contains

- Logo
- Project Name
- Monitoring Status
- Current Interface
- System Time
- Settings Button

Monitoring Badge

Green

Monitoring Active

Red

Monitoring Stopped

---

# Dashboard Overview

First screen users see.

Widgets

- Monitoring Status
- Packets Processed
- Active Threats
- Total Alerts
- Blocked IPs
- Current Network Interface

---

# KPI Cards

Cards

Packets Processed

Live counter

---

Threats Detected

Today's detections

---

Blocked IPs

Currently blocked

---

Monitoring Status

Active / Offline

---

Average Detection Time

Milliseconds

---

CPU Usage

Percentage

---

Memory Usage

MB

---

# Traffic Graph

Type

Real-Time Line Chart

X-axis

Time

Y-axis

Packets / Second

Refresh Rate

1 second

Features

Zoom (future)

Pause

Auto-scroll

---

# Threat Timeline

Shows events chronologically.

Columns

Time

Attack

Source IP

Severity

Status

Action

Newest event appears first.

---

# Threat Severity Chart

Chart

Doughnut

Displays

Low

Medium

High

Critical

Updates live.

---

# Active Threats Panel

Displays

- Attack Type
- Source IP
- Severity
- Detection Time
- Block Status

High severity shown first.

---

# Evidence Panel

Opened when an event is selected.

Shows

Attack Name

Source IP

Destination IP

Rule Triggered

Packet Count

Confidence Score

Severity

Recommendation

Explanation

Example

```
Attack

SYN Flood

Source

192.168.1.20

Reason

Detected 231 SYN packets within 3 seconds.

Action

Blocked for 120 seconds.

Confidence

98%

Recommendation

Investigate the source device.
```

---

# Blocked IP Page

Columns

IP Address

Reason

Blocked At

Expires In

Status

Manual Unblock Button

Search supported.

---

# Whitelist Page

Functions

Add Device

Edit Device

Delete Device

Search

Columns

IP Address

Description

Created Date

Created By

---

# Logs Page

Supports

Search

Filters

- Date
- Severity
- Attack Type
- IP Address
- Module

Export (Future)

CSV

JSON

PDF

---

# Rules Page

Displays

Rule Name

Enabled

Threshold

Block Duration

Priority

Description

Administrator can

Enable

Disable

Edit

Reset

---

# Settings Page

Options

Dashboard Refresh Rate

Block Duration

Theme

Detection Thresholds

Network Interface

Auto Start Monitoring

Save Configuration

---

# About Page

Displays

Project Name

Version

Team Members

Hackathon

Technology Stack

License

GitHub Repository

---

# Notifications

Notification Types

Success

Warning

Error

Critical

Example

```
✓ Monitoring Started

⚠ Port Scan Detected

✖ Firewall Rule Failed

🚨 SYN Flood Blocked
```

Auto-dismiss

5 seconds

Critical alerts remain until acknowledged.

---

# Search Experience

Global search supports

IP Address

Attack Type

Rule Name

Event ID

Severity

---

# Responsive Design

Target

1366×768

Supports

1920×1080

Tablets (basic)

Not optimized for phones.

---

# Loading States

Skeleton loaders

Loading spinner

Progress bar

No empty white screens.

---

# Empty States

Examples

No threats detected.

Monitoring has not started.

No blocked IPs.

Whitelist is empty.

---

# Error States

Examples

Backend unavailable

Database disconnected

Firewall command failed

Network interface unavailable

Each error includes

- Description
- Suggested action

---

# Accessibility

Minimum contrast ratio

4.5:1

Keyboard navigation

Supported

Visible focus indicators

Enabled

Icons always paired with labels.

---

# Animations

Subtle only.

Examples

Card fade-in

Counter animation

Chart updates

Notification slide-in

Avoid excessive motion.

---

# User Flow

```
Launch NetGuard

↓

Select Network Interface

↓

Start Monitoring

↓

Dashboard Updates

↓

Attack Detected

↓

Alert Appears

↓

User Opens Evidence

↓

View Explanation

↓

Optional Manual Unblock

↓

Continue Monitoring
```

---

# Demo Mode

Special hackathon view.

Highlights

- Full-screen dashboard
- Larger KPI cards
- Larger charts
- Bigger fonts
- One-click attack launch indicator
- Simplified navigation

Optimized for projection screens.

---

# Future UI Enhancements

- Light theme
- Interactive network topology map
- World map of attacker IPs
- Dark mode customization
- Drag-and-drop widgets
- Mobile companion dashboard
- Multi-language support
- AI incident summary panel

---

# UI Acceptance Criteria

✓ Dashboard loads in under 2 seconds.

✓ Updates every second.

✓ Evidence panel opens instantly.

✓ Critical alerts are visually prominent.

✓ Navigation requires no more than three clicks.

✓ Layout fits a 1366×768 laptop without horizontal scrolling.

✓ Dashboard remains usable during live attack demonstrations.

---

# Revision History

| Version | Date | Description |
|----------|------|-------------|
| 1.0 | July 2026 | Initial UI/UX Specification |

---

End of Document