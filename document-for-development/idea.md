NetGuard
Explainable Intrusion Detection & Prevention System
Event: MVIC Build Nepal Hackathon 2026
Dates: 1 to 2 August 2026, Mid Valley International College
Team size: 4 members
Prepared: Five day build plan before the event
Enterprise grade intrusion detection, built from scratch, running free on a student laptop.
Unlike most IDS tools, it explains its decisions instead of being a black box.
1. The Problem
Small businesses, schools, and colleges in Nepal cannot afford enterprise security tools like Cloudflare WAF
or commercial intrusion detection systems, which often cost thousands of dollars a month. Most either run
with no protection at all, or rely on a firewall with no visibility into what is actually being blocked and why.
Existing free tools like Snort or Suricata are powerful but complex to set up, and they behave like black
boxes. They tell you something was blocked, but not why, in language a non-expert can understand.
2. The Solution
NetGuard is a lightweight intrusion detection and prevention system that runs entirely on a laptop, with no
cloud service and no special hardware. It works like a security guard for a network:
Watches traffic. Scapy captures every packet flowing through the network in real time.
Recognizes attacks. YARA rules pattern match traffic against known attack signatures, such as SYN
floods, port scans, SQL injection attempts, brute force logins, and ARP spoofing.
Blocks automatically. The moment an attack is detected, iptables blocks that IP address for a short
window, with no human needed.
Explains itself. A live dashboard shows not just that something was blocked, but exactly why: which rule
fired, how many packets, from which source, and how severe the threat was rated.
This last point, explainability, is what separates NetGuard from a typical student IDS project. Most tools show
a table of blocked IPs. NetGuard shows evidence, the way a real security analyst would explain a decision to
their manager.
1.
2.
3.
4.
NetGuard — Build Nepal Hackathon 2026
3. Why This Wins
It is real, working software. Not a wrapper around an existing API. Every layer, from packet capture to
blocking to dashboard, is built by the team.
It demos live. Judges can launch an attack from a second laptop and watch NetGuard detect and block
it in real time, in seconds.
It solves a real gap. Affordable security for schools and small businesses in Nepal is a genuine,
underserved need.
It shows production thinking. Features like a whitelist and false positive handling show the team
understands real security tooling, not just a classroom exercise.
Judging tip: A reliable local demo beats an ambitious but fragile cloud demo. The plan below prioritizes a rock
solid, always-working local system over adding cloud or machine learning features that could fail on stage.
•
•
•
•
NetGuard — Build Nepal Hackathon 2026
4. Tech Stack
Layer Tool Purpose
Packet capture Scapy (Python) Reads live network traffic packet by packet
Detection rules YARA Matches traffic against attack signatures
Blocking iptables
Automatically blocks attacking IP addresses, with auto
expiry
Backend Flask (Python) Serves the dashboard and API, logs every decision
Frontend Chart.js + HTML/CSS/JS
Live dashboard: traffic graph, blocked events, evidence
panel
Attack
simulation
Kali Linux VM (nmap, hydra,
hping3)
Generates real attacks for the live demo
5. Detection Coverage
Five attack types, chosen to be reliable, explainable, and easy to demo live rather than a long list that is hard
to test properly.
Attack Type What It Looks Like Demo Tool
SYN Flood Large burst of SYN packets from one source in a short time hping3
Port Scan Many connection attempts across sequential ports nmap
Brute Force Login Repeated failed login attempts in a short window hydra
SQL Injection String Suspicious SQL syntax patterns in HTTP request payloads curl or a custom script
ARP Spoofing Conflicting IP to MAC address mappings on the local network arpspoof
6. Team Roles
Four members, each owning one layer end to end so there is a single point of accountability and no blocked
work during the hackathon itself.
Role Owns Main Deliverable
Member 1
Detection
Engineer
Scapy packet capture, YARA rules A script that reliably detects all 5 attack types and logs
each detection with evidence
NetGuard — Build Nepal Hackathon 2026
Member 2
Backend
Engineer
Flask API, iptables integration,
logging
An API that receives detections, blocks IPs
automatically, and stores structured logs
Member 3
Frontend
Engineer
Dashboard UI, Chart.js
visualizations
A live dashboard showing stats, traffic graph, and an
evidence panel for each block
Member 4
Demo and Pitch
Lead
Kali VM setup, attack scripts, pitch
deck, rehearsal
A one command attack trigger kit, a 3 slide pitch, and
a recorded demo backup
All four members should understand the full pipeline well enough to explain it to a judge, since questions
may go to any team member during pitching.
NetGuard — Build Nepal Hackathon 2026
7. Five Day Build Plan (Before the Hackathon)
Since the team is starting a full week before the event, the goal is to arrive at the hackathon with a fully
working local system, so that both hackathon days can go toward polish, the explainability layer, and demo
rehearsal rather than basic plumbing.
Day 1: Environment and Packet Capture Foundation
Day 2: Core Detection Rules Detection
Day 3: Blocking and Logging Prevention
✓ All 4 members set up Linux environment, Python, Scapy, YARA, and iptables access
✓ Set up a shared GitHub repo with a clear folder structure: detection, backend, frontend, demo
✓ Member 1 builds a basic Scapy sniffer that prints live packet info to the terminal
✓ Member 4 sets up the Kali VM and confirms it can reach the target laptop over the network
✓ Member 1 writes YARA rules or rule logic for all 5 attack types
✓ Test each rule against real traffic generated by Member 4's Kali VM, one attack type at a time
✓ Member 2 starts the Flask API skeleton with a basic endpoint to receive detection events
✓ Member 3 starts the dashboard layout with placeholder data, no live connection yet
Member 2 connects detection events to iptables, blocking the source IP for 60 to 120 seconds with
auto expiry
✓
✓ Every decision is logged with timestamp, source IP, rule matched, evidence, and severity
✓ Member 1 and Member 2 test the full pipeline together: attack in, block out, log written
✓ Member 3 connects the dashboard to real log data from the Flask API
NetGuard — Build Nepal Hackathon 2026
Day 4: Explainability, Dashboard, and Whitelisting Differentiator
Day 5: Full Rehearsal and Backup Plan Demo Ready
Hackathon Day 1 and 2 (at the venue): With the system already working from the week before, use Day 1 (10
AM to 7 PM) for polish and stress testing on the venue's actual network, and Day 2 morning for final rehearsal
before the 3 PM submission and pitch.
Member 3 builds the evidence panel: clicking a blocked event shows why it was blocked, in plain
language
✓
✓ Add a severity score (Low, Medium, High) to each detection, not just a block or allow flag
Member 2 adds a simple whitelist and a "why was this not blocked" toggle, showing the team
understands false positives
✓
Member 4 finalizes attack trigger scripts so each of the 5 attacks can be launched with a single
command
✓
✓ Run the complete demo start to finish at least 3 times, timing it to 90 seconds
✓ Record a backup video of a successful demo run, in case of wifi or hardware issues at the venue
✓ Draft the 3 slide pitch: problem, solution with live demo, and what is next
✓ Fix any bugs found during rehearsal, do not add new features this late
NetGuard — Build Nepal Hackathon 2026
8. What Each Member Should Bring
Required
Own laptop and charger
Student ID or valid identification
At least one laptop able to run Kali Linux, native,
dual boot, or VM
Fully charged power bank, venue outlets may be
limited
Recommended
USB drive with the GitHub repo cloned locally, in
case of venue wifi issues
Printed or offline copy of the pitch slides
A phone hotspot as backup internet
Headphones for focused work during build
blocks
9. The 90 Second Live Demo Script
0 to 10 seconds: Show the dashboard in idle state, "Monitoring Active"
10 to 25 seconds: Launch a SYN flood attack from the Kali VM with one command
25 to 45 seconds: Dashboard shows the traffic spike, then the alert, then the block, all in real time
45 to 65 seconds: Click the blocked event, show the evidence panel: packet count, rate, rule matched
65 to 90 seconds: Briefly repeat with a second attack type to show it is not a one trick demo
10. Anticipated Judge Questions
Question Suggested Answer
How is this different from
Snort or Suricata?
Lightweight, zero cost, and explainable for non-experts, deployable by anyone with a
laptop and no security background
Does this scale beyond
one laptop?
Yes, the architecture supports moving the Flask API to a small cloud instance and adding
machine learning based anomaly detection for unknown attacks, planned as a next step
What happens with false
positives?
The whitelist and severity scoring system let an admin tune sensitivity and review
borderline cases before they are blocked
Who built what? Every member should be ready to explain the full pipeline, not just their own part
11. What We Are Deliberately Not Building This Week
Cloud deployment, machine learning based anomaly detection, and multi node correlation are strong ideas
for where this project goes next, but attempting them in five days risks a fragile demo. They belong in the
"what is next" part of the pitch, spoken about with confidence, not built under time pressure.
•
•
•
•
•
•
•
•
1.
2.
3.
4.
5.
NetGuard — Build Nepal Hackathon 2026
Build Today, Transform Tomorrow.
NetGuard — Build Nepal Hackathon 2026