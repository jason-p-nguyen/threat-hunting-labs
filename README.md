# 🦉 Jason Nguyen – Threat Hunting Labs

Welcome to my hands-on threat hunting portfolio. Each lab simulates a real-world incident scenario and showcases investigative methods using Microsoft Defender for Endpoint, Sentinel, and KQL.

---

### About Me 👋

I’m Jason. I’m learning threat hunting by getting hands-on with real situations. I’m not an expert yet, but I’m curious and committed to figuring things out step by step. This portfolio shows what I’ve worked on so far and where I’m headed.


---

## 📁 Scenarios

### 🌐 Internet-Exposed Devices  
🛠️ Tools: MDE · Sentinel · KQL · Azure
🎯 Focus: External Exposure · Attack Surface Discovery  
🧠 MITRE ATT&CK Techniques: T1046 · T1590.005  
📅 Date: 2025-06-11  
📄 [Read Full Report →](internet-exposed-devices/Internet-exposed-devices.md)

---

### 🚨 Sudden Network Slowdowns  
🛠️ Tools: MDE · Sentinel · PowerShell · KQL · Azure
🎯 Focus: Internal Reconnaissance · Port Scanning  
🧠 MITRE ATT&CK Techniques: T1059.001 · T1046 · T1016 · T1569.002 · T1018  
📅 Date: 2025-06-13  
📄 [Read Full Report →](sudden-network-slowdowns/sudden-network-slowdowns.md)

---

### 🗃️ Suspected Data Exfiltration  
🛠️ Tools: MDE · KQL · Azure
🎯 Focus: Insider Threat · Data Staging · Exfiltration  
🧠 MITRE ATT&CK Techniques: T1059.001 · T1218.011 · T1053 · T1560.001 · T1074.001 · T1048.003  
📅 Date: 2025-06-16  
📄 [Read Full Report →](suspected-data-exfiltration/suspected-data-exfiltration.md)

---

### Zero-Day Ransomware (PwnCrypt) Outbreak
🛠️ Tools: MDE · KQL · Azure · PowerShell
🎯 Focus: Ransomware · Threat Hunting · Incident Response   
🧠 MITRE ATT&CK Techniques: T1059.001 · T1059.003 · T1562.001 · T1119 · T1486 · T1105
📅 Date: 2025-06-17  
📄 [Read Full Report →](pwncrypt-ransomware/pwncrypt-ransomware.md)

---

### 🕵️ Threat Hunting Project: Tor Browser Activity Detection in Microsoft Defender

🛠️ **Tools**: Microsoft Defender for Endpoint (MDE) · Microsoft Sentinel · KQL · Azure VM · Log Analytics  
🎯 **Focus**: Threat Hunting · Endpoint Telemetry Analysis · Suspicious File & Process Detection · Timeline Reconstruction  
🧠 **MITRE ATT&CK Techniques**: T1059 · T1036 · T1204  
📅 **Date**: 2025-06-21  
📄 **[Read Full Report →](https://github.com/jason-p-nguyen/threat-hunting-projects/tree/main/tor_usage)**

---

### 🧩 Threat Hunting Postmortem: CTF Lurker – Suspicious PowerShell Execution

🛠️ **Tools**: Microsoft Defender for Endpoint (MDE) · KQL · PowerShell · Event Timeline Analysis  
🎯 **Focus**: Suspicious PowerShell Execution · Threat Hunting Methodology · Investigation Process Review · Lessons Learned  
🧠 **MITRE ATT&CK Techniques**: T1059.001 (PowerShell) · T1086 (Command and Scripting Interpreter)  
📅 **Date**: 2025-07-14  
📄 **[Read Full Report →](https://github.com/jason-p-nguyen/threat-hunting-projects/blob/main/CTF-Lurker)**

---

## 🕵️ Threat Hunt Report: Dropbox Data Exfiltration via Suspicious Insider Activity

🛠️ **Tools**: Microsoft Defender for Endpoint (MDE) · KQL · Azure VM · PowerShell
🎯 **Focus**: Insider Threat Detection · Data Exfiltration via Cloud Apps · Process & File Event Analysis · Response Recommendations  
🧠 **MITRE ATT&CK Techniques**: T1081 (Credentials in Files) · T1074.001 (Local Data Staging) · T1567.002 (Exfiltration to Cloud Storage)  
📅 **Date**: 2025-07-12  
📄 **[Read Full Report →](https://github.com/jason-p-nguyen/threat-hunting-projects/blob/main/dropbox_exfiltration/README.md)**

---

## 🧰 Tools Used

- ☁️ Microsoft Azure
- 🛡️ Microsoft Defender for Endpoint (MDE)  
- 📊 Microsoft Sentinel  
- 🔍 Azure Log Analytics  
- 💬 KQL (Kusto Query Language)  
- 🧑‍💻 PowerShell  
- 🗃️ GitHub for portfolio version control

---

## 💡 Threat Hunt Ideas

A running list of threat hunting scenarios to explore, simulate, or build projects around. Based on real-world techniques, malware behavior, and threat actor tactics.

**[See My List →](threat-hunt-ideas.md)**

---

💡 *This portfolio is actively updated as I complete new labs and expand my skills across MITRE ATT&CK tactics.*

