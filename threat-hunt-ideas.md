# 🧠 Threat Hunt Ideas

A running list of threat hunting scenarios to explore, simulate, or build projects around. Based on real-world techniques, malware behavior, and threat actor tactics.

---

## ✅ Completed

- **TOR Browser Usage**  
  Unauthorized use of the TOR browser for anonymous browsing or evasion of web filters.

---

## 🔍 In Progress / Next Up

- **Firefox Installation on Corporate Device**  
  Detect installation and use of an unapproved browser like Firefox on a managed system.

- **Dropbox Data Exfiltration**  
  Large sensitive file uploaded to unauthorized cloud storage (Dropbox).

- **USB Malware Execution (PowerShell)**  
  A USB device is inserted, running a malicious `Invoke-WebRequest` payload via PowerShell.

- **Chrome Extension Persistence**  
  Malicious browser extension used to establish backdoor access or maintain persistence.

---

## 🛠️ Practical Scenarios to Build

- **LOLBins Abuse**  
  User abuses legitimate Windows tools like `certutil.exe` or `mshta.exe` to download and execute a payload.

- **Privileged Escalation**  
  User gains admin privileges via a misconfiguration or known exploit on the system.

- **PowerShell Abuse**  
  Use of suspicious PowerShell commands like `Invoke-WebRequest` or encoded base64 strings.

- **Hidden Persistence via Scheduled Task**  
  Attacker schedules a hidden task to run malware after reboot.

- **USB Keylogger or Autorun Attack**  
  Hidden device emulates a keyboard or auto-executes a payload upon insertion.

- **Remote Desktop Software Installed**  
  User installs AnyDesk/TeamViewer without approval to allow external remote access.

- **Macro-Based Email Attack**  
  Phishing email attachment with macro-enabled Word/Excel file initiating malicious code.

- **Bypassing Application Whitelisting**  
  Attacker runs payloads from non-whitelisted paths or uses scripting engines.

---

## 🎧 Inspired by Darknet Diaries

- **Evercookie Tracking (Samy Kamkar)**  
  A persistent cookie mechanism that survives regular deletion via multiple vectors.

- **PoisonTap Device Attack**  
  $5 Raspberry Pi device simulates network and intercepts HTTP traffic via USB.

- **KeySweeper (Samy Kamkar)**  
  USB wall charger that secretly logs and transmits keystrokes from wireless keyboards.

- **SRF Vulnerability Abuse**  
  Exploiting server-side request forgery to pivot internally or expose internal resources.

- **Bug Bounty Writeup Replication**  
  Recreate and hunt real findings from public bug bounty disclosures.

## 🧪 Threat Hunt & Lab Ideas (Darknet Diaries Inspired)

- **DDoS Tools – LOIC / HOIC Simulation**  
  Explore how simple tools like Low Orbit Ion Cannon (LOIC) can flood a target. Investigate how your own lab network handles packet floods (lab only, never against real-world targets).

- **Stressor Services – DDoS-as-a-Service**  
  Research how commercial “stress testing” platforms work, how they use botnets, and how attackers might abuse them. Compare with how defenders detect and mitigate this traffic.

- **NTP Amplification Attack – Lab Simulation**  
  Investigate how Network Time Protocol (NTP) servers can be abused for amplification. Try capturing traffic in Wireshark or simulate how spoofed requests work in theory.

- **IP Spoofing Detection**  
  Learn what IP spoofing is, how it’s used in amplification attacks, and what indicators can help detect it (e.g. TTL mismatches, routing anomalies).

- **Packet Sniffing – Network Visibility**  
  Practice packet capture with Wireshark or `tcpdump`. Learn to identify logins, DNS queries, or other interesting activity. Use a separate isolated VM or lab machine.

- **Defending Against DDoS**  
  Research and simulate how websites defend against floods using services like Akamai, Cloudflare, or AWS Shield. What rate-limiting or firewall rules can you implement?

- **Lawful Intercept vs Malicious MITM**  
  Compare legitimate uses of packet capture (lawful intercept, network monitoring) with malicious interception. Could lead to a project visualizing MITM (man-in-the-middle) attack flows.

- **Wi-Fi Reconnaissance – What’s Public?**  
  Use tools like `iwlist` or `airodump-ng` to see what info is broadcasted by Wi-Fi networks around you. Investigate what can be learned from open, hidden, or poorly secured SSIDs.

- **Pastebin & Ghostbin – Data Leak Monitoring**  
  Study how attackers use public paste sites to share exfiltrated data or payloads. Build a lightweight Python script to monitor known keywords or hashes on these sites.

- **Home Network Privacy – Who’s Phoning Home?**  
  Monitor outbound traffic from your router or devices to detect phone-home behavior (e.g., smart TVs, phones, or assistants). Can be used to spot unexpected connections or trackers.

---

## 🌐 Linux / Endpoint-Focused Scenarios

- **Unauthorized Package Installation (Linux)**  
  Detect installation of `nmap`, `netcat`, or other hacking tools on a Linux endpoint.

- **User Enumeration or Privilege Discovery**  
  Suspicious enumeration commands (`whoami`, `id`, `sudo -l`, etc.) on Linux system.

- **SSH Brute-Force Attempts**  
  Detect repeated failed SSH login attempts or anomalous access patterns.

---

## 📌 To Brainstorm or Research Further

- USB firmware-level threats  
- Insider threat with scheduled file deletion  
- Malware that disables security tools (Defender, Sentinel)  
- Fake VPN apps used as backdoors  
- Cryptominer dropped in temp folder via phishing

---

> ✍️ Tip: When starting a hunt, always define a scenario, log source, expected IOCs, and what success looks like.

