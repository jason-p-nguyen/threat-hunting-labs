# Brute Force Hunting Lab: Microsoft Defender for Endpoint (MDE)

## 1. 🧭 Preparation

**Goal:** Set up the hunt by defining what you're looking for.

During routine maintenance, the security team was asked to review VMs in the shared services cluster (DNS, Domain Services, DHCP, etc.) to identify any misconfigured or publicly exposed VMs. The mission: detect brute-force login attempts or successful compromises.

> **Hypothesis Example:**
> "Older VMs without account lockout policies may have been brute-forced while exposed to the public internet."

---

## 2. 📥 Data Collection

**Goal:** Gather logs from key data sources.

Look into:

* Which devices were exposed to the internet?
* Which received excessive failed login attempts?
* Source IP addresses and volume of login failures

**Key Log Tables:**

* `DeviceInfo`
* `DeviceLogonEvents`

---

## 3. 📊 Data Analysis

**Goal:** Test your hypothesis using logs and tools.

Look for anomalies or Indicators of Compromise (IOCs):

* Patterns of repeated failed logins
* Any successful logins after multiple failures?

> **Tip:** If a brute force attack succeeded, check what else happened around that time.

---

## 4. 🕵️ Investigation

**Goal:** Investigate suspicious events.

Dig deeper:

* What was accessed?
* Does it match any known TTPs in the [MITRE ATT\&CK Framework](https://attack.mitre.org)?

> Use ChatGPT to analyze logs or summarize activity using uploaded or pasted content.

---

## 5. 🛡️ Response

**Goal:** Mitigate confirmed threats.

Take action:

* Coordinate with your security team
* Contain and remove threats
* Begin recovery

---

## 6. 📝 Documentation

**Goal:** Record findings and improve future response.

* Document what you found
* Include log sources, queries, indicators, and actions taken

---

## 7. 🔄 Improvement

**Goal:** Enhance your detection and response capabilities.

Reflect on:

* What could’ve prevented the incident?
* What tools/methods worked or didn’t?
* What changes should be made to your hunting playbook?

---

## 💡 Sample Queries (Spoilers — highlight or copy to reveal)

```kql
// Top IPs by failed logons
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by RemoteIP, DeviceName
| order by Attempts desc
```

```kql
// Check if any of top failed IPs succeeded
let RemoteIPsInQuestion = dynamic(["119.42.115.235","183.81.169.238", "74.39.190.50"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

```kql
// Detect brute force success
let FailedLogons = DeviceLogonEvents
| where ActionType == "LogonFailed" and isnotempty(RemoteIP)
| summarize FailedLogonAttempts = count() by RemoteIP, DeviceName;
let SuccessfulLogons = DeviceLogonEvents
| where ActionType == "LogonSuccess" and isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by RemoteIP, DeviceName, AccountName;
FailedLogons
| join kind=inner SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
```

---

## 🧾 Timeline Summary & Key Findings

### 🖥️ Exposure

```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

> Last observed internet exposure: **2025-06-10T13:22:47Z**

### 🚫 Brute Force Attempts

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where ActionType == "LogonFailed"
| summarize Attempts = count() by RemoteIP
| order by Attempts desc
```

> Top 10 IPs had **no successful logons**:

```kql
let RemoteIPsInQuestion = dynamic(["109.205.213.154", "185.39.19.71", "118.107.45.60"]);
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

> ✅ *Query returned no results*

### ✅ Valid Logins (Labuser Only)

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```

> No brute force for `labuser` — all logins were valid and expected

### 🌍 Login Origin Check

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where AccountName == "labuser"
| summarize LoginCount = count() by RemoteIP
```

> All login origins were normal — no anomalies detected.

---

## 🧠 Mapped MITRE ATT\&CK TTPs

### **Initial Access**

* `T1078.001`: Valid Accounts — default account used (not compromised)
* `T1133`: External Remote Services — public RDP access

### **Credential Access**

* `T1110.001`: Brute Force — password guessing attempts

### **Reconnaissance (Implied)**

* `T1595`: Active Scanning — inferred from behavior

---

## 🔐 Response Actions

✅ Hardened NSG — restricted RDP to internal IPs only
✅ Implemented account lockout policy
✅ Enabled Multi-Factor Authentication (MFA)

---

## 📚 Resources

* [MITRE ATT\&CK Framework](https://attack.mitre.org)
* [KQL Documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)

---

**Author Note:** This lab was inspired by hands-on experience with Microsoft Defender for Endpoint threat hunting. Special thanks to Josh for permission to share this lab publicly.

> 🛡️ Stay safe and happy hunting!
