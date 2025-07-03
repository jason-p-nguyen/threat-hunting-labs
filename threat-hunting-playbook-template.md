# 🧠 Threat Hunting Playbook Template  

## 🧭 1. Scenario Overview  
**Title:**  
_(What is this scenario about?)_  

**Date Executed:**  
_(When did this take place?)_  

**MITRE ATT&CK Techniques:**  
_(What tactics/techniques does this involve?)_  
_(Example: T1567.002 - Exfiltration to Cloud Storage)_

**Hypothesis / Objective:**  
_(What threat are you simulating or hunting for? What do you expect to find?)_

---

## 🛠️ 2. Environment Setup  
**VM or Device Name(s):**  
_(E.g., `fin-w10-wks-8`)_

**Accounts Used:**  
- _(E.g., `j.doe`, `admin.jnguyen`)_

**Security Tools:**  
- [ ] Microsoft Defender for Endpoint (MDE)  
- [ ] Microsoft Sentinel  
- [ ] Azure NSG Logs  
- [ ] Log Analytics Workspace  
- [ ] Other: ___________

**Artifacts/Resources:**  
- Scripts:  
  - [ ] `installer.ps1`  
  - [ ] `fake-malware.ps1`  
  - [ ] `usb-mount.ps1`  
- GitHub URLs:  
  - `https://github.com/...`

---

## 📦 3. Attack Simulation Steps  
**Step-by-step Summary of Actions Taken:**  
_(E.g., Created user → Placed files → Ran Dropbox → Uninstalled client)_  

1.  
2.  
3.  
...

**Notes on Deception / Cleanup / OPSEC:**  
_(Did you simulate insider activity, clear logs, spoof file metadata, etc.?)_

---

## 🔍 4. Log Sources Reviewed  
- [x] DeviceProcessEvents  
- [x] DeviceFileEvents  
- [x] DeviceNetworkEvents  
- [ ] AlertEvidence  
- [ ] Sentinel Incidents  
- [ ] Other: ___________

**Expected Log Traces:**  
_(What behaviors should show up in logs?)_

---

## 🧪 5. Detection Queries (KQL)  
```kql
// Example: Detect suspicious file downloads
DeviceNetworkEvents
| where RemoteUrl has "dropbox"
````

```kql
// Example: Local PowerShell execution
DeviceProcessEvents
| where FileName endswith ".ps1"
```

*(Add more queries used during the hunt)*

---

## 📈 6. Hunt Results

**Did You Confirm the Hypothesis?**
✅ Yes / ❌ No / 🔄 Partially

**What Evidence Was Found?**

* *(List filenames, process chains, logs, indicators, timestamps)*

**What Was Missing or Failed to Log?**
*(E.g., NSG blocked outbound, script didn't execute fully, etc.)*

---

## 🪪 7. Threat Actor / TTP Notes

**Is This Based on a Real Threat Group or Behavior?**
*(Optional: e.g., “Loosely inspired by Scattered Spider”)*

**Techniques Observed or Simulated:**

* [ ] Polymorphic malware
* [ ] Cloud storage exfiltration
* [ ] LOLBin misuse
* [ ] Registry edits
* [ ] \_\_\_\_\_\_\_\_\_\_\_

---

## 📂 8. Supporting Artifacts

Folder structure recommendation:

```
/threat-hunting-projects/
└── scenario_name/
    ├── README.md (this filled template)
    ├── scripts/
    ├── queries/
    ├── screenshots/
    ├── evidence/
```

**Links to Files:**

* Scripts
* Screenshots
* Logs
* KQL queries

---

## 💡 9. Lessons Learned

**Challenges or Failures:**
*(E.g., Uninstaller script failed, GitHub URL blocked, logs didn’t appear)*

**Debugging Steps Taken:**
*(E.g., Opened port, used different cmdlet, ran script manually)*

## **Improvements for Future Hunts:**

*
*

---

## 📢 10. Portfolio Sharing

* [ ] Upload to GitHub
* [ ] Add screenshots of scenario and logs
* [ ] Share insights on LinkedIn or personal blog
* [ ] Tag with appropriate MITRE techniques

