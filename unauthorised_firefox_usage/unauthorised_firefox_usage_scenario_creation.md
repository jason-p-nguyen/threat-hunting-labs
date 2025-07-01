# Threat Event (Suspicious Firefox Use)

**Unauthorized Firefox Installation and Access to Potentially Risky Sites**

---

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. **Download the Firefox installer** directly from Mozilla:
   `https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-US`

2. **Install Firefox silently or without admin approval**:

   ```powershell
   Start-Process -FilePath "Downloads\Firefox Setup 140.0.2.exe" -ArgumentList "/S" -Wait
   ```

   The user ran the installer silently to avoid detection from coworkers still in the office.

3. **Launch Firefox** 

4. **Browse risky or unapproved sites**, such as:

   * `https://www.freedownloadmanager.org/` — often used to sideload extensions
   * `https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/` — used as a cover for testing fake/malicious extensions

   Installed **Free Download Manager**:

   ```powershell
   Start-Process -FilePath "Downloads\fdm_x64_setup.exe" -ArgumentList "/S" -Wait
   ```

   Added **uBlock Origin** as a Firefox extension.

6. **Delete the installers** to cover tracks.

   * Deleted shortcuts and unpinned Firefox
   * Removed apps from Windows taskbar
   * Shut down the VM to mimic the actor leaving for the day after setup

---

## Tables Used to Detect IoCs:

| **Parameter** | **Description**                                                                                          |
| ------------- | -------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceFileEvents                                                                                         |
| **Info**      | [Microsoft Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose**   | Detect Firefox installer download, extension-related file writes, and document creation/deletion.        |
| ✅ Confirmed   |                                                                                                          |

| **Parameter** | **Description**                                                                                             |
| ------------- | ----------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceProcessEvents                                                                                         |
| **Info**      | [Microsoft Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**   | Detect installation and launch of Firefox outside the approved software center.                             |
| ✅ Confirmed   |                                                                                                             |

| **Parameter** | **Description**                                                                                             |
| ------------- | ----------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceNetworkEvents                                                                                         |
| **Info**      | [Microsoft Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**   | Monitor Firefox network connections, especially to known extension sources or risky domains.                |
| ✅ Confirmed   |                                                                                                             |

---

## Related Queries:

```kql
// Detect Firefox installer download
DeviceFileEvents
| where FileName has "Firefox Setup"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType

// Detect Firefox installed silently (two spaces before /S sometimes required)
DeviceProcessEvents
| where ProcessCommandLine has "Firefox Setup"
| where ProcessCommandLine contains "/S"
| project Timestamp, DeviceName, FileName, ProcessCommandLine

// Detect Firefox being launched from non-standard directory
DeviceProcessEvents
| where FileName == "firefox.exe"
| where FolderPath !has "Program Files\\Mozilla Firefox"
| project Timestamp, DeviceName, FolderPath, ProcessCommandLine

// Detect Firefox making outbound connections to known extension or risky URLs
DeviceNetworkEvents
| where InitiatingProcessFileName == "firefox.exe"
| where RemoteUrl has_any ("addons.mozilla.org", "freedownloadmanager.org", "update.mozilla.org")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort

// Detect suspicious note file creation and deletion
DeviceFileEvents
| where FileName contains "firefox-extensions-testing.txt"
| project Timestamp, DeviceName, FileName, ActionType, FolderPath
```

---

## Created By:

* **Author Name**: Jason Nguyen
* **Author Contact**: [https://github.com/jason-p-nguyen](https://github.com/jason-p-nguyen)
* **Date**: June 21, 2025

---

## Additional Notes:

* Firefox is not inherently malicious but is often used in portable or unauthorized configurations to bypass monitoring or company policy.
* Pairing this hunt with AppLocker logs, extension audits, or browser management policies in enterprise environments is recommended.

---

## Revision History:

| **Version** | **Changes**   | **Date**      | **Modified By** |
| ----------- | ------------- | ------------- | --------------- |
| 1.0         | Initial draft | June 21, 2025 | Jason Nguyen    |

