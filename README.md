Thanks for the correction. Here's the updated `README.md` with the correct TOR version: `tor-browser-windows-x86_64-portable-14.5.3.exe`.

````markdown
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ayubhali/Threat-Hunting-Scenario-Tor-Browser-Usage/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "ayubcyberlab" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and possibly a `.txt` file related to TOR activity.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "melona-hunt"  
| where InitiatingProcessAccountName == "ayubcyberlab"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-06-02T15:52:53.685265Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
````

![image](https://github.com/user-attachments/assets/1f658c82-dd56-49b2-afc1-9d0f9618fe73)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86\_64-portable-14.5.3.exe". Based on the logs returned, at `2025-06-02T15:54:47Z`, the user on the "melona-hunt" device ran the file from their Desktop folder using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "melona-hunt"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

![image](https://github.com/user-attachments/assets/bcffe527-8bdf-4500-8001-84a2f713c845)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that the user "ayubcyberlab" actually opened the TOR browser. There was evidence that they did open it at `2025-06-02T16:08:35Z`. Several other instances of `firefox.exe` (TOR) as well as `tor.exe` followed.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "melona-hunt"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/aa7caedc-356e-4fc3-8ff4-7a6313646cc5)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-06-02T16:08:52Z`, the user on the "melona-hunt" device successfully established a connection to the remote IP address `148.251.151.125` on port `9001`. The connection was initiated by the process `tor.exe`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "melona-hunt"  
| where InitiatingProcessAccountName != "system"  
| where RemotePort in ("9001", "9030", "9040", "9050", "9150")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/b8279284-2705-4c8f-9565-b0d4294a3ee3)

---

## Chronological Event Timeline

### 1. File Download - TOR Installer

* **Timestamp:** `2025-06-02T15:52:53Z`
* **Event:** The user "ayubcyberlab" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.3.exe` to the Desktop folder.
* **Action:** File download detected.
* **File Path:** `C:\Users\ayubcyberlab\Desktop\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 2. Process Execution - TOR Browser Installation

* **Timestamp:** `2025-06-02T15:54:47Z`
* **Event:** The user "ayubcyberlab" executed the installer in silent mode.
* **Action:** Process creation detected.
* **Command:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`
* **File Path:** `C:\Users\ayubcyberlab\Desktop\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 3. Process Execution - TOR Browser Launch

* **Timestamp:** `2025-06-02T16:08:35Z`
* **Event:** The TOR browser (`tor.exe`, `firefox.exe`) was launched by the user.
* **Action:** Process execution.
* **File Path:** `C:\Users\ayubcyberlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

* **Timestamp:** `2025-06-02T16:08:52Z`
* **Event:** A network connection to IP `148.251.151.125` on port `9001` by `tor.exe` was logged.
* **Action:** Outbound connection success.
* **Process:** `tor.exe`
* **File Path:** `C:\Users\ayubcyberlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

## Summary

The user "ayubcyberlab" on the "melona-hunt" device downloaded, silently installed, and launched the TOR browser. Network logs confirmed successful connections to known TOR entry nodes. These actions strongly indicate unauthorized anonymized browsing attempts during work hours.

---

## Response Taken

TOR usage was confirmed on the endpoint `melona-hunt` by the user `ayubcyberlab`. The device was isolated from the corporate network, and management was notified for further action.

---
