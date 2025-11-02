<img width="100" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/tylerdroxler/threat-hunting-scenario-TOR-Browser-usage-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user downloaded a tor installer, did something that resulted in many tor related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at:
Query to locate events :2025-10-31T19:19:49.0331889Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "tyler-windows10"
| where FileName contains "tor"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/tylerdroxler/threat-hunting-scenario-TOR-Browser-usage-/blob/main/Downloaded-Tor.png">

---

### 2. Searched the `DeviceProcessEvents` Table


Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor”. Based on the logs returned at 2025-11-02T01:14:40.9956149Z, an employee on the “tyler-windows10” device ran the command tor-browser-windows-x86_64-portable-15.0  /S, triggering a silent installation of the Tor browser. This could indicate an attempt to bypass network monitoring. 


**Query used to locate event:**

```kql

DeviceFileEvents
| where DeviceName == "tyler-windows10"
| where FileName has "tor"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, InitiatingProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/tylerdroxler/threat-hunting-scenario-TOR-Browser-usage-/blob/main/Installed-Tor.png">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “labuser” actually opened the tor browser. There was evidence that they did open it at 2025-11-02T01:15:31.08Z. There were several other instances of firefox.exe and tor.exe spawned after this timeframe.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "tyler-windows10"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by TimeGenerated desc

```
<img width="1212" alt="image" src="https://github.com/tylerdroxler/threat-hunting-scenario-TOR-Browser-usage-/blob/main/Opened-Tor.png">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

At 2025-11-02T01:16:18.0808086Z, the user labuser successfully launched the Tor process on tyler-windows10, which connected to a remote Tor node at IP 77.73.67.21 over port 9001. This confirms active use of the Tor network for anonymized communication. There were additional connections around this time frame. A few connections were found using standard https port 443 as well. 


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "tyler-windows10"
| where InitiatingProcessFileName has "tor"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443", "80")
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    InitiatingProcessAccountName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath

```
<img width="1212" alt="image" src="https://github.com/tylerdroxler/threat-hunting-scenario-TOR-Browser-usage-/blob/main/Usage-Tor.png">

---

## Chronological Event Timeline 

2025-10-31T19:19:49.0331889Z — File events discovered by hunting: a search for files containing “tor” shows the user downloaded the Tor installer at this time. The installer filename was tor-browser-windows-x86_64-portable-15.0.exe (SHA256 fd022504bb6e57e379668ed4b82966f284f19508dd88d76eaaf33e505add4f43).   

2025-11-02T01:14:40.9956149Z — Process created: the user account labuser executed the downloaded portable Tor installer on device tyler-windows10 using the command tor-browser-windows-x86_64-portable-15.0 /S, triggering a silent installation from C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.exe.   

2025-11-02T01:15:31.0800000Z — Tor Browser opened: evidence shows labuser launched the browser (process spawns recorded for tor.exe and firefox.exe). Multiple subsequent launches of browser-related processes were observed and Tor bundle files appeared under a Desktop path such as c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe. A Desktop file named tor-shopping-list.txt was created around this timeframe.    

2025-11-02T01:16:18.0808086Z — Network connection established: tor.exe on tyler-windows10 successfully connected to remote IP 77.73.67.21 on port 9001 (a known Tor relay port), confirming the Tor process was actively communicating on the Tor network. Additional Tor-related outbound connections were observed in the same timeframe, including some over TCP 443.


---

## Summary

the user 'labuser' on device 'tyler-windows10' downloaded a Tor portable installer, silently installed it, launched the Tor Browser (bundle files copied to Desktop and tor-shopping-list.txt created), and then used Tor to establish outbound connections including to 77.73.67.21:9001, confirming installation and active use of the Tor network from the endpoint.


---

## Response Taken

TOR usage was confirmed on endpoint tyler-windows10 by the user labuser. The device was isolated and the user's direct manager was notified.

---
