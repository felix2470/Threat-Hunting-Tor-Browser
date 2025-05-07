# Threat Hunt Event - Unauthorized TorBrowser Usage
![image](https://github.com/felix2470/tor-image-project/blob/main/Tor_Browser.jpg)
## Overview

In this project, I simulated a real-world insider threat scenario where an employee attempts to use the Tor Browser to bypass corporate security policies.
My objective was to detect, investigate, and contain this behavior using tools like Microsoft Defender for Endpoint (MDE) and Microsoft Sentinel.


---

## Lab Setup

| Component                       | Purpose                                      |
|--------------------------------|----------------------------------------------|
| **Windows 10 VM (Azure)**      | Simulated corporate workstation              |
| **Microsoft Defender for Endpoint** | EDR platform for detection and response |
| **Microsoft Sentinel**         | SIEM for centralized alerting                |
| **Log Analytics Workspace**    | Query data using KQL                         |
| **NSG Rules**                  | VM-level security control                    |
| **Tor Browser**                | Secure and anonymous web browsing            |


---

##  Organizational Device Inventory Overview

The image below illustrates the current device and monitoring infrastructure deployed in our organization. 
It includes key elements such as endpoint devices, Microsoft Defender for Endpoint (MDE), Microsoft Sentinel,
Azure-based virtual machines , Etc

This architectural diagram serves as a foundational reference for understanding how logs and alerts flow across the environment, 
and how threat detection is coordinated across platforms.
Note: This diagram helps contextualize where my test VM sits within the wider organization and how it connects to Sentinel and 
MDE for detection and response.

![image](https://github.com/felix2470/tor-image-project/blob/main/Cyber-range%20diagram.drawio-2.png)

---

## This project follows the NIST 800-61 Incident Response Lifecycle, with a focus on hands-on detection and response.

### 📚 Incident Response Framework (NIST 800-61)

| Phase                   | How I Applied It                                                                 |
|-------------------------|----------------------------------------------------------------------------------|
| **1. Preparation**      | Onboarded VM to MDE, set up Log Analytics, verified Sentinel connection          |
| **2. Detection & Analysis** | Created detection rules, triggered alert using simulated unauthorized Tor usage |
| **3. Containment**      | Used MDE to isolate the device and cut off further activity                      |
| **4. Recovery**         | Released VM from isolation after verifying no persistent threats; validated system integrity via Defender scans |                                                                      |

---

## Scenario
Management has prohibited the use of anonymous browsing tools like the Tor Browser within the organization due to the risk of data exfiltration.
My goal is to simulate a user bypassing policy, then detect and respond to it using Microsoft security tools.

---

## Objectives
Create KQL-based rules to generate alerts in Sentinel
Simulate unauthorized activity (Tor Browser usage)
Detect file/process/network artifacts associated with Tor
Investigate triggered alerts and trace actions
Contain the incident via MDE isolation

---

# Project Workflow (My Steps)

## 1. Setting Up the Environment: 
I deployed a Windows 10 VM and configured appropriate NSG rules to secure it. After setup, I onboarded the VM to Microsoft Defender for 
Endpoint via  onboarding package.

![image](https://github.com/felix2470/tor-image-project/blob/main/Terry-vm%20Onboarded.png)
![image](https://github.com/felix2470/tor-image-project/blob/main/Terry%20Onboarded%20on%20MDE.png)
This image confirms that our Device (window 10) was Onboarded and visible in Microsoft Defender For Endpoint.

---

## 2. Creating KQL  Rules for Detection
I created KQL queries to identify suspicious activity related to Tor Browser — both at the process level and network level.

_KQL Detection Rule:_


```kql
union 
(
    // Stage 1: Tor Browser Download Attempt
    DeviceFileEvents
    | where DeviceName == "terry-vm"
    | where InitiatingProcessAccountName == "terry-vm"
    | where FolderPath contains "Download" and FolderPath contains "tor"
    | project TimeGenerated, DeviceName, Account = InitiatingProcessAccountName, FileName, FolderPath, EventType = "Tor_Download"

),
(
    // Stage 2: Tor Installer Detected
    DeviceFileEvents
    | where DeviceName == "terry-vm"
    | where FileName in~ ("tor.exe", "tor")
    | project TimeGenerated, DeviceName, Account = InitiatingProcessAccountName, FileName, FolderPath, EventType = "Tor_Installer"
),
(
    // Stage 3: Silent Installation
    DeviceProcessEvents
    | where DeviceName == "terry-vm"
    | where AccountName == "terry-vm"
    | where ProcessCommandLine contains "tor-browser" and ProcessCommandLine contains "/S"
    | project TimeGenerated, DeviceName, Account = InitiatingProcessAccountName, FileName, ProcessCommandLine, EventType = "Tor_SilentInstall"
),
(
    // Stage 4: Active Tor Connections
    DeviceNetworkEvents
    | where DeviceName == "terry-vm"
    | where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
    | where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 443)
    | project TimeGenerated, DeviceName, Account = InitiatingProcessAccountName, ActionType, RemoteUrl, RemotePort, InitiatingProcessFileName
)

```


## Tor Detection Rule – Summary
This rule was created in Log Analytics Workspace to detect potential Tor activity on the VM terry-vm. It will be used in Microsoft Sentinel for automatic detection and alerting.

*It analyzes the following tables:*
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceProcessEvents`

*The rule identifies:*
- Tor browser downloads  
- Tor installer presence  
- Silent installations


Active Tor connections on tor known  ports (9001, 9030, 9040, 9050, 9051, 9150, 443)
All detections are scoped to the device *terry-vm*

--- 

## 3.  Creating Sentinel Alert Rule
After confirming that the Rule is  working, I set it up as a custom Analytics Rule in Azure Sentinel. I configured it to generate an incident every time the detection conditions were met.

![image](https://github.com/felix2470/tor-image-project/blob/main/sentinel_alert-creation-1.png)
![image](https://github.com/felix2470/tor-image-project/blob/main/sentinel_alert-creation-2.png)
*The image above confirms the successful creation of our custom Sentinel rule for detecting Tor activity, 
mapped to relevant MITRE ATT&CK techniques*

---

## 4. Triggering the Rule (Simulated Threat) 
To simulate a potential insider threat, I logged into the VM and downloaded the Tor Browser. I launched it and initiated browsing activity through the Tor network to trigger the detection.

![image](https://github.com/felix2470/tor-image-project/blob/main/tor-browser-initiated.png)
![image](https://github.com/felix2470/tor-image-project/blob/main/tor-browser-initiated-2.png)
*The Images above simulate a potential insider threat*

---

## 5. Confirming the Detection
Shortly after the activity, my custom rule was triggered in Azure Sentinel, and a new incident was generated.

![image](https://github.com/felix2470/tor-image-project/blob/main/sentinel-Rule-triggered.png)

---

## 6.Investigation & Evidence Collection
I assigned the incident to myself  and further carried out the investigation:

![image](https://github.com/felix2470/tor-image-project/blob/main/asign-incident-to-myself.png)

## *I then used the Microsoft Defender portal to:*
Check Tor Browser Download Attempt

Check for file artifacts related to Tor usage (e.g., custom text files, folders)

Identify the silent installation 

Trace network connections made by the browser

Confirm the identity of the user involved

----

## A. Tor Browser Download Attempt
```kql

 // Stage 1: Tor Browser Download Attempt
    DeviceFileEvents
    | where DeviceName == "terry-vm"
    | where InitiatingProcessAccountName == "terry-vm"
    | where FolderPath contains "Download" and FolderPath contains "tor"
    | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, FileName, FolderPath, EventType = "Tor_Download"
```

![image](https://github.com/felix2470/tor-image-project/blob/main/tor-download.png)

---

## B.  Check for file artifacts related to Tor usage (e.g., custom text files, folders)

```kql
DeviceFileEvents
    | where DeviceName == "terry-vm"
    | where FileName in~ ("tor.exe", "tor")
    | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, FileName, FolderPath, EventType = "Tor_Installer"
```
![image](https://github.com/felix2470/tor-image-project/blob/main/Inspect-1.png)


--- 
##   C. Identifying the silent installation

```kql
DeviceProcessEvents
    | where DeviceName == "terry-vm"
    | where ProcessCommandLine contains "tor-browser-windows" and ProcessCommandLine contains "/S"
    | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, FileName, ProcessCommandLine, EventType = "Tor_SilentInstall"
```
![image](https://github.com/felix2470/tor-image-project/blob/main/Inspect-2.png)

--- 

## D.Network connections made by the browser

```kql
DeviceNetworkEvents
    | where DeviceName == "terry-vm"
    | where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
    | where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150,443)
    | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType,RemoteUrl,RemotePort,InitiatingProcessFileName
```

![image](https://github.com/felix2470/tor-image-project/blob/main/Inspect-3.png)


---

## E. User has been confirmed to be : Terry-vm
![image](https://github.com/felix2470/tor-image-project/blob/main/Inspect-4.png)

---

## 📅 Chronological Event Timeline

### A. File Download – TOR Installer
- **Timestamp:** 2025-05-04T21:09:14.6928475Z  
- **Event:** The user "Terry-vm" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.exe` to the Downloads folder.  
- **Action:** File download detected.  
- **File Path:** `C:\Users\Terry-vm\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### B. Process Execution – TOR Browser Installation
- **Timestamp:** 2025-05-04T21:18:57.4466881Z  
- **Event:** The user "Terry-vm" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.  
- **Action:** Process creation detected.  
- **Command:** `tor-browser-windows-x86_64-portable-14.5.exe /S`  
- **File Path:** `C:\Users\Terry-vm\Desktop\tor-browser-windows-x86_64-portable-14.0.1.exe`

### C. Process Execution – TOR Browser Launch
- **Timestamp:** 2025-05-04T21:24:31.3919252Z  
- **Event:** User "Terry-vm" opened the TOR browser. Subsequent processes such as `firefox.exe` and `tor.exe` were created, indicating successful launch.  
- **Action:** Process creation of TOR browser-related executables detected.  
- **File Path:** `C:\Users\Terry-vm\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### D. Network Connection – TOR Network
- **Timestamp:** 2025-04-25T17:44:37.9992858Z  
- **Event:** A network connection to IP `194.5.101.253` on port `443` by user "Terry-vm" was established using `tor.exe`, confirming TOR network activity.  
- **Action:** Connection success.  
- **Process:** `tor.exe`  
- **File Path:** `C:\Users\Terry-vm\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

  ---

 ## Summary
The user "terry-vm" on the "terry-vm" device initiated and completed the installation of the TOR browser.  then proceeded to launch the browser,
establish connections within the TOR network, and created various files related to TOR on their desktop,
This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes

---

## 7.Containing the Device
As part of the response, I used the Isolate Device feature in MDE to immediately disconnect the VM from the network. 
This would prevent further unauthorized activity or communication with external servers. and the user's direct manager was notified

![image](https://github.com/felix2470/tor-image-project/blob/main/device-isolation.png)

---







