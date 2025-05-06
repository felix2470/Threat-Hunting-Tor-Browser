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
| **4. Recovery**         | —-----                                                                           |

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



