<p align="center">
  <img src="https://abishekponmudi.github.io/Abishek.site/images/planqx.png" alt="PlanqX EDR">
</p>

# Endpoint Detection and Response (EDR) Solution for windows Environment 
NOTE : THE DOCUMENTATION ARE MENTIONED BELOW , IF DOWNLOAD OR TESTING PLEASE ! VISIT HERE [installation process](#installation)

##See Demo (Installation and configuration part)
[![Watch the video](https://drive.google.com/file/d/1d40pjPEzXpGWIg8lgeoD5Ntx7Mpk25s4/view?usp=sharing)


## Table of Contents
- [Overview](#overview)
- [Project Objectives](#project-objectives)
- [System Architecture](#system-architecture)
- [Project Workflow](#project-workflow)
- [Component Details](#component-details)
  - [Network Analysis Module](#1-network-analysis-module)
  - [Malware Analysis and Detection](#2-malware-analysis-and-detection)
  - [System-Level Analysis](#3-system-level-analysis)
  - [Forwarder Mechanism](#4-forwarder-mechanism)
- [Data Collection and Analysis](#data-collection-and-analysis)
- [Malware Analysis Research](#malware-analysis-research)
  - [Advanced Static Analysis Techniques](#advanced-static-analysis-techniques)
  - [Dynamic Analysis Methods](#dynamic-analysis-methods)
- [Implementation Details](#implementation-details)
- [GitHub Repository](#github-repository)
- [Conclusion and Future Work](#conclusion-and-future-work)

## Overview
The **Custom Endpoint Detection and Response (EDR) Solution** is a cybersecurity tool designed to protect enterprise environments from a wide range of cyber threats. It provides capabilities for real-time detection, analysis, and response to malicious activities on endpoint devices, such as desktops, laptops, and servers. The solution integrates several advanced detection methodologies, including network traffic monitoring, malware detection, and system behavior analysis, making it an essential tool for modern organizations to maintain security and resilience against cyber attacks.

## Project Objectives
The main goals of this EDR solution are:

- **Real-Time Threat Detection:** Implement monitoring mechanisms to identify any signs of malicious activity, such as malware execution, process injections, unauthorized access attempts, and network anomalies, in real time.
- **Advanced Analysis and Reporting:** Develop a framework for comprehensive data collection, forwarding collected data to a centralized server for in-depth analysis, and generating detailed reports to provide insights into potential threats.
- **Modular and Scalable Design:** Create a modular architecture that can be easily extended to include additional security features and can scale to support large numbers of endpoints without significant performance degradation.
- **Leverage Malware Analysis Research:** Utilize the latest malware analysis research and techniques to enhance the accuracy of threat detection, reduce false positives, and provide actionable intelligence.

## System Architecture
The system follows a client-server architecture to efficiently handle the processes of data collection, transmission, analysis, and response. This architecture allows for centralized management and scalability, making it suitable for large and complex networks.

### Architecture Components

- **Client Module:** A lightweight client module is deployed on each endpoint device. This module continuously monitors system activity, such as running processes, file operations, network connections, and system configuration changes. It collects relevant data and securely transmits it to the centralized server for further analysis.
- **Forwarder Mechanism:** A robust mechanism that ensures secure and efficient transmission of collected data from the client module to the server. It handles data encryption, compression, and batching to optimize the use of network resources.
- **Server Module:** A centralized server that receives and processes data from multiple clients. It runs various analysis techniques to detect threats and stores the results in a secure database for further investigation.
- **Analysis Engine:** A core component of the server module that performs in-depth analysis of the collected data. It uses multiple techniques, including static and dynamic malware analysis, anomaly detection, and behavioral analysis, to identify potential threats and generate alerts.

### Architecture Diagram
<p align="center">
  <img src="https://github.com/AbishekPonmudi/PlanqX_EDR-Endpoint-Detection-and-Response/blob/master/playbooks-crowd-strike-falcon---true-positive-incident-handling-__-doc_files-CrowdStrike_Falcon_-_True_Positive_Incident_Handling-cdf042f55c5b373b5777d4737ffe0a61.jpg?raw=true" alt="PlanqX EDR">
</p>

## Project Workflow

### 1. Data Collection
The client module initiates the data collection process, gathering information from the endpoint. This includes:
   - **System Information:** Details about the operating system, hardware, installed applications, running processes, and system configurations.
   - **Network Data:** Information on active network connections, traffic patterns, and any unusual or suspicious network activity.
   - **File Activity Logs:** Records of file creation, modification, deletion, and unauthorized access attempts that could indicate malicious activity.

### 2. Data Forwarding
The **Forwarder Mechanism** is responsible for securely transmitting the collected data to the server. It performs the following tasks:
   - **Data Encryption:** Encrypts data using advanced cryptographic standards to ensure confidentiality during transmission.
   - **Compression:** Reduces the size of the data to optimize bandwidth usage and improve transmission speed.
   - **Batching:** Groups smaller pieces of data into larger batches to minimize the frequency of transmissions and reduce network overhead.

### 3. Data Analysis
The **Analysis Engine** on the server processes the incoming data in several stages:
   - **Preprocessing:** Cleans and organizes the data to prepare it for analysis, removing any irrelevant or redundant information.
   - **Static Analysis:** Examines files and processes for known malware signatures, suspicious strings, or unusual attributes. This includes checking against known malware databases and using YARA rules.
   - **Dynamic Analysis:** Observes the behavior of files and processes in a controlled environment (sandboxing) to detect any malicious actions that may not be evident through static analysis.
   - **Anomaly Detection:** Utilizes machine learning algorithms to identify deviations from normal behavior patterns that could indicate a potential threat.
   - **Rule-Based Detection:** Applies custom detection rules and signatures to identify known threats and emerging attack techniques.

### 4. Alert Generation
If malicious activity is detected, the system generates alerts containing detailed information, such as:
   - **Threat Type:** A classification of the detected threat (e.g., malware, intrusion, data exfiltration).
   - **Severity Level:** An assessment of the potential impact of the threat on the system or network.
   - **Recommended Actions:** Guidance on how to respond to the detected threat, such as isolating the affected endpoint or blocking a specific IP address.

### 5. Reporting and Response
After generating alerts, the system creates detailed reports that are accessible to the security team. These reports include:
   - **Incident Summary:** An overview of the detected threat, including its source, type, and potential impact.
   - **Detailed Analysis:** In-depth information on the threat, including the affected systems, files, and processes, as well as any observed behavior patterns.
   - **Response Actions:** Suggested or automated actions taken by the system to mitigate the threat, such as quarantining files, terminating malicious processes, or blocking network connections.

## Component Details

### 1. Network Analysis Module
The **Network Analysis Module** is responsible for monitoring network activity to detect network-based threats. It focuses on identifying malicious behavior patterns such as:

- **Command and Control (C2) Communication:** Detects connections to known C2 servers, which are often used by attackers to remotely control compromised systems.
- **Data Exfiltration:** Identifies unusual outbound traffic that could indicate unauthorized data transfer from the network.
- **Lateral Movement:** Monitors internal network traffic to detect attempts by attackers to move laterally within the network, compromising additional systems.

**Techniques Used:**
- **Packet Capture and Analysis:** Continuously captures and analyzes network packets to identify potential threats.
- **Protocol Anomaly Detection:** Monitors network traffic for deviations from normal protocol behavior, which may indicate malicious activity.
- **Machine Learning Models:** Uses machine learning algorithms to identify patterns of malicious network behavior that may not be detectable through traditional signature-based methods.

### 2. Malware Analysis and Detection
This module is designed to detect malware on endpoint devices using a combination of static, dynamic, and behavioral analysis techniques:

- **Static Analysis:** Analyzes executable files without running them, looking for known malware signatures, suspicious strings, and unusual file attributes.
- **Dynamic Analysis:** Executes files in a controlled sandbox environment to observe their behavior and detect any malicious actions, such as file modification, registry changes, or network communication with C2 servers.
- **Behavioral Analysis:** Monitors the behavior of running processes in real-time to detect suspicious activities, such as attempts to escalate privileges, modify system settings, or communicate with external servers.

**Key Features:**
- **Integration with YARA Rules:** Uses YARA rules to identify known and emerging threats based on their characteristics and behavior patterns.
- **PE Analysis:** Analyzes Portable Executable (PE) files for malicious indicators, such as suspicious imports, obfuscated code, or unusual section headers.
- **DLL Injection Detection:** Detects attempts to inject malicious Dynamic Link Libraries (DLLs) into legitimate processes, a common technique used by attackers to evade detection.

### 3. System-Level Analysis
The **System-Level Analysis** module monitors the endpoint for suspicious activities at the system level, providing comprehensive protection against various types of attacks:

- **Process Monitoring:** Tracks the creation, modification, and termination of processes to detect any suspicious behavior, such as unauthorized execution of scripts or malware.
- **Registry Monitoring:** Observes changes to the Windows Registry, which could indicate attempts to modify system settings or establish persistence.
- **File System Monitoring:** Monitors file activity, such as creation, modification, and deletion of files, to detect potential threats like ransomware or data exfiltration.

**Techniques Used:**
- **Hooking and API Monitoring:** Intercepts and monitors API calls made by applications to detect suspicious behavior, such as attempts to bypass security controls or access sensitive data.
- **Behavioral Analysis:** Analyzes the behavior of applications and processes in real-time to identify deviations from normal patterns, which may indicate malicious activity.

### 4. Forwarder Mechanism
The **Forwarder Mechanism** is designed to ensure reliable data transmission between the client and server components of the EDR solution. It is responsible for:

- **Efficient Data Transfer:** Optimizes data transmission to minimize the impact on network performance and reduce the time required to send data from the client to the server.
- **Secure Communication:** Ensures the confidentiality and integrity of data during transmission using strong encryption algorithms.
- **Data Batching and Compression:** Groups smaller pieces of data into larger batches and compresses them to reduce network overhead and improve transmission speed.

## Data Collection and Analysis
The solution's **Data Collection and Analysis** framework is responsible for gathering relevant information from endpoint devices and analyzing it to detect potential threats. The framework is designed to:

- **Collect Comprehensive Data:** Gather information from various sources, including system logs, network traffic, process activity, and file operations, to provide a holistic view of the endpoint's security posture.
- **Utilize Multiple Analysis Techniques:** Combine static, dynamic, and behavioral analysis methods to detect a wide range of threats, from known malware to zero-day attacks.
- **Generate Actionable Intelligence:** Provide security teams with detailed insights into potential threats, enabling them to respond quickly and effectively.

## Malware Analysis Research

### Advanced Static Analysis Techniques
- **Signature-Based Detection:** Uses predefined signatures of known malware to detect threats.
- **YARA Rules:** Allows for flexible pattern matching based on specific strings or sequences of instructions within files.
- **Entropy Analysis:** Detects packed or obfuscated files by analyzing their entropy levels.
- **PE File Structure Analysis:** Inspects the headers, imports, exports, and other characteristics of PE files to identify anomalies.

### Dynamic Analysis Methods
- **Sandboxing:** Executes suspicious files in a controlled environment to observe their behavior without risking the security of the endpoint or network.
- **API Call Monitoring:** Monitors API calls made by an application to detect malicious actions, such as privilege escalation or unauthorized data access.
- **Memory Analysis:** Inspects the memory of running processes for signs of malware, such as injected code or suspicious strings.
- **Behavioral Analysis:** Uses machine learning models to identify patterns of malicious behavior that may not be detectable through traditional static analysis methods.

## Implementation Details
The solution is implemented using a combination of programming languages, tools, and frameworks suitable for real-time data collection, analysis, and reporting:

- **Python:** Used for developing the core components of the solution, including the client module, server module, and analysis engine.
- **C++:** Utilized for performance-critical tasks, such as monitoring low-level system activities and network traffic.
- **SQL:** Employed for managing and querying the database that stores collected data, analysis results, and threat intelligence.
- **REST APIs:** Enables secure communication between the client and server components, supporting data transmission, analysis requests, and alert generation.

## installation
You can install server component on windows manually!! (FOR LINUX SERVER WILL BE RELEASED AS SOON!!)

```bash
      PlanqxSetup.exe
```
which will open do the initial setup on the Server side and Planqx-CLI server can be accessable 

## This is now Only Developed like wokring By Manually Configuration between client and server so it will be updated soon!!!!

Ok let have the deep understanding about the above section this is the windows exploit suggestor this is used to detect the vulnerbity that are not yest patched on the windows system and this alll get through the vulnerbility database Named CVE (Common Vulnerabilities and Exposures) [cve.org](https://cve.mitre.org/) this contain the common vulnerbity and more TTP about the recent Vulnerbilities ans by using the windows exploit suggestor we can also this find the Patch information and exposures.

### custom Malware Analysis
Next there is a Malware analyser built using the Signature based analysis ,YARA , PE Header analysis , Integrated with API (Virustotal,ClamAV,binwalk) this are the Part of the Static based analysis , also have some research work to integrate the Dynamic based malware analysis using the Sandbox and ML based analysis. For learn please refer this [research_work](https://midi-fox-ef1.notion.site/Malware-analysis-using-ML-model-Research-68ec135c6aa64754929e869262325ba9).Let see what we done!
#### Signature based analysis :
This is the Traditional methods to analysis the Malware analysis this methods include the IOC of the Malware signature , we developed the Malware analyser with python that convert the sysf ttem files into the hashes and match with the existing IOC and if the signature mathces it mark it as flag and do this (Critical, warning, Remove, Quaritane). and this will struggle with analys the unknown malware so that we implemented the new methods let see below!
#### YARA Rules based analysis:
THis is also the another method of anlaysis interrecpted with Malware anslysis , Traffic analysis, signature analysis and more.., Ok here we see Malware analysis,

## How it works internally :
First it generate the system information from the windows using the windows API named systeminfo this will further analysed using the wes module 

## GitHub Repository
The source code for this project is available on GitHub. Visit the repository to explore the codebase, contribute to the project, or report issues:

- **GitHub Repository:** [Link to Your Repository](https://github.com/abishekponmudi/threat-intelligence-platform)

## Conclusion and Future Work
The Custom EDR Solution is a powerful tool designed to provide comprehensive protection against a wide range of cyber threats. By integrating advanced detection techniques, leveraging malware analysis research, and adopting a modular and scalable design, the solution is well-suited to meet the security needs of modern organizations.

### Future Enhancements:
- **Integration with Threat Intelligence Feeds:** Enhance detection capabilities by incorporating real-time threat intelligence from external sources.
- **Machine Learning Models for Anomaly Detection:** Develop and deploy advanced machine learning models to improve detection accuracy and reduce false positives.
- **Support for Additional Operating Systems:** Expand the solution to support additional operating systems, such as Linux and macOS.
- **User-Friendly Dashboard:** Create a web-based dashboard for monitoring and managing endpoints, viewing alerts, and generating reports.

---

Feel free to contribute and collaborate! If you have any questions about the modules or code, or if you'd like to understand what's going on, please contact me on [X.com](https://x.com/Havox03).
