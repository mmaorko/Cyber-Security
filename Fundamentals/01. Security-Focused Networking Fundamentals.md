## 1. What Is a Network? (Security Perspective)

**_A network is:_** Multiple devices communicating with each other using defined rules (protocols).

**_From a cyber security mindset,_** you should always ask:

* Who is communicating with whom?

* Through which port?

* Is the traffic encrypted or plaintext?

* Is this communication authorized?

**Wherever there is communication, there is risk.**

## 2. Types of Networks

- LAN (Local Area Network): Small area, high-speed network, e.g., in an office or home.
- MAN (Metropolitan Area Network): Covers a city or large campus.
- WAN (Wide Area Network): Covers a large geographical area. The Internet is the largest WAN.

## 3. OSI Model – Understanding Where Attacks Happen
OSI Model (7 Layers)

| Layer | Name         | Security Relevance |
| ----- | ------------ | ------------------ |
| 7     | Application  | SQL Injection, XSS |
| 6     | Presentation | SSL/TLS weaknesses |
| 5     | Session      | Session hijacking  |
| 4     | Transport    | SYN flood attacks  |
| 3     | Network      | IP spoofing        |
| 2     | Data Link    | ARP poisoning      |
| 1     | Physical     | Cable tapping      |



<details>
<summary><b>Layer 1 – Physical Layer:</b></summary>

The Physical Layer is the lowest layer of the OSI Model. It deals with the actual transmission of raw data as bits (0s and 1s).

**It includes:**

- Defines cables, connectors, and physical media
- Controls voltage levels, data rates, and transmission modes 

### Common attacks

- Cable tapping  
- Hardware keyloggers  
- Device theft  

### How the attacks work

If an attacker gains **physical access** to the environment:

- Network cables can be tapped to capture data  
- Devices can be stolen, altered, or implanted with malicious hardware  

This can **bypass most technical security controls**, regardless of how strong the software security is.

### Security Insight

- Strong physical access control systems  
- Locked server rooms and racks  
- CCTV monitoring  
- Regular hardware inventory and monitoring  

**_Physical access often means total compromise._**

---
</details>






<details>
<summary><b>Layer 2 – Data Link Layer:</b></summary>

This layer is responsible for **local network communication**.

**It does the following:**

- Uses MAC addresses to identify devices  
- Enables communication within the same network (LAN)  
- Handles switching between devices  

### Common attacks

- ARP poisoning  
- MAC flooding  
- VLAN hopping  

### How the attacks work

**Example:**
**_ARP Poisoning:_**  
An attacker sends **fake ARP replies** to devices on the network, pretending to be the default gateway.
**_MAC Flooding:_**
MAC Flooding is a network attack technique that targets Layer 2 (Data Link Layer), mainly Ethernet switches.
A switch normally learns the MAC addresses of connected devices and stores them in its MAC (CAM) table. This table helps 
the switch decide which port should receive a specific frame.

In a MAC flooding attack, the attacker sends a large number of Ethernet frames with different and usually fake source MAC addresses. 
As a result, the switch’s MAC table becomes full.

When the MAC table is full:
- The switch can no longer learn new MAC addresses
- The switch starts behaving like a hub
- Frames are broadcast to all ports instead of being sent to a specific port

This allows the attacker to capture traffic intended for other devices.
As a result:

- The attacker places themselves in the middle of communication  
- Network traffic can be intercepted (Man-in-the-Middle)  
- Credentials and session data can be stolen  

### Security Insight

- Enable Dynamic ARP Inspection (DAI)  
- Configure port security on switches  
- Use proper VLAN segmentation  
- Apply static ARP entries where possible  

**_Internal networks are not automatically trusted._**

---
</details>







<details>
<summary><b>Layer 3 – Network Layer:</b></summary>

This layer is responsible for **moving data between different networks**.

**It does the following:**

- Assigns and manages IP addresses  
- Routes packets from source to destination  
- Forwards data across multiple networks  

### Common attacks

- IP spoofing  
- Route hijacking  
- ICMP flooding  

### How the attacks work

**IP Spoofing example:**  
An attacker forges the **source IP address** of packets to make them appear to originate from a trusted system.

This allows the attacker to:

- Hide their real identity  
- Bypass IP-based trust rules  
- Launch further attacks anonymously  

### Security Insight

- Implement ingress and egress filtering  
- Use Access Control Lists (ACLs)  
- Apply anti-spoofing rules on routers  
- Continuously monitor routing changes  

**_Bad routing decisions can send sensitive data to the wrong place._**

---
</details>



<details>
<summary><b>Layer 4 – Transport Layer:</b></summary>

This layer is responsible for **end-to-end communication between systems**.

**It does the following:**

- Manages TCP and UDP connections  
- Controls data flow between sender and receiver  
- Uses port numbers to identify services  
- Ensures reliable or fast data delivery  

### Common attacks

- SYN flood  
- TCP reset attacks  
- UDP flood  

### How the attacks work

**SYN Flood example:**  
The attacker sends a huge number of TCP **SYN requests** but never completes the three-way handshake.

As a result:

- Server resources get exhausted  
- Connection tables fill up  
- Legitimate users cannot connect  

### Security Insight

- Enable SYN cookies  
- Apply rate limiting  
- Use stateful firewalls  
- Deploy IDS/IPS for traffic monitoring  

**_Most attacks at this layer focus on disrupting availability._**

---
</details>





<details>
<summary><b>Layer 5 – Session Layer:</b></summary>

This layer is responsible for **managing communication sessions** between two systems.

**It handles:**

- Establishing sessions  
- Maintaining active sessions  
- Terminating sessions properly  

**Examples include:**

- Login sessions  
- Cookies  
- Authentication tokens  

### Common attacks

- Session hijacking  
- Session fixation  
- Replay attacks  

### How the attacks work

If an attacker manages to steal a **session ID or authentication token**:

- They can impersonate the legitimate user  
- No password is needed to take over the account  
- Full access is granted within the active session  

### Security Insight

- Use **Secure** and **HttpOnly** cookies  
- Implement session expiration and inactivity timeouts  
- Rotate session tokens regularly  
- Re-authenticate users after privilege changes  

**_Compromised sessions mean compromised users._**

---
</details>



<details>
<summary><b>Layer 6 – Presentation Layer:</b></summary>

This layer is responsible for **how data is presented and secured** before it is transmitted.

**It handles:**

- Data encryption and decryption  
- Encoding and decoding  
- Compression and decompression  
- SSL/TLS operations  

### Common attacks

- Weak TLS/SSL configurations  
- SSL stripping  
- Downgrade attacks  

### How the attacks work

**SSL Stripping example:**  
An attacker forces a secure **HTTPS connection** to downgrade to **HTTP**.  

As a result:

- The user believes the connection is secure  
- Sensitive information (like passwords) is sent in plaintext  
- Data is exposed to attackers  

### Security Insight

- Use **TLS 1.2 or TLS 1.3** only  
- Disable weak cipher suites  
- Enable **HSTS (HTTP Strict Transport Security)**  
- Validate certificates properly  

**_Encryption is useless if misconfigured._**

---
</details>




<details>
<summary><b>Layer 7 – Application Layer:</b> </summary>
This is the layer closest to the user. All application-level services operate here.

**Such as:**

- Web applications
- APIs
- Email services
- Database interactions

Protocols like HTTP, HTTPS, FTP, and SMTP work at this layer.

### Common attacks
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Malicious file uploads

### How the attacks work

**SQL Injection example:**
If an application does not properly validate user input, an attacker can inject malicious SQL code.


**This can result in:**

- Authentication bypass

- Database data theft

- Data modification or deletion

### Security Insight

- Strong input validation and sanitization

- Use prepared statements / parameterized queries

- Deploy a Web Application Firewall (WAF)

- Secure API design and testing

**_Most real-world attacks target this layer._**

---

</details>



## 5. Ports, Protocols & Services
Ports, Protocols, and Services that actually make the network run. Think of this as the "who, what, and where" of every connection

**_Protocol:_** A standardized set of rules and formats that determine how data is transmitted, routed, and received across a 
network (e.g., TCP, UDP, IP). It ensures that disparate systems can interpret the data correctly.
**_Conclusion:_** The rules (the language both devices agree to speak).

**_Port:_** A logical endpoint within an operating system used to identify a specific process or application. Ports range from 0 to 65,535, 
categorized into Well-known, Registered, and Dynamic/Private ports.
**_Conclusion:_** The door (where the data enters or leaves a device).

**_Service:_** A software application or background process that "listens" on a specific port for incoming requests and executes tasks 
accordingly (e.g., a web server like Nginx or a database like PostgreSQL).
**_Conclusion:_** The program (the application waiting behind that door to do work).

### **_Understanding these "Well-Known Ports" (0-1023) is essential for network administration and security auditing:_**

| **Port** | **Protocol** | **Service**        | **Technical Function**                                                      |
| -------- | ------------ | ------------------ | --------------------------------------------------------------------------- |
| 21       | FTP          | File Transfer      | Used for command and control of file transfers between a client and server. |
| 22       | SSH          | Secure Shell       | Provides an encrypted channel for secure remote login and data transfer.    |
| 25       | SMTP         | Mail Transfer      | The standard protocol for routing and relaying email across the internet.   |
| 53       | DNS          | Name Resolution    | Resolves human-readable hostnames (example.com) into IP addresses.          |
| 80       | HTTP         | Hypertext Transfer | Used for transmitting unencrypted web traffic.                              |
| 443      | HTTPS        | HTTP over TLS      | Encrypts web traffic using SSL/TLS to ensure data integrity and privacy.    |
| 3389     | RDP          | Remote Desktop     | Enables a graphical interface for remote management of Windows systems.     |

### Security Implications
From a cybersecurity perspective, port management is a primary defense mechanism:

- **_Attack Surface Management:_** Every open port represents a potential entry point. The more services you expose, the larger your Attack Surface becomes.

- **_Reconnaissance (Footprinting):_** Threat actors use tools like Nmap or ZMap for Service Discovery. They identify open ports and "fingerprint" the
  services behind them to find specific software versions.

- **_Vulnerability Exploitation:_** If a service is outdated or misconfigured, it may be susceptible to CVEs (Common Vulnerabilities and Exposures),
  allowing attackers to gain unauthorized access or execute remote code (RCE).




## 5. Basic Networking Essentials

### TCP/IP Model

In practice, networks often use the TCP/IP model:

- Application

- Transport

- Internet

- Network Access

### IP Addressing

- IP Address: A unique identifier for each device on a network.

- IPv4: 32-bit, e.g., 192.168.1.1

- IPv6: 128-bit, more addresses and better security

**_Public vs Private IP:_**

- Public IP: Visible on the Internet

- Private IP: Used internally within a network

### Subnetting

- Dividing a large network into smaller subnets improves performance and security.

### MAC Address

- A MAC Address is a hardware-based unique identifier used at the Data Link Layer.

### Switching & Routing

**_Switching:_** Forwarding frames, MAC table, broadcast vs collision domain.
Routing: Routing table, static vs dynamic routing, default gateway.

### VLAN
A VLAN is a logical group of workstations, servers, and network devices that appear to be on the same local area network (LAN) despite their 
geographical distribution.

**_In simple terms:_** In a standard LAN, all devices connected to a physical switch can "talk" to each other. With a VLAN, you can use software to divide one physical switch into multiple virtual networks. This allows you to isolate departments (e.g., IT, HR, Finance) even if they are plugged into the same hardware.

#### Why use a VLAN? (Key Functions)
**_Security:_** You can isolate sensitive data (like Finance or Management) from general users.

**_Performance:_** It reduces "Broadcast Traffic" by breaking one large broadcast domain into smaller ones, which improves network speed.

**_Flexibility/Segmentation:_** You can change a user’s network group through software configuration without moving physical cables.

#### VLAN Security Auditing (Security Insight)
During a network audit, the following vulnerabilities are checked:

**_VLAN Hopping Attacks:_** As discussed earlier, attackers try to jump from a low-security VLAN (like Guest Wi-Fi) to a high-security one.

**_Fix:_** Disable DTP (Dynamic Trunking Protocol) on user ports and shut down unused ports.

**_The Default VLAN (VLAN 1):_** Most switches use VLAN 1 as the default. Hackers target this because it is predictable.

**_Fix:_* Change the management and native VLAN to a non-standard ID (e.g., VLAN 999).

**_Access Control:_** Even with VLANs, you need a Layer 3 device (Router or Firewall) to control traffic between VLANs. Without ACLs (Access Control Lists), segmentation is useless.

### Wireless Networking

- Wi-Fi standards (802.11a/b/g/n/ac/ax)

- SSID and authentication

- Encryption: WPA2, WPA3

### Memory Management
Memory Management is the process of intelligently controlling a computer's RAM. Its primary roles are to allocate space for new programs, use techniques like Paging and Virtual Memory to run large applications on limited RAM, and ensure that one program cannot interfere with another’s data. The biggest security threat here is the Buffer Overflow, where attackers send excessive data to take control of the system. To prevent this, operating systems use ASLR to constantly randomize memory locations and DEP to block malicious code execution. Simply put, it ensures the system’s speed, stability, and security.


## Linux Fundamentals (Very Important for Cyber Security)

In the cybersecurity world, Linux is not just an operating system — it is the foundation. Most servers, firewalls, SIEM tools, cloud platforms, and security appliances are built on Linux. That is why understanding Linux is not optional for a security specialist; it is mandatory.

### Core Navigation and Awareness

Basic commands like ls, cd, and pwd might look simple, but they are critical during investigations. A security analyst constantly moves between directories to inspect configuration files, application folders, and log locations. Using ls -la helps identify hidden files, which attackers often use to hide malicious scripts or backdoors. Knowing exactly where you are (pwd) prevents mistakes during incident response or privilege escalation testing.

### Searching and Threat Hunting

Real security work is about finding patterns inside massive data. This is where grep and find become powerful. grep is heavily used during log analysis to detect failed login attempts, suspicious commands, or indicators of compromise. On the other hand, find helps locate sensitive or dangerous files such as SUID binaries, recently modified files, or unauthorized scripts. These tools are essential for both blue team investigations and red team enumeration.

### Process Monitoring and Live Attack Detection

Commands like ps, top, and htop allow security professionals to see what is actually running on the system. During an attack, malicious processes often reveal themselves through abnormal CPU or memory usage. Crypto-mining malware, reverse shells, or unauthorized services can often be detected by closely monitoring running processes. htop is especially useful because it shows process trees and makes suspicious behavior easier to spot.

### Network Visibility and Connection Analysis

From a security perspective, networking is where compromise becomes visible. Tools such as netstat and ss show open ports, active connections, and listening services. This information is crucial for detecting backdoors, command-and-control connections, and unauthorized services. A system with unknown listening ports is almost always a red flag.

### Permissions, Ownership, and Privilege Control

Linux security is largely based on permissions. Commands like chmod and chown directly control who can read, write, or execute files. Misconfigured permissions are a common cause of privilege escalation. For example, world-writable scripts or improperly owned configuration files can allow attackers to gain root access. Understanding permissions means understanding how attackers abuse them.

### Linux Directory Structure from a Security View

Certain directories are significant for security work. The /etc directory contains configuration files for users, services, and authentication mechanisms; a small change here can compromise the entire system. The /var directory holds variable data, including logs and web files, making it a key location for forensic analysis. The /proc directory provides real-time information about running processes and system resources, which can be extremely valuable when analyzing suspicious behavior.

### Logs: The Backbone of Security Monitoring

Logs are the primary source of truth in cybersecurity. Authentication logs, system logs, and web server logs—mostly stored under /var/log/—allow analysts to reconstruct attacks, identify timelines, and understand attacker behavior. Without logs, detection and investigation become nearly impossible.



## Windows Fundamentals (Important for Cyber Security)

Windows remains the most widely used operating system in corporate environments. Because of this, a cyber security specialist must understand Windows internals to effectively detect, analyze, and respond to threats.

### Windows Internals (Basic Understanding)

Processes represent programs that are currently running on the system. By monitoring processes through tools like Task Manager or Process Explorer, security analysts can identify unknown or suspicious activity. Abnormal CPU or memory usage often indicates malware or unauthorized execution.

Services are background components that start automatically or run continuously to support system and application functionality. Malware frequently disguises itself as a legitimate service to maintain persistence. Understanding which services start at boot and under which account they run is critical for threat detection.

### Windows Registry (Security Perspective)

The Windows Registry is a centralized configuration database for the operating system. From a security standpoint, it is a favorite persistence mechanism for malware.

Attackers commonly abuse registry Run keys and startup entries to ensure malicious code executes every time the system boots. This allows malware to survive reboots while remaining stealthy and difficult to detect.

### Security Insight

- Unknown or unsigned processes may indicate compromise

- Suspicious services often hide in plain sight

- Registry-based persistence is common in real-world malware
