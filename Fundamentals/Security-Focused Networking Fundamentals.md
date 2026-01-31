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

- Logical network segmentation for better security and performance.

### Wireless Networking

- Wi-Fi standards (802.11a/b/g/n/ac/ax)

- SSID and authentication

- Encryption: WPA2, WPA3





