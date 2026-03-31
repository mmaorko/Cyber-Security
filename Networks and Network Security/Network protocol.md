What is a Network Protocol?
Networks need rules to function properly. These rules are called network protocols — a set of guidelines that two or more devices follow to determine the order of delivery and 
structure of data sent across a network.
Imagine you type www.yourcomany.org into your browser. Just to load that one website, your device uses four different protocols working together behind the scenes.

### Domain Name System(DNS): 
Computers do not understand human-readable names; they only understand IP addresses. When you type a domain name, DNS translates it into an IP address (e.g., 192.0.2.1).

#### **_Security View:_**
- Attack Process:
An attacker injects false information into a DNS server. For example, the real IP of mybank.com (1.1.1.1) is replaced with a fake IP (2.2.2.2) controlled by the attacker.

- Result:
When users type the bank’s website, they are redirected to a fake website created by the attacker and may unknowingly enter their login credentials.

- What Analysts Check:
If a domain suddenly resolves to an unfamiliar IP address or a geographically unusual location, it is a red flag.

### Transmission Control Protocol (TCP): 
Before any data is exchanged, your device and the web server must "meet" each other. TCP handles this by performing a handshake — a verification process that confirms both 
devices are ready to communicate. Only after this handshake does data start flowing.
It uses a 3-Way Handshake (SYN → SYN-ACK → ACK) to ensure both sides are ready for data communication.

#### **_Security View:_**
- Attack Process:
The attacker sends thousands of SYN requests to a server. The server responds with SYN-ACK and waits for the final ACK (creating half-open connections).

- Result:
The attacker never sends the final ACK. The server’s resources get exhausted maintaining these incomplete connections, preventing legitimate users from accessing the service.

- What Analysts Check:
If a SIEM tool shows a high number of incomplete TCP handshakes from a single source IP, that IP should be quickly blocked.

### Address Resolution Protocol (ARP): 
Data travels across the network in packets, hopping through multiple routers. ARP figures out the MAC address of the next router or device along the path, making sure the data 
reaches the right destination.

#### **_Security View:_**
The biggest weakness of the ARP protocol is that it trusts any reply without verification.
- Attack Process:
An attacker inside a local network tells the router, “I am the victim user,” and tells the victim, “I am the router.”
- Result:
All network traffic is routed through the attacker’s machine. This is known as an on-path (Man-in-the-Middle) attack. The attacker can steal passwords or modify data.
- What Analysts Check:
If a network scan shows the same MAC address assigned to multiple IP addresses, it is a strong indication of ARP poisoning.

### HyperText Transfer Protocol Secure (HTTPS)
Once the connection is established, HTTPS handles the actual request for the webpage. It provides a secure, encrypted channel between your browser and the web server
using SSL/TLS technology, keeping your data safe from attackers.

#### **_Security View:_**

Attackers now use HTTPS to hide malicious traffic. Since the traffic is encrypted, traditional firewalls or intrusion prevention systems (IPS) often cannot see what is inside the data, allowing malware to pass through undetected.

 **_How Is This Tackled?_**
Large organizations use a technique called SSL/TLS Inspection (Break and Inspect). Encrypted traffic is intercepted at the gatewayIt is decrypted and inspected for threats
Then it is re-encrypted and sent to its destination. This allows security systems to detect hidden malware within encrypted traffic.

**_Common Misconception_**

Many people believe that if a website uses HTTPS, it is completely safe.

Reality:
HTTPS only ensures that the connection is encrypted. It does not guarantee that the website itself is trustworthy.
Attackers can easily create phishing sites (e.g., secure-login-bank.com) and obtain free SSL certificates from services like Let’s Encrypt, enabling HTTPS on malicious websites.
