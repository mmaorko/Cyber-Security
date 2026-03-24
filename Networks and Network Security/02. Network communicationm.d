# Network communication
Network communication is the process through which two or more devices exchange data with each other. It is similar to a postal system—where a letter (Data Packet) is sent to a 
specific address (IP Address) using certain rules (Protocols) and a medium (Cables/Wi-Fi).
## Anatomy of a Data Packet:
The analogy of a letter used in the text is an excellent example for understanding packet encapsulation. 
### A packet has three main parts:
- Header (Envelope): Contains Source IP, Destination IP, and MAC Address. It also includes the Protocol Number, which tells the device what type of data it is (e.g., TCP or UDP).
- Payload/Body (Letter): This is the actual message. It could be part of an email or even a command from malware.
- Footer/Trailer (Signature): Usually contains a Checksum, which ensures that the data has not been corrupted or altered during transit.
## How Data Travels (Encapsulation)
During communication, data does not travel directly; it passes through various layers in the form of a “packet.” Each layer adds additional information (Header) to the data.
- Application Layer: Your email or web request is created.
- Transport Layer: Data is divided into smaller segments and assigned a port number (TCP/UDP).
- Network Layer: Source and destination IP addresses are added.
- Data Link Layer: Hardware MAC addresses are added.
- Physical Layer: Finally, the data is transmitted as electrical signals or light pulses through cables.
## Bandwidth and Speed: Why do security analysts monitor this?
Bandwidth is like the width of a pipe—the amount of data that can travel per second. It is very important for security monitoring because:
- DDoS Attack: If the bandwidth usage suddenly spikes, it indicates that a DDoS attack might be happening on your network.
- Data Exfiltration: If you notice unusually high bandwidth usage in the middle of the night (outside office hours) sending data to an unknown external IP, it could mean someone is stealing sensitive files from your company.
## Packet Sniffing:
Packet Sniffing mentioned in the text is a key task of a security analyst. When you use tools like Wireshark or tcpdump, you are essentially capturing and analyzing these packets.
- The Problem: If the network is unencrypted (e.g., HTTP or Telnet), anyone sniffing the traffic can see user passwords or credit card numbers.
- The Solution: As a defensive professional, your job is to sniff the network to identify any unencrypted traffic.

## Why is this important for a Security Analyst?
By properly understanding network communication, you can perform the following tasks:
- Traffic Analysis: Identify unusual network traffic (e.g., data transfer over unexpected ports).
- Incident Response: In case of an attack (e.g., Man-in-the-Middle), quickly determine which layer or protocol is being used.
- Vulnerability Management: Recognize which protocols are insecure (e.g., Telnet or FTP) and ensure they are replaced with secure protocols (SSH or SFTP).
