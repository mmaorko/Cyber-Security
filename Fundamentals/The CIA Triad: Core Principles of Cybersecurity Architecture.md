# CIA Triad: Confidentiality, Integrity, and Availability
The CIA Triad is the fundamental for any cybersecurity architecture or IT project, ensuring that sensitive data is protected, systems are trustworthy, 
and resources are accessible. It consists of three core principles: Confidentiality, Integrity, and Availability.
## 1. Confidentiality
Confidentiality ensures that sensitive data is only available to those authorized to see it. It is primarily enforced through two methods:

<details>
<summary><b>Access Control:</b> Authentication, Authorization, MFA, and RBAC</summary>

### Access Control Overview

**Access Control** ensures that only authorized users can access systems, applications, and data.  
It is built on two core security processes:

- **Authentication** – Verifying the identity of a user  
- **Authorization** – Determining what actions or resources the user is permitted to access  

---

### Authentication

Authentication confirms **who** the user is before granting access.

#### Multifactor Authentication (MFA)

**MFA** strengthens authentication by requiring multiple forms of verification:

- Something you **know** → Password, PIN  
- Something you **have** → OTP, hardware token, mobile device  
- Something you **are** → Biometric data (fingerprint, facial recognition)

Using MFA significantly reduces the risk of unauthorized access due to stolen credentials.

---

### Authorization

Authorization defines **what** an authenticated user is allowed to do.

#### ◾ Role-Based Access Control (RBAC)

**RBAC** assigns permissions based on predefined roles rather than individual users:

- Ensures users receive only the access necessary for their job function  
- Reduces administrative overhead  
- Minimizes the risk of privilege misuse or escalation  

---

> Proper implementation of Access Control is a foundational requirement for secure systems and Zero Trust architectures.

</details>


<details>
<summary><b>Encryption:</b> Protecting Data with Cryptographic Keys</summary>

### Encryption Overview

**Encryption** is the process of transforming data into an unreadable format using a **cryptographic key**,  
ensuring that only authorized parties with the correct key can access the original information.

This protects data from unauthorized access, even if it is intercepted or stolen.

---

### Symmetric Encryption

**Symmetric encryption** uses a **single pre-shared key** for both:

- **Encrypting** the data  
- **Decrypting** the data  

Because the same key is shared between parties, it is fast and efficient, but the key itself must be securely stored and transmitted.

#### Common Use Cases
- Disk encryption (e.g., BitLocker)
- Secure file storage
- Encrypted backups

---

> Encryption is a core component of **Confidentiality** in the CIA Triad and ensures data remains protected at rest and in transit.

</details>

## 2. Integrity
Integrity is the quality that ensures a message or transaction is "true to itself" and has not been modified. If data is tampered with, the system must 
be able to detect it.

**Detection Tools** 
- Technologies like digital signatures and message authentication codes (MACs) allow for comparing records to identify changes.
  
**Immutability**
- A blockchain acts as a distributed ledger where records can be added but not changed or deleted, ensuring the history remains trustworthy. 
This prevents bad actors from deleting syslogs to hide their activities.
---

## 3. Availability
Availability means that systems and resources are consistently accessible to authorized users when they need them. This is often targeted by attacks intended to crash systems:

<details>
<summary><b>Denial of Service (DoS):</b> Overwhelming Systems to Disrupt Availability</summary>

### Denial of Service (DoS) Overview

A **Denial of Service (DoS)** attack occurs when an attacker floods a system, server, or network with more **transaction requests** than it can handle.

As a result, the system becomes overloaded and is unable to respond to **legitimate users**, effectively denying access to the service.

---

### Key Characteristics

- Targets **Availability** in the CIA Triad  
- Exploits limited system resources (CPU, memory, bandwidth)  
- Typically launched from a **single source**

---

### Impact

- System slowdown or complete outage  
- Legitimate users unable to access services  
- Potential financial and reputational damage

---

> Even without data theft, a DoS attack can cause severe business disruption by making systems unavailable.

</details>


<details>
<summary><b>Distributed Denial of Service (DDoS):</b> Large-Scale Attacks Using Botnets</summary>

### Distributed Denial of Service (DDoS) Overview

A **Distributed Denial of Service (DDoS)** attack is an amplified form of a DoS attack where a **bad actor uses a botnet**—a collection of remotely controlled and compromised systems—to simultaneously flood a target with massive traffic.

Because the attack originates from multiple sources, it is significantly harder to detect and block.

---

### Key Characteristics

- Targets **Availability** in the CIA Triad  
- Traffic originates from **multiple compromised devices**  
- Often uses legitimate-looking requests to bypass basic filters

---

### Impact

- Severe service outages  
- Network congestion and resource exhaustion  
- Disruption of business-critical services

---

> DDoS attacks are designed to overwhelm infrastructure at scale, making availability defenses such as traffic filtering and rate limiting essential.

</details>


<details>
<summary><b>SYN Flood Attack:</b> Exploiting the TCP Three-Way Handshake</summary>

### SYN Flood Attack Overview

A **SYN Flood** attack exploits the TCP **three-way handshake** process by sending a large number of connection requests (**SYN packets**) without ever completing the final step of the handshake.

Because the connection is never completed, the server keeps these connections in a half-open state, eventually exhausting available resources.

---

### How the Attack Works

1. Attacker sends a **SYN** request to the server  
2. Server responds with **SYN-ACK**  
3. Attacker never sends the final **ACK**  

This causes the server to wait indefinitely for a response.

---

### Impact

- Server memory and connection tables become exhausted  
- Legitimate connection requests are dropped  
- Services become unavailable

---

### Mitigation

- **Timeout Implementation**  
  Configure the server to wait only for a limited time before closing incomplete connections and freeing up resources.

- **SYN Cookies (optional)**  
  Prevents resource allocation until the handshake is fully completed.

---

> SYN Flood attacks directly target **Availability** and are commonly used in large-scale DDoS campaigns.

</details>


By meeting the requirements of these three pillars, a project's foundational security is considered complete
