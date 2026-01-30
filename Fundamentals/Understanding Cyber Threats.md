# Types of Cyber Threats

In today’s digital world, our daily lives, work, and businesses rely heavily on the internet.
A cyber threat refers to any malicious activity or attack that aims to:

- Steal sensitive information

- Damage or disrupt systems

- Deny access to services

- Gain unauthorized access

Understanding these threats is essential for IT professionals, cybersecurity specialists, and even everyday users.

##  1️. Malware-Based Threats

Malware is any malicious software designed to harm a computer or network.

<details>
<summary><b>Virus:</b> Malware That Attaches to Legitimate Files</summary>

### Virus Overview

A **Virus** is a type of malware that attaches itself to legitimate files or programs.  
It becomes active only when the infected file is executed by the user.

Once activated, it can spread to other files and cause serious damage to the system.

---

### How a Virus Works

1. Virus attaches itself to a legitimate file or program  
2. User executes the infected file  
3. Virus activates and spreads to other files  
4. Data may be corrupted, modified, or deleted  

---

### Impact

- Corruption or deletion of files  
- System instability or crashes  
- Loss of data integrity  

---

### Example

- A virus spreading through an infected **USB drive** when plugged into a computer

---

 Virus attacks mainly impact **Integrity** and **Availability**, and can also affect **Confidentiality** in advanced cases.

</details>


<details>
<summary><b>Worm:</b> Self-Propagating Network Malware</summary>

### Worm Overview

A **Worm** is a type of malware that spreads automatically across networks  
**without requiring any user interaction**.

Unlike viruses, worms do not need to attach themselves to files.  
They exploit network vulnerabilities to replicate and spread rapidly.

---

### How a Worm Works

1. Worm exploits a network or system vulnerability  
2. Automatically copies itself to other systems on the network  
3. Continues spreading without user involvement  
4. Consumes network bandwidth and system resources  

---

### Impact

- Network congestion and slow performance  
- High CPU and memory usage  
- Service outages due to resource exhaustion  

---

### Example

- Malware spreading through **network shares** or unsecured ports

---

> Worm attacks primarily impact **Availability** and can also affect **Integrity** in severe cases.

</details>



<details>
<summary><b>Trojan Horse:</b> Malware Disguised as Legitimate Software</summary>

### Trojan Horse Overview

A **Trojan Horse** is a type of malware that **appears to be legitimate software**  
but secretly contains **hidden malicious code**.

Unlike viruses or worms, a trojan does **not self-replicate**.  
Instead, it relies on users to install or execute it.

---

### How a Trojan Works

1. Attacker disguises malware as legitimate software  
2. User downloads or installs the fake application  
3. Hidden malicious code executes in the background  
4. A **backdoor** is created, allowing attackers to access the system  

---

### Impact

- Unauthorized system access  
- Data theft or system control  
- Installation of additional malware  

---

### Example

- **Fake software cracks**, pirated tools, or modified installers

---

> Trojan attacks primarily impact **Confidentiality** and **Integrity**, and may also affect **Availability**.

</details>



<details>
<summary><b>Ransomware:</b> Malware That Encrypts Data for Ransom</summary>

### Ransomware Overview

**Ransomware** is a highly destructive type of malware that **encrypts files** on a system  
and then **demands payment** (ransom) in exchange for the decryption key.

It is considered one of the **most dangerous cyber threats** due to its ability to completely disrupt business operations.

---

### How Ransomware Works

1. Ransomware enters the system (phishing email, malicious link, or exploit)  
2. Files are encrypted using strong cryptographic algorithms  
3. User loses access to critical data  
4. Attacker demands payment for file recovery  

---

### Impact

- Complete loss of access to files  
- Business and operational downtime  
- Potential permanent data loss  

---

### CIA Triad Impact

- **Confidentiality:** Compromised  
- **Integrity:** Compromised  
- **Availability:** Compromised  

---

### Example

- Organization files encrypted after clicking a **malicious email attachment**

---

> Ransomware attacks severely impact all three pillars of the **CIA Triad** and are often financially motivated.

</details>

<details>
<summary><b>Spyware:</b> Spyware secretly tracks user activity, such as passwords, browsing history, or credit card information.</summary>

### Example

- Keyloggers or browser tracking malware.

---

</details>

<details>
<summary><b>Adware:</b> Adware is software that displays unwanted advertisements or annoys users, and sometimes can also steal user information.</summary>

### Example

- Pop-up ads or unwanted browser toolbars.

---

</details>

<details>
<summary><b>Rootkit:</b> Malware that hides deep in the system and gains administrative control without the user knowing, sometimes allowing other malware to be installed.</summary>

### Example

- Hacker-installed root access on Windows or Linux systems.

---

</details>

<details>
<summary><b>Botnet Malware:</b> Malware that allows hackers to control many infected devices at once, often used for DDoS attacks, spam campaigns, or scams.</summary>

### Example

- Thousands of infected computers attacking a website simultaneously.

---

</details>

## 2️. Network-Based Attacks

These attacks target servers or network infrastructure directly.

<details>
<summary><b>Denial of Service (DoS):</b> Disrupting System Availability</summary>

### DoS Attack Overview

A **Denial of Service (DoS)** attack attempts to **overwhelm a system** by flooding it  
with an excessive number of requests.

As a result, the system becomes unable to respond to legitimate users, causing service disruption.

---

### How a DoS Attack Works

1. Attacker sends a large volume of requests to the target system  
2. System resources (CPU, memory, bandwidth) become exhausted  
3. Legitimate user requests are delayed or dropped  
4. Services become unavailable  

---

### Impact

- Service downtime  
- Poor user experience  
- Potential financial and reputational loss  

---

### Target (CIA Triad)

- **Availability:** Compromised  

---

> DoS attacks focus solely on disrupting **Availability** and are often used as a precursor to larger DDoS attacks.

</details>


<details>
<summary><b>Distributed Denial of Service (DDoS):</b> Coordinated Network Flood Attack</summary>

### DDoS Attack Overview

A **Distributed Denial of Service (DDoS)** attack is an **amplified form of a DoS attack**  
where **multiple compromised devices**, known as a **botnet**, simultaneously send massive traffic to a target system.

Because the attack originates from many different sources at the same time, it becomes **very difficult to detect, trace, and block**.

---

### How a DDoS Attack Works

1. Attacker compromises multiple systems and forms a botnet  
2. All infected devices send traffic to the target simultaneously  
3. Target system resources become overwhelmed  
4. Legitimate users are unable to access the service  

---

### Impact

- Website or service goes offline  
- Network bandwidth exhaustion  
- Business operations disrupted  

---

### Example

- A **website suddenly goes offline** due to traffic from thousands of attacking devices

---

### Target (CIA Triad)

- **Availability:** Compromised  

---

> DDoS attacks are widely used against websites, online platforms, and critical infrastructure.

</details>


<details>
<summary><b>Man-in-the-Middle (MitM):</b> Intercepting Network Communication</summary>

### MitM Attack Overview

A **Man-in-the-Middle (MitM)** attack occurs when an attacker **secretly intercepts communication**  
between two legitimate parties without their knowledge.

The attacker can **steal sensitive data**, **modify information**, or **hijack user sessions**.

---

### How a MitM Attack Works

1. Attacker positions themselves between two communicating parties  
2. Data is intercepted as it travels across the network  
3. Sensitive information is captured or altered  
4. Communication continues without users realizing the attack  

---

### Impact

- Theft of usernames, passwords, and session tokens  
- Data manipulation or injection  
- Loss of privacy and trust  

---

### Example

- **Session hijacking over public Wi-Fi** networks

---

### Target (CIA Triad)

- **Confidentiality:** Compromised  
- **Integrity:** Compromised  

---

> MitM attacks commonly occur on unsecured networks and can be prevented using encryption and secure communication protocols.

</details>


## 3️. Web Application Attacks

These attacks exploit weaknesses in websites or web applications.

<details>
<summary><b>SQL Injection (SQLi):</b> Injecting Malicious Code into Database Queries</summary>

### SQL Injection Overview

**SQL Injection (SQLi)** is a web application attack where an attacker  
injects **malicious SQL code** into a database query through vulnerable input fields.

This allows the attacker to **steal, modify, or delete sensitive information** stored in the database.

---

### How SQL Injection Works

1. Attacker enters malicious SQL code into an input field (login form, search box, URL)  
2. Application fails to properly validate or sanitize user input  
3. Database executes the injected SQL command  
4. Data is exposed, altered, or deleted  

---

### Impact

- Unauthorized access to confidential data  
- Data modification or deletion  
- Full database compromise  

---

### Target (CIA Triad)

- **Confidentiality:** Compromised  
- **Integrity:** Compromised  

---

> SQL Injection remains one of the most critical web vulnerabilities and can be prevented using parameterized queries and input validation.

</details>


<details>
<summary><b>Cross-Site Scripting (XSS):</b> Injecting Malicious Scripts into Web Pages</summary>

### XSS Attack Overview

**Cross-Site Scripting (XSS)** is a web application attack where an attacker  
injects **malicious scripts** into trusted web pages.  

When users visit the affected pages, the scripts execute in their **browsers**, allowing the attacker to steal data or manipulate the user’s session.

---

### How XSS Works

1. Attacker injects malicious JavaScript into a web application  
2. The application does not properly validate or encode the input  
3. The malicious script is delivered to users when they load the page  
4. Script executes in the user’s browser, potentially stealing cookies or session tokens  

---

### Impact

- Session hijacking  
- Credential theft  
- Malicious redirection or content injection  

---

### Example

- A malicious script stealing session cookies when a user logs into a website  

---

### Target (CIA Triad)

- **Confidentiality:** Compromised  
- **Integrity:** Compromised  

---

> XSS attacks exploit trust in a website and can be prevented using proper input validation, output encoding, and Content Security Policy (CSP).

</details>


<details>
<summary><b>Cross-Site Request Forgery (CSRF):</b> Forcing Unauthorized User Actions</summary>

### CSRF Attack Overview

**Cross-Site Request Forgery (CSRF)** is a web application attack that  
**forces authenticated users** to perform actions **without their knowledge or consent**.

The attacker abuses the user’s trusted session with a legitimate website.

---

### How a CSRF Attack Works

1. User logs into a trusted website and remains authenticated  
2. Attacker tricks the user into clicking a malicious link or visiting a crafted webpage  
3. Browser automatically sends authenticated requests to the trusted site  
4. Unauthorized actions are executed on behalf of the user  

---

### Impact

- Unauthorized password changes  
- Unauthorized fund transfers  
- Account or profile manipulation  

---

### Example

- User unknowingly triggers a **password change** or **money transfer**

---

### Target (CIA Triad)

- **Integrity:** Compromised  

---

> CSRF attacks can be prevented using CSRF tokens, same-site cookies, and proper request validation.

</details>


## 4️. Social Engineering Attacks

These attacks exploit human psychology rather than technical vulnerabilities.

<details>
<summary><b>Phishing:</b> Tricking Users into Revealing Sensitive Information</summary>

### Phishing Attack Overview

**Phishing** is a social engineering attack where attackers use **fake emails, messages, or websites**  
to trick users into **disclosing sensitive information** like usernames, passwords, or credit card details.

Phishing relies on **human psychology** rather than exploiting software vulnerabilities.

---

### How Phishing Works

1. Attacker creates a **fake email or website** that looks legitimate  
2. User receives the phishing message and clicks on the link or opens an attachment  
3. User enters sensitive information thinking it is a legitimate site  
4. Attacker collects the credentials or sensitive data  

---

### Impact

- Compromised login credentials  
- Unauthorized access to accounts  
- Financial loss and identity theft  

---

### Example

- A **fake bank email** asking the user to "verify account details"  

---

### Target (CIA Triad)

- **Confidentiality:** Compromised  

---

> Phishing attacks are one of the most common and effective cyber threats and can be prevented using user awareness, email filtering, and multi-factor authentication (MFA).

</details>


<details>
<summary><b>Spear Phishing:</b> Targeted Social Engineering Attack</summary>

### Spear Phishing Overview

**Spear Phishing** is a **highly targeted form of phishing**  
that is aimed at **specific individuals, teams, or organizations**.

Unlike generic phishing, these attacks are **carefully researched** to appear more personal and trustworthy.

---

### How Spear Phishing Works

1. Attacker gathers information about the target (job role, organization, contacts)  
2. A personalized email or message is crafted  
3. Target receives the message and trusts it due to its relevance  
4. Credentials, sensitive data, or access is compromised  

---

### Impact

- Compromise of high-value accounts  
- Data breaches and financial loss  
- Potential entry point for larger attacks  

---

### Example

- An email appearing to come from a **company executive or IT department** requesting urgent action  

---

### Target (CIA Triad)

- **Confidentiality:** Compromised  

---

> Spear phishing attacks are difficult to detect and are often the first step in advanced cyber attacks.

</details>


<details>
<summary><b>Pretexting:</b> Obtaining Information Through Fake Scenarios</summary>

### Pretexting Attack Overview

**Pretexting** is a social engineering attack where an attacker  
**creates a false story or scenario** to gain the victim’s trust  
and trick them into revealing **confidential or sensitive information**.

The attacker often pretends to be a trusted authority or service provider.

---

### How Pretexting Works

1. Attacker creates a believable fake identity or situation  
2. Victim is contacted via email, phone call, or message  
3. Attacker builds trust using urgency or authority  
4. Victim unknowingly shares confidential information  

---

### Impact

- Exposure of sensitive personal or organizational data  
- Identity theft or account compromise  
- Financial or reputational damage  

---

### Example

- **Fake bank emails** or phone calls asking to “verify account details”

---

### Target (CIA Triad)

- **Confidentiality:** Compromised  

---

> Pretexting relies heavily on manipulation and trust, making user awareness and verification procedures critical defenses.

</details>


## 5️. Credential-Based Attacks

<details>
<summary><b>Brute Force Attack:</b> Guessing Passwords by Repeated Attempts</summary>

### Brute Force Attack Overview

A **Brute Force attack** is a method where an attacker repeatedly tries  
different password combinations until the correct one is found.

There is no clever trick involved—  
the attacker simply keeps guessing every possible password until they succeed.

This type of attack becomes effective when weak or short passwords are used  
and when the system allows unlimited login attempts.

---

### How a Brute Force Attack Works

1. The attacker targets a login page or user account  
2. Automated tools are used to try many password combinations  
3. The system does not restrict repeated login attempts  
4. Eventually, the correct password is discovered  

---

### Impact

- Unauthorized access to user accounts  
- Exposure of sensitive or private information  
- Potential misuse of systems or services  

---

### Example

- Repeated login attempts against an email or administrator account  

---

### Target (CIA Triad)

- **Confidentiality:** Compromised  

---

> Brute force attacks can be prevented by using strong passwords, login attempt limits, account lockout policies, and Multi-Factor Authentication (MFA).

</details>


<details>
<summary><b>Credential Stuffing:</b> Reusing Stolen Login Credentials</summary>

### Credential Stuffing Overview

**Credential Stuffing** is a credential-based attack where attackers use  
**stolen usernames and passwords from previous data breaches** to access other systems.

This attack works because many users **reuse the same password** across multiple websites.

---

### How It Works

1. Attacker obtains leaked credentials from a breach  
2. Automated tools test those credentials on other services  
3. Password reuse allows successful logins  
4. Accounts are compromised  

---

### Impact

- Unauthorized account access  
- Data and privacy breaches  

---

### Target (CIA Triad)

- **Confidentiality:** Compromised  

---

> Unique passwords and Multi-Factor Authentication (MFA) are the most effective defenses.

</details>


<details>
<summary><b>Keylogging:</b> Recording User Keystrokes</summary>

### Keylogging Overview

**Keylogging** is an attack where malicious software or hardware  
**records every keystroke** typed by a user to capture sensitive data like passwords.

---

### Impact

- Theft of login credentials  
- Loss of sensitive information  

---

### Target (CIA Triad)

- **Confidentiality:** Compromised  

---

> Anti-malware tools and secure authentication methods help prevent keylogging attacks.

</details>


## 6️. Insider Threats

Threats originating from inside an organization.

Malicious Insider: Intentionally stealing or damaging data

Negligent Insider: Accidental data leaks due to carelessness
 Example: Sending sensitive files to the wrong recipient via email

## 7️. Advanced Persistent Threats (APT)

Long-term, targeted attacks

Gradually steal critical data

Usually carried out by well-funded groups or state-sponsored actors

 Typical Targets: Government agencies, banks, ISPs

## 8️. Supply Chain Attacks

Target third-party software or vendors

Malicious code enters systems via software updates or dependencies
 Example: Compromised software update
