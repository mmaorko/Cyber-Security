## 1. Operating System Architecture
To enter the world of cyber security, it is essential to have a strong understanding of how an operating system works.

### Kernel
The kernel is the core of the operating system. You must understand how the kernel communicates with hardware and manages system memory.
Security importance

- If the kernel is compromised → attacker owns the system
- Kernel exploits = root/admin access

### User Space vs Kernel Space
Understanding the difference between user space and kernel space is crucial for security, because many attacks directly target the kernel.
| User Space            | Kernel Space        |
| --------------------- | ------------------- |
| Applications run here | Kernel runs here    |
| Limited privileges    | Full privileges     |
| Crash is safe         | Crash = system down |

**_How They Work Together_**
- System Calls: Applications in user space cannot directly interact with hardware. Instead, they make system calls (e.g., read(), write()) to request services from the kernel.
- Context Switching: The CPU switches between user mode and kernel mode when handling system calls or interrupts.
- Protection: This separation prevents faulty or malicious applications from corrupting the OS or hardware.
**_Why the Separation Matters_**
- Security: Prevents unauthorized access to sensitive system resources.
- Stability: Application crashes don’t bring down the entire system.
- Efficiency: Kernel manages resources centrally, ensuring fair allocation and performance.

## 2. File Systems
You should have knowledge of file systems such as NTFS for Windows and EXT4 or XFS for Linux. Understanding file permissions 
(Read, Write, Execute) is a fundamental step in cyber security. In cyber security, this matters a lot because attackers and 
defenders both care about files.
### Windows File System: NTFS (Security Perspective):
NTFS uses Access Control Lists (ACLs).That means every file has a list that says:
- which user can read it
- which user can write to it
- which user has full control

**_Why does this matter in cyber security?_**
If a high-privilege program (like a service running as SYSTEM) uses a file that:
- a normal user can write to

then an attacker can replace that file.

What happens next?
- The service restarts
- The attacker’s file runs as SYSTEM

 This is a classic privilege escalation attack.

NTFS also supports Alternate Data Streams (ADS), which attackers can abuse to hide malicious data inside normal files.

### Linux File Systems: EXT4 / XFS (Security Perspective)
Linux usually uses EXT4 or XFS.
Linux permissions are simpler and cleaner:
- Read (r)
- Write (w)
- Execute (x)

And permissions are applied to:
- Owner
- Group
- Others
### Why permissions are critical in Linux security

Attackers look for:
- world-writable files
- scripts run by root
- SUID binaries
A single wrong permission can lead directly to root access.

### Why Execute permission is so important
In Linux:
- If a file is not executable, it cannot run.
- Malware must have execute permission to work.
- Scripts abused by attackers usually need write + execute access.

## 3. Processes & Services
Your Operating System isn’t just a single program; it’s a collection of many small programs running simultaneously. 
Some are launched by you, some start automatically, and others run hidden in the background. These active programs 
are what we call Processes and Services.
### Process:
A Process is essentially a program in execution. When you perform an action—such as opening a Browser, launching a Text Editor, 
or running a Terminal—the Operating System creates a dedicated process for that task.

Every process is equipped with its own:
- Memory Space: Dedicated RAM for its operations.
- Process ID (PID): A unique identifier assigned by the OS.
- Permissions: Defined access rights and limits.

The Security Advantage: One of the most critical security features is Process Isolation. If a process crashes, 
it only terminates that specific program without affecting the stability of the entire system.

### Why is a Process Important in Cyber Security?
In the world of cybersecurity, understanding processes is non-negotiable because almost every attack or defense 
mechanism revolves around them.

### Key Reasons:
- **_Malware Execution:_** At its core, malware is simply a malicious program that must run as a Process to perform its
  tasks (stealing data, encrypting files, etc.).
- **_Process Injection:_** Advanced attackers don't always start a new, suspicious process. Instead, they "inject"
  malicious code into an already running, legitimate process to bypass security filters.
- **_Targeting Sensitive Processes:_** Attackers target specific system processes to steal credentials.
  For example, on Windows, the lsass.exe (Local Security Authority Subsystem Service) is a prime target for
  dumping passwords from memory.
- **_Stealth & Persistence:_** Many threats hide behind Trusted Processes (like svchost.exe or explorer.exe) to remain
  invisible to the average user and basic antivirus software.

#### Crucial Examples:
- **_Browser Hijacking:_** Injecting malicious code into a browser process to steal cookies, session tokens, or saved passwords.
- **_Credential Dumping:_** Targeting the lsass process to extract plain-text passwords or NTLM hashes.
- **_Living off the Land (LotL):_** Using legitimate OS processes (like PowerShell or CMD) to carry out an attack, making it harder 
to detect.

**_The Important Note:_**
Without a deep understanding of how processes function, isolate memory, and manage permissions, it is nearly impossible to 
analyze malware behavior or defend against sophisticated exploits.

### Service
A Service (known as a Daemon in Linux) is a specialized type of process that operates independently of user interaction. Unlike regular applications, 
services are designed to ensure the operating system functions correctly behind the scenes.

#### Key Characteristics of a Service:
- **_Background Operation:_** Services do not have a user interface (UI). They run silently in the background without the user's direct involvement.
- **_Automatic Startup:_** Most services are configured to launch automatically as soon as the system boots up, even before any user logs in.
- **_High Privilege Level:_** Services often run with elevated permissions, such as SYSTEM (on Windows) or root (on Linux). This gives them deep access to the hardware and OS kernel.
- **_Persistent Nature:_** They are designed to stay active for the entire duration of the system's uptime.

#### Common Responsibilities of a Service:
- **_Networking:_** Managing Wi-Fi, Ethernet connections, and network protocols.
- **_Authentication:_** Handling the user login process and security checks.
- **_System Maintenance:_** Checking for updates, managing printer queues, and disk defragmentation.
- **_Hosting Servers:_** Running web servers (like Apache or Nginx) or database servers (like MySQL).

#### The Cyber Security Perspective:
Because services run with high privileges and start automatically, they are prime targets for hackers. If an attacker can replace a legitimate 
service with a malicious one, they gain full control over the system every time it turns on, often without the user ever noticing.


#### Why are Services Considered High-Risk in Cyber Security?
In a secure environment, services are often viewed as potential entry points or "weak links" because of their inherent nature and high level of 
authority within the Operating System.
#### The Risk Factors:
- **_Continuous Operation:_** Services are designed to run indefinitely. This constant activity provides a permanent window for attackers to exploit vulnerabilities.
- **_Auto-Resilience (Self-Restarting):_** Most services are configured to restart automatically if they fail or if the system reboots. For a hacker, this means their
  malicious code can stay active without manual intervention.
**_Elevated Privileges:_** Many services operate with SYSTEM or root level permissions. If a service is compromised, the attacker instantly gains the highest level of
  control over the machine.
**_Lack of Visibility:_** Since services run in the background without a User Interface (UI), malicious activity often goes unnoticed by the average user.

#### How Attackers Exploit Services:
- **_Persistence:_** By installing a malicious service or hijacking an existing one, hackers ensure they "stay" in the system even after a reboot.
  This is a primary method for maintaining a long-term foothold.
- **_Privilege Escalation:_** Attackers exploit poorly configured services (e.g., weak file permissions) to upgrade their access from a limited user to a full
  Administrator or Root user.
- **_Backdoor Implementation:_** A hidden service can act as a permanent Backdoor, silently listening for commands from a remote attacker's server (C2 server).
- **_Misconfiguration Risks:_** A single misconfigured service (like a service running an unquoted path or weak permissions) can turn a secure system into an open target.

**_The Important Note:_**
A single insecure service configuration is often the difference between a minor security breach and a total system takeover.
