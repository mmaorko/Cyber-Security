# Open Web Application Security Project(OWASP) Security Principles
## 1. Minimize the Attack Surface Area
The goal here is simple: reduce the number of ways a threat actor can get in. An "attack surface" is the sum of all potential vulnerabilities. By disabling unnecessary 
software features or restricting access, you close off the "attack vectors"—like phishing or weak passwords—that hackers use to penetrate defenses.

## 2. Principle of Least Privilege
This means giving users only the specific access they need to do their jobs and nothing more. Here’s the thing: if an entry-level analyst's account is compromised, the 
damage is contained because they don't have the permissions to change system-wide settings. It’s about limitng the "blast radius" of a breach.

## 3. Defense in Depth
Never rely on a single security measure. Defense in depth means layering your controls—like using multi-factor authentication (MFA) alongside firewalls and intrusion 
detection systems. What this really means is that if a hacker breaks through one layer, they are immediately met with another.

## 4. Separation of Duties
This principle prevents fraud and misuse by ensuring no single person has too much power. For example, the person who prepares company paychecks should not be the same 
person authorized to sign them. Splitting these tasks creates a natural system of checks and balances.

## 5. Keep Security Simple
Complexity is the enemy of security. If a system is too complicated, it becomes unmanageable and people start making mistakes or finding workarounds. Keeping your controls 
straightforward makes it easier for teams to collaborate and maintain a high level of protection.

6. Fix Security Issues Correctly
When a breach happens, don't just patch the surface. You need to identify the root cause quickly, fix the underlying vulnerability, and then run tests to confirm the repair
actually worked. If the issue was a weak Wi-Fi password, the fix isn't just changing it—it's implementing a stricter password policy.
