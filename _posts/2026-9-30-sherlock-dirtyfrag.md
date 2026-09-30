

tags:
dmesg
---

**Sherlock Sceario: A Linux workstation running Ubuntu 22.04.2 LTS was compromised through a kernel vulnerability in the IPsec (ESP/XFRM) subsystem. The attacker created a new user account, exploited the kernel flaw to escalate privileges, deployed a hidden SUID backdoor binary, and installed a malicious root cron job that establishes a reverse shell to a remote host. Kernel logs, user account records, file permissions, and cron entries were collected from the compromised machine for forensic analysis.**

------------

**1\. What is the kernel version of the compromised system?**



---------

6.8.0-101-generic

Submit Task
Task 2
What is the username of the account that was used to run the exploit?

username

Submit Task
Task 3
What Linux distribution and exact version is installed?

****** **.**.* ***

Submit Task
Task 4
What is the CVE identifier for the vulnerability exploited in this incident?

CVE-****-*****

Submit Task
Task 5
List all non-system user accounts on the machine in this exact format: username:UID sorted alphabetically by username.

username:UID,username:UID,...

Submit Task
Task 6
At what exact time was the exploit user account created?

hh:mm:ss

Submit Task
Task 7
The kernel recorded a single event that could only appear if the ESP subsystem was initialized by the exploit. What is that exact message? Copy the text only, no timestamp, no brackets.

************ **** ******* ******

Submit Task
Task 8
What is the exact kernel log message that proves privilege escalation succeeded? Copy the message text only, without the timestamp or brackets.

******* '**' ******** '/***/**' **** **** ****: ***** ****** *****

Submit Task
Task 9
How many seconds elapsed between the XFRM netlink socket initialization and the privilege escalation confirmation in the kernel log?

decimal seconds

Submit Task
Task 10
What single character in the shadow file proves that svc_monitor cannot be used for direct password-based login?

*

Submit Task
Task 11
What is the exact octal permission value of the hidden backdoor binary?

number, such as 3, 17, or 4567

Submit Task
Task 12
What is the SHA256 hash of the hidden SUID binary?

SHA-256 Hash

Submit Task
Task 13
What is the exact full line of the malicious cron entry? Include every field from the schedule to the end of the command.

