---
layout: single
title: Sherlock - Phantom
excerpt: Laboratorio para analizar el protocolode VoIP.
date: 2026-9-29
classes: wide
header:
   teaser: ../assets/images/logoletsdefend.png
   teaser_home_page: true
   icon: ../assets/images/hackthebox.webp
categories:
   - hackthebox
   - soc
   - blue team
   - dfir
tags:
---

**Sherlock Scenario: A Linux server in your organization has been exhibiting suspicious behavior. Network monitoring detected unusual outbound connections to an unknown IP address, and system administrators noticed that several standard diagnostic commands were returning incomplete information. A memory dump was captured from the compromised server before isolation. Your task is to analyze this memory dump to uncover evidence of a sophisticated rootkit infection, map its capabilities, and document all indicators of compromise.**

Para este lab se nos da los siguientes ficheros:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/phantom/phantom]
└─$ ls
dump_srv.mem  Ubuntu_6.8.0-87-generic.json
```

-----------

**1\. What is the name of the hidden kernel module?**




-----------

What kernel taint flags are set for the rootkit module? (comma-separated, alphabetical order)

***_******,********_******

Submit Task
Task 3
At what exact time (in seconds since boot) was the rootkit module loaded

****.******

Submit Task
Task 4
What was the PID of the process that loaded the rootkit module?

number, such as 3, 17, or 4567

Submit Task
Task 5
Which kernel tracepoint is hooked by the rootkit

******************

Submit Task
Task 6
What is the IP address of the command and control server?

IPv4 address

Submit Task
Task 7
What port is the C2 server listening on?

number, such as 3, 17, or 4567

Submit Task
Task 8
What are the PIDs of the compromised bash processes connected to the C2 server? (comma-separated, ascending order)

****,****,****

Submit Task
Task 9
How many hooks has the rootkit installed?

number, such as 3, 17, or 4567

Submit Task
Task 10
Which function is hooked to hide IPv4 network connections?

****_***_****

Submit Task
Task 11
How many variants of getdents syscalls are hooked?

number, such as 3, 17, or 4567

Submit Task
Task 12
Which function is hooked to enable an ICMP-based covert channel?

****_***

Submit Task
Task 13
What is the memory address of the centralized callback function? (Format:0x************)

**************

Submit Task
Task 14
What is the value of the suspicious environment variable which leads to the escalation of privileges?
