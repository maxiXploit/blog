---
layout: single
title: BTLO Investigation - Piggy
excerpt: Análisis forense de red. 
date: 2025-07-24
classes: wide
header:
  teaser: ../gits/sec/blog/assets/imag
  teaser_home_page: true
  icon: ../assets/images/btlo.png
categories:
   - Blue Team Labs Online
   - investigation
   - linux
tags:
   - wireshark
   - MITRE ATT&CK
   - network forensics
   - virus total
   - threat intelligence
---

### **Scenario**

Investigate some simple network activity in Wireshark! You can launch Wireshark in a terminal with the command 'wireshark'. The questions are mapped to the four PCAPs on the Desktop.

---

Once the site has launched the lab, we face with some .pcap files, at this poing we can start with the fists questions. 

1. PCAP One) What remote IP address was used to transfer data over SSH?

By opening the first .pcap file and applying a filter by ssh we can see the following: 

![](../assets/images/btlo-piggy/1.png)

A conection from a internal ip to a private ip, this is a reverse shell from `10.0.9.171` to `35.211.33.16`

2. PCAP One) How much data was transferred in total?

To this we need to go to `Statistics > Conversations`

![](../assets/images/btlo-piggy/2.png)

3. PCAP Two) Review the IPs the infected system has communicated with. Perform OSINT searches to identify the malware family tied to this infrastructure.

To answere this we can subbmit one of the ips in the pcap two.

In the report of any of these ips we can se the following: 

![](../assets/images/btlo-piggy/3.png)

TrickBot is a modular malware that originated in 2016 as a banking trojan, but has since evolved into a versatile cybercrime platform used for:
- Credential theft
- Lateral movement
- Network reconnaissance
- Payload delivery (e.g., ransomware)

It is often used in targeted attacks against organizations and is considered part of advanced persistent threat (APT) toolkits.

TrickBot consists of a core loader and multiple downloadable modules. Each module performs a specific malicious function. Common modules include:
- pwgrab: Steals passwords from browsers, Outlook, and FTP clients.
- injectDll: Browser injection to intercept online banking credentials.
- networkDll: Scans and maps the local network.
- vncDll: Enables remote desktop control.
- rdpScanDll: Scans for open RDP services for lateral movement.

Core Capabilities
- Credential harvesting (browsers, VPNs, RDP).
- Data exfiltration to C2 servers.
- Persistence via registry and scheduled tasks.
- Encrypted communication (typically using TLS).
- Downloading and executing additional payloads (e.g., ransomware).

4. PCAP Three) Review the two IPs that are communicating on an unusual port. What are the two ASN numbers these IPs belong to? (Format: ASN, ASN)

To answer this I added two new columns with source and destination ports, by analyzig this data we can se 2 usual ports, 8080 and 8000. With the `whois` command we can found this ASN in the `origin` field. 

An Autonomous System Number (ASN) is a unique identifier assigned to an autonomous system, which is a group of IP networks under the control of one or more network operators with a single, clearly defined routing policy.
ASNs are essential for routing information exchange between different networks on the internet. They allow network operators to control routing within their networks and exchange routing information with other network operators, such as Internet Service Providers (ISPs). 

5. PCAP Three) Perform OSINT checks. What malware category have these IPs been attributed to historically?

To answer this I subbmited in VirusToal the two ips founded in the previous question, both have a detection labed as `miner`. 

6. PCAP Three) What ATT&CK technique is most closely related to this activity?

For this question I asked to GPT for techniques related to `miner` malware: 

![](../assets/images/btlo-piggy/4.png)

7. PCAP Four) Go to View > Time Display Format > Seconds Since Beginning of Capture. How long into the capture was the first TXT record query made? (Use the default time, which is seconds since the packet capture started)

Searching in DNS records I saw the following packet: 

![](../assets/images/btlo-piggy/5.png)

> TXT is used as a light comunication chanel. 

8. PCAP Four) Go to View > Time Display Format > UTC Date and Time of Day. What is the date and timestamp?

`2024-05-24 10:08:50`

9. 

By reviewing the dns record we can say the following:

This is a unusual TXT Query: The DNS TXT request for a randomly generated subdomain (tfbtvvrpkmhltlptpkpuwaqymuhduv.sandbox.alphasoc.xyz) is indicative of a DNS-based C2 channel.

Beaconing Behavior: Such automated, periodic TXT lookups align with beaconing patterns used by malware to fetch commands or exfiltrate data over DNS.

The technique observed is T1071.004 (Application Layer Protocol: DNS).


