---
layout: single
ititle: Cyberdefenders - CorporateSecrets Lab
excerpt: Analysis of an .ad1 file. 
date: 2025-06-24
classes: wide
header:
  teaser: ../assets/images/sherlock-bumbleebe/
  teaser_home_page: true
  icon: ../assets/images/logo-icon.svg
categories:
   - cyberdefenders
   - dfir
tags:
   - ftk imager
   - registry explorer
   - prefetch
   - mft
   - mftecmd
   - db browser for slite
   - PasswordFox
   - winprefetchview
---

We have been provided with a .ad1 file, which we will be analyzing it with FTK Imager, and some other tools.
I mounted the image file on my system with FTK, so we can move on to the questions. 

----- 

<h3 style="color: #0d6efd;"> Q1. What is the current build number on the system? </h3>

I found this loading the SOFTWARE hive into Registry Explorer, under: `Microsoft\Windows NT\CurrentVersion`

----

<h3 style="color: #0d6efd;"> Q2. How many users are there? </h3>

Once we have been mounted the .ad1 on our system, we just go to the disk and see how many users are under `E:\DFA_SP2020_Windows.E01_Partition 2 [50649MB]_NONAME [NTFS]\[root]\Users`

----

<h3 style="color: #0d6efd;"> Q3. What is the CRC64 hash of the file "fruit_apricot.jpg"? </h3>

A CRC64 is a 64-bit cyclic redundancy check (CRC) a type of checksum or hash function used primarly for error detection, not for security. It is used to detect accidental changes or errors in raw data. It's commonly used in:

- Filesystems
- Networking Protocols
- Backup tools
- Data Transmission(e.g., hard drives, SSDs, network packets)

We can obtaing this with [this site](https://toolkitbay.com/tkb/tool/CRC-64), the image file is under `hansel.apricot`. 

![](../assets/images/cyber-secret/1.png)

Or using the next command in linux: `find . -name "fruit_apricot.jpg" -exec 7z h -scrcCRC64 {} \;`

----

<h3 style="color: #0d6efd;"> Q4.  </h3>

I found that image in `suzy.strawberry` directory. Right click > Properties and we will see the size file.

-----

<h3 style="color: #0d6efd;"> Q5. What is the processor architecture of the system? (one word) </h3>

In Registry Explorer, we can found the answer under: `SYSTEM/ControlSet001/Control/Session Manager/Environment/`

----

<h3 style="color: #0d6efd;"> Q6. Which user has a photo of a dog in their recycling bin? </h3>

I found that image exploring the path: `E:\DFA_SP2020_Windows.E01_Partition 2 [50649MB]_NONAME [NTFS]\[root]\$Recycle.Bin\S-1-5-21-2446097003-76624807-2828106174-1005`. 

Files in the recybling bin that start with `$I` contain the metadata for the trashed file, files starting with `$R` are the actual file. Now, we need to figure out what user has the `1005` UID. 
I foud this under `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\` in Registry Explorer, this profile list maps user SIDs to their user profile paths. 

-----

<h3 style="color: #0d6efd;"> Q7. What type of file is "vegetable"? Provide the extension without a dot. </h3>

I foud this file under: `E:\DFA_SP2020_Windows.E01_Partition 2 [50649MB]_NONAME [NTFS]\[root]\Users\miriam.grapes\Pictures`

Applying the following command: 

```powershell
 certutil -dump .\vegetable | Select-Object -First 10
  000000  ...
  03f2d3
    000000  37 7a bc af 27 1c 00 04  74 de e6 e2 8f f2 03 00   7z..'...t.......
    000010  00 00 00 00 24 00 00 00  00 00 00 00 e5 da d4 96   ....$...........
    000020  e0 c0 41 c0 04 5d 00 7f  b6 1b ed f0 84 40 58 e3   ..A..].......@X.
    000030  91 de 10 27 56 8a 1c 8e  d2 36 67 29 e1 37 e7 22   ...'V....6g).7."
    000040  58 ed 64 f1 8b 56 5b f2  f7 8e db ec 3f 0a bf ee   X.d..V[.....?...
    000050  c0 fd cd 63 8d 6e 6c 1b  b9 65 1f e9 56 95 4f 19   ...c.nl..e..V.O.
    000060  34 c1 d2 89 ee e7 f4 87  a0 cd ad ea 95 66 81 6e   4............f.n
    000070  f5 1e d1 96 dc 5b 51 3c  67 de 7a af 37 a3 46 32   .....[Q<g.z.7.F2
```

------

<h3 style="color: #0d6efd;"> Q8. What type of girls does Miriam Grapes design phones for (Target audience)? </h3>

I started looking for the photo in Miriam's directory, I ended up in firefox directory, in `places.sqlite`: `E:\...\miriam.grapes\AppData\Roaming\Mozilla\Firefox\Profiles\9far2v52.default-release\places.sqlite`

Analyzing this DB in [sqliteviewer.app](https://sqliteviewer.app/#/msgstore.db/table/messages/).

![](../assets/images/cyber-secret/2.png)

------

<h3 style="color: #0d6efd;"> Q9. What is the name of the device? </h3>

I found this in SYSTEM hive, under: `ControlSet001\Control\ComputerName\ComputerName`

----

<h3 style="color: #0d6efd;"> Q10. What is the SID of the machine? </h3>

We can get the machine SID from the first user SID in the ProfileList:

```bash 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
```

Each user's SID starts with the machine SID + a Relative ID (RID).

--------

<h3 style="color: #0d6efd;"> Q12. How many super secret CEO plans does Tim have? (Dr. Doofenshmirtz Type Beat) </h3>

I found this under `tim.apple` docuuments directory. 

![](../assets/images/cyber-secret/3.png)

There's a little hidden secret. 

-----

<h3 style="color: #0d6efd;"> Q13. Which employee does Tim plan to fire? (He's Dead, Tim. Enter the full name - two words - space separated) </h3>

We saw that in the previus question.  

-----

<h3 style="color: #0d6efd;"> Q14. What was the last used username? (I didn't start this conversation, but I'm ending it!) </h3>

In Registry Explorer, I found this in `SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon`

------

<h3 style="color: #0d6efd;"> Q15. What was the role of the employee Tim was flirting with? </h3>

We can start to search this in Jim's browsing history: `Users\tim.apple\AppData\Roaming\Mozilla\Firefox\Profiles\9far2v52.default-release\places.sqlite`
Analyzing this in sqliteviewer. 

![](../assets/images/cyber-secret/4.png)

----

<h3 style="color: #0d6efd;"> Q16. What is the SID of the user "suzy.strawberry"? </h3>

We already know how to solve this. In `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

----

<h3 style="color: #0d6efd;"> Q17. List the file path for the install location of the Tor Browser. </h3>

We had already found this: `C:\Program1`

----

<h3 style="color: #0d6efd;"> Q18. What was the URL for the Youtube video watched by Jim? </h3>

We can foun this in Jim's browsing history: `jim.tomato/AppData/Local/Google/Chrome/UserData/Default/`

![](../assets/images/cyber-secret/5.png)

----

<h3 style="color: #0d6efd;"> Q19. Which user installed LibreCAD on the system? </h3>

Navigating through users directories, I found LibreCAD in miriam.grapes's directory. 

-----

<h3 style="color: #0d6efd;"> Q20. How many times "admin" logged into the system? </h3>

I found this with [RegRipper](https://github.com/keydet89/RegRipper3.0), I load the SAM hive into RegRipper: 

![](../assets/images/cybe-secret/6.png)

----

<h3 style="color: #0d6efd;"> Q21. What is the name of the DHCP domain the device was connected to? </h3>

I found this under: `SYSTEM/ControlSet001/Services/Tcpip/Parameters/Interfaces/`

![](../assets/images/cyber-secret/7.png)

----

<h3 style="color: #0d6efd;"> Q22. What time did Tim download his background image? (Oh Boy 3AM . Answer in MM/DD/YYYY HH:MM format (UTC).) </h3>

Navigating through users directories I found a image in Jim's directory: 

![](../assets/images/cyber-secret/8.png)

------

<h3 style="color: #0d6efd;"> Q23. How many times did Jim launch the Tor Browser? </h3>

The file NTUSER.DAT contains the user-level registry hive — it stores settings and activity specific to a user account, including:

- Recently opened programs
- Application usage history
- User-specific configurations
- RunMRU (commands run)
- MUICache, UserAssist, etc.

So, I loaded this file into Registry Explorer and I navigated to `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\count`: 

![](../assets/images/cyber-secret/9.png)

But it seems this is not the corret answer, we need to go to prefetch directory, and we can see two tor references 

![](../asseets/images/cyber-secret/10.png)

-----

<h3 style="color: #0d6efd;"> Q24. There is a png photo of an iPhone in Grapes's files. Find it and provide the SHA-1 hash. </h3>

Going to `miriam.grapes` directory I found a `samplePhone.jpg`, so we need to review this file to figure out whether there's another file in there.

Applying the `foremost` comand on samplePhone.jpg. We obtained a file called 00000011.png, we can apply the `sha1sum` command. 

> foremost is a data carving tool used in digital forensics to recover deleted files from disk images, memory dumps, or any raw binary data — even when the file system metadata is missing or corrupted.

----

<h3 style="color: #0d6efd;"> Q25. When was the last time a docx file was opened on the device? (An apple a day keeps the docx away. Answer in UTC, YYYY-MM-DD HH:MM:SS) </h3>

I found this under `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx` in John's NTUSER.DAT.

------

<h3 style="color: #0d6efd;"> Q26. How many entries does the MFT of the filesystem have? </h3>

To answer this I used [mftdump](https://github.com/mcs6502/mftdump/blob/master/mftdump.py). Using the next command to convert raw $MFT binary data into human-readable format. 

```bash 
┌──(kali㉿kali)-[~/blue-labs/secret]
└─$ python2.7 /opt/mftdump/mftdump.py MFT > MFT.txt
```

Now, we can count the total lines: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/secret]
└─$ wc -l MFT.txt
219906 MFT.txt
```

Excluding the first two lines: 219904

----

<h3 style="color: #0d6efd;"> Q27. Tim wanted to fire an employee because they were ......?(Be careful what you wish for) </h3>

Analyzing Tim's browsing history under: `\Users\tim.apple\AppData\Local\Google\Chrome\User Data\Defualt`

![](../assets/images/cyber-secret/11.png)

----

<h3 style="color: #0d6efd;"> Q28. What cloud service was a Startup item for the user admin? </h3>

In order to answer this we need to load the admin `NTUSER.adt` into Registry Explorer. 

I found the answer under: `Software\Microsoft\Windows\CurrentVersion\Run`

![](../assets/images/cyber-secret/12.png)

This is a registry key used by windows to define programs that run automatically when a user logs on. 

-----

<h3 style="color: #0d6efd;"> Q29. Which Firefox prefetch file has the most runtimes? (Flag format is ) </h3>

Loading the prefetch directory into WinPrefetchView, in `Options>Advanced Options`

Exploring the diferent entries:  

![](../assets/images/cyber-secret/13.png)

-----

<h3 style="color: #0d6efd;"> Q30. What was the last IP address the machine was connected to? </h3>

From question 21, under `SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{f2329ece-8884-4fbd-ad6e-3925da11ddd7}` we saw that there was only an IP. 

-----

<h3 style="color: #0d6efd;"> Q31. Which user had the most items pinned to their taskbar? </h3>

We need to analyze every Taskbar of each user: `C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar`

------

<h3 style="color: #0d6efd;"> Q32. What was the last run date of the executable with an MFT record number of 164885? (Format: MM/DD/YYYY HH:MM:SS (UTC).) </h3>

I just use the next command:

```powershell
PS C:\Users\Lenovo\Downloads\compartida\compartida> C:\Users\Lenovo\Downloads\compartida\PECmd\PECmd.exe -f  "E:\DFA_SP2020_Windows.E01_Partition 2 [50649MB]_NONAME [NTFS]\[root]\Windows\Prefetch\7ZG.EXE-0F8C4081.pf" | findstr "Last Run"
Last accessed on: 2020-04-11 23:17:35
Run count: 5
Last run: 2020-04-12 02:32:09
```

-----

<h3 style="color: #0d6efd;"> Q33. What is the log file sequence number for the file "fruit_Assortment.jpg"? </h3>

In RecycleBin, with Jim's RID, i found an interesting file: `$RQ1FSDY.docx`. Using binwalk to get more info: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/secret]
└─$ binwalk '$RQ1FSDY.docx'

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, at least v2.0 to extract, name: Document1/
40            0x28            Zip archive data, at least v2.0 to extract, compressed size: 4546, uncompressed size: 5319, name: Document1/Content.xml
4637          0x121D          Zip archive data, at least v2.0 to extract, name: Document1/docProps/
4686          0x124E          Zip archive data, at least v2.0 to extract, compressed size: 314, uncompressed size: 542, name: Document1/docProps/app.xml
5056          0x13C0          Zip archive data, at least v2.0 to extract, compressed size: 357, uncompressed size: 731, name: Document1/docProps/core.xml
5470          0x155E          Zip archive data, at least v2.0 to extract, name: Document1/word/
5515          0x158B          Zip archive data, at least v2.0 to extract, compressed size: 529, uncompressed size: 1367, name: Document1/word/document.xml
6101          0x17D5          Zip archive data, at least v2.0 to extract, compressed size: 281, uncompressed size: 853, name: Document1/word/fontTable.xml
6440          0x1928          Zip archive data, at least v2.0 to extract, compressed size: 219, uncompressed size: 313, name: Document1/word/settings.xml
6716          0x1A3C          Zip archive data, at least v2.0 to extract, compressed size: 660, uncompressed size: 2393, name: Document1/word/styles.xml
7431          0x1D07          Zip archive data, at least v2.0 to extract, name: Document1/word/_rels/
7482          0x1D3A          Zip archive data, at least v2.0 to extract, compressed size: 197, uncompressed size: 531, name: Document1/word/_rels/document.xml.rels
7747          0x1E43          Zip archive data, at least v2.0 to extract, compressed size: 335, uncompressed size: 1374, name: Document1/[Content_Types].xml
8141          0x1FCD          Zip archive data, at least v2.0 to extract, name: Document1/_rels/
8187          0x1FFB          Zip archive data, at least v2.0 to extract, compressed size: 217, uncompressed size: 573, name: Document1/_rels/.rels
10035         0x2733          End of Zip archive, footer length: 22
```

It seems to be a zip file. Now I unzip the file: `unzip '$RQ1FSDY.docx' -d RQ1`

```bash
┌──(kali㉿kali)-[~/blue-labs/secret]
└─$ ls -la RQ1/Document1
total 32
drwxrwxr-x 5 kali kali 4096 Apr 11  2020  .
drwxrwxr-x 3 kali kali 4096 Jun 22 22:05  ..
-rw-rw-r-- 1 kali kali 1374 Apr 11  2020 '[Content_Types].xml'
-rw-rw-r-- 1 kali kali 5319 Apr 11  2020  Content.xml
drwxrwxr-x 2 kali kali 4096 Apr 11  2020  docProps
drwxrwxr-x 2 kali kali 4096 Apr 11  2020  _rels
drwxrwxr-x 3 kali kali 4096 Apr 11  2020  word
```

Openind Content.xml with libre office we will see four company secrets. 


