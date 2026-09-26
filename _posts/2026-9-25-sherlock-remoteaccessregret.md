---
layout: single
title: Sherlock - Remote_Access_Regret
excerpt: Laboratorio sencillo para analizar el History de un navegador junto con los de Anydesk
date: 2026-9-25
classes: wide
header:
   teaser: ../assets/images/socs/logoletsdefend.png
   teaser_home_page: true
   icon: ../assets/images/hacktheweb.webp
categories:
   - hackthebox
   - soc 
   - blue team
   - dfir
tags: 
   - anydesk
   - windows
   - dfir
   - digital-forensics
   - incident-response
   - chrome
   - browser-cache
   - web-cache
   - artifacts
   - forensic-analysis
   - timeline-analysis
   - html
   - sqlite
   - python
   - datetime
   - cached-data
   - social-engineering
   - scam
   - remote-access
   - remote-access-software
   - log-analysis
---

**Sherlock Scenario**

On February 18, 2025, Margaret was browsing the web looking for Thanksgiving recipes when her browser suddenly displayed a full-screen warning. The page claimed her computer was infected with viruses and locked her browser.

Frightened, Margaret called the phone number displayed on the screen. A man answered and claimed to be from Microsoft Support. He convinced her that hackers were actively stealing her information and she needed to act immediately.

The man instructed her to download a program that would let him "fix" the problem remotely. Once connected, he spent over an hour "cleaning" her computer while showing her scary-looking windows and error messages.

At the end, he demanded $500 for a "protection plan" and insisted payment be made with gift cards for "security reasons." Margaret drove to Target, purchased the cards, and read the numbers over the phone.

As a DFIR analyst your job is to analyze Chrome browser data and AnyDesk application data.

-----------

Para esto lab se nos da el siguiente fichero:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/remoteaccessregret]
└─$ file intelvol.raw                       
intelvol.raw: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "mkfs.fat", sectors/cluster 4, reserved sectors 4, root entries 512, Media descriptor 0xf8, sectors/FAT 256, sectors/track 32, heads 8, sectors 262144 (volumes > 32 MB), serial number 0x48bac6c8, label: "INTELVOL   ", FAT (16 bit)
```

El cual podemos montar con el siguiente comando:

```bash
┌──(kali㉿kali)-[/mnt/intelvol]
└─$ sudo mount -o loop,ro -t vfat intelvol.raw /mnt/intelvol/
```

Con esto podemos pasar a las preguntas.

-----

**1\. What is the local AnyDesk ID assigned to the victim's computer?**

Explorando el montaje:

```bash
┌──(kali㉿kali)-[/mnt/intelvol]
└─$ tree Users 
Users
└── Margaret
    ├── AppData
    │   ├── Local
    │   │   └── Google
    │   │       └── Chrome
    │   │           └── User_Data
    │   │               └── Default
    │   │                   ├── Cache
    │   │                   │   └── Cache_Data
    │   │                   │       ├── f_000a1b
    │   │                   │       └── index
    │   │                   └── History
    │   └── Roaming
    │       └── AnyDesk
    │           ├── ad.trace
    │           ├── connection_trace.txt
    │           └── system.conf
    ├── Desktop
    └── Downloads
        └── AnyDesk.exe
```

Revisando la configuración de `AnyDesk`:

```bash
┌──(kali㉿kali)-[/mnt/intelvol]
└─$ cat Users/Margaret/AppData/Roaming/AnyDesk/system.conf                        
[license]
key=

[client]
id=847291503

[user_interface]
; gui_language is unset, defaults to system language

[connection]
direct_auto_accept=0

[recording]
session_recording=0

[security]
unlock_password_hash=
access_control_list=
```

----------

**2\. Using the Chrome History database, what was the first website Margaret visited before encountering the scam?**


Abriendo el historial con `sqlite3`:

```bash
┌──(kali㉿kali)-[/mnt/intelvol]
└─$ sqlite3 Users/Margaret/AppData/Local/Google/Chrome/User_Data/Default/History
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
urls    visits
sqlite> select * from urls;
1|https://www.google.com/search?q=thanksgiving+recipes|thanksgiving recipes - Google Search|1|1|13382748130000000|0
2|https://www.allrecipes.com/recipes/17562/holidays-and-events/thanksgiving/|Thanksgiving Recipes | Allrecipes|1|0|13382748225000000|0
3|https://www.allrecipes.com/recipe/221958/perfect-roast-turkey/|Perfect Roast Turkey Recipe | Allrecipes|1|0|13382748305000000|0
4|http://ww1.windows-security-alert.com/warning/?tid=8847291||1|0|13382748363000000|0
5|https://support-windows-defender.com/alert/critical.php|Microsoft Windows Defender Alert|1|0|13382748371000000|0
6|https://anydesk.com/en/downloads/windows|Download AnyDesk for Windows|1|1|13382749102000000|0
7|https://www.bankofamerica.com/|Bank of America - Banking, Credit Cards, Loans|1|1|13382751727000000|0
8|https://secure.bankofamerica.com/myaccounts/signin/signIn.go|Sign In - Bank of America|1|0|13382751802000000|0
9|https://www.target.com/|Target : Expect More. Pay Less.|1|1|13382752875000000|0
10|https://www.target.com/c/gift-cards/-/N-5xsxu|Gift Cards : Target|1|0|13382752940000000|0
sqlite>
```

En la primera línea vemos: `1|https://www.google.com/search?q=thanksgiving+recipes|thanksgiving recipes - Google Search|1|1|13382748130000000|0`

Es el `Google Search`, por loque primero entra a `www.google.com`.

---------

**3\. What is the domain of the initial malicious redirect that led Margaret to the scam page?**

En la salida anterior vemos las siguientes líneas:

```bash
4|http://ww1.windows-security-alert.com/warning/?tid=8847291||1|0|13382748363000000|0
5|https://support-windows-defender.com/alert/critical.php|Microsoft Windows Defender Alert|1|0|13382748371000000|0
```

El sitio `ww1.windows-security-alert.com` es que parece llevarnos después a `support-windows-defender.com`

-------------

**4\. The scam page was cached by Chrome. Examining the cached HTML file, what phone number was displayed to the victim?**

Anteriormente ya vimos que en la siguiente ruta tenemos archivos relacionados con Google: `Users/Margaret/AppData/Local/Google/Chrome/User_Data/Default/Cache/Cache_Data/`

Revisando qué tipo de archivos son nos damos cuenta de que se tratan de texto plano:

```bash
┌──(kali㉿kali)-[/mnt/intelvol]
└─$ file Users/Margaret/AppData/Local/Google/Chrome/User_Data/Default/Cache/Cache_Data/f_000a1b                       
Users/Margaret/AppData/Local/Google/Chrome/User_Data/Default/Cache/Cache_Data/f_000a1b: HTML document, Unicode text, UTF-8 text
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/intelvol]
└─$ file Users/Margaret/AppData/Local/Google/Chrome/User_Data/Default/Cache/Cache_Data/index                          
Users/Margaret/AppData/Local/Google/Chrome/User_Data/Default/Cache/Cache_Data/index: ASCII text
```

Analizando con strigs vemos lo siguiente:

```bash
┌──(kali㉿kali)-[/mnt/intelvol]
└─$ strings Users/Margaret/AppData/Local/Google/Chrome/User_Data/Default/Cache/Cache_Data/f_000a1b                       

<SNIP>
Call Microsoft Support Now<br>
<span style="font-size:40px">+1 (888) 351-4019</span><br>
<SNIP>
```

-------------------

**5\. What is the AnyDesk ID of the remote machine that connected to Margaret's computer?**


Revisando los logs de **AnyDesk**

```bash
┌──(kali㉿kali)-[/mnt/intelvol]
└─$ cat Users/Margaret/AppData/Roaming/AnyDesk/connection_trace.txt
Connection Trace
================

2025-02-18 08:41:17 - Incoming connection from 529481627 (MicrosoftSupport)
  Status: Accepted
  Session: ses_748291037
  Start: 2025-02-18 08:41:23
  End: 2025-02-18 09:48:55
  Duration: 01:07:32
  Direction: Incoming
  Permissions: Full Access
  Transfer Out: 1559433 bytes
  Transfer In: 0 bytes
```

En esta línea vemos los datos del equipo remoto: `2025-02-18 08:41:17 - Incoming connection from 529481627 (MicrosoftSupport)`

---------------

**6\. What alias did the scammer use for their AnyDesk connection?**

En la pregunta anterior vemos que el alias del ID es `(MicrosoftSupport)`

-----------------------


**7\. According to the AnyDesk logs, what was the total session duration in seconds?**

Ya vimos los logs de acceso, con el siguiente script de python podemos calcular y convertir a segundos:

```bash
#!/usr/bin/python3

from datetime import datetime

start = datetime.strptime("2025-02-18 08:41:23", "%Y-%m-%d %H:%M:%S")
end = datetime.strptime("2025-02-18 09:48:55", "%Y-%m-%d %H:%M:%S")

duration = end - start

print(duration)
print(duration.total_seconds())
```

-----------

**8\. The AnyDesk logs show files were exfiltrated. What is the filename (not full path) of the first file stolen from Margaret's Desktop?**

Revisando los logs de transferencias:

```bash
┌──(kali㉿kali)-[/mnt/intelvol]
└─$ cat Users/Margaret/AppData/Roaming/AnyDesk/ad.trace | grep -i "file"
info 2025/02/18 08:41:23.891 anydesk - Permissions granted: input,clipboard,filetransfer
info 2025/02/18 08:48:22.445 anydesk - File manager opened by remote
info 2025/02/18 08:52:17.663 anydesk - File transfer: upload started
info 2025/02/18 08:52:17.891 anydesk - File transfer: C:\Users\Margaret\Desktop\Bank Statements 2024.pdf
info 2025/02/18 08:52:22.445 anydesk - File transfer: complete (247293 bytes)
info 2025/02/18 08:55:08.227 anydesk - File transfer: upload started
info 2025/02/18 08:55:08.334 anydesk - File transfer: C:\Users\Margaret\Documents\Tax Return 2023.pdf
info 2025/02/18 08:55:14.772 anydesk - File transfer: complete (1293847 bytes)
info 2025/02/18 09:01:33.112 anydesk - File transfer: upload started
info 2025/02/18 09:01:33.445 anydesk - File transfer: C:\Users\Margaret\Desktop\Passwords.docx
info 2025/02/18 09:01:35.221 anydesk - File transfer: complete (18293 bytes)
```

----------

**9\. How many bytes total were uploaded (exfiltrated) to the remote attacker during the session?**

Esto ya lo vimos en el `connecion_trace.txt`:

```txt
  Transfer Out: 1559433 bytes
```

--------

**10\. Based on the Chrome History, how many total URLs were visited during the browsing session on the day of the incident?**

En la pregunta dos vimos que hay 10 líneas.
