---
layout: single
title: Cyberdefenders - Lockdown
excerpt: Análisis de un ataque completo contra un servidor IIS Windows, 
classes: wide
header:
   teaser: ../assets/images/m
   teaser_home_page: true
   icon: ../assets/images/logo-icon.svg
categories:
   - cyberdefenders
   - windows
tags:
   - wireshark
   - tshark
   - port scanning
   - smb2
   - IIS explotation
   - reverse shell
   - memory forensics
   - malware analysis
---

Se nos entrega un fichero .zip, asì que el primer paso es descomprimirlo con `7z x <nombre del fichero>`, se nos proporcionan 3 ficheros: 

```bash 
┌──(kali㉿kali)-[~/labs2/labs]
└─$ ls
capture.pcapng memdump.mem  updatenow.exe
```

Asì que podemos empezar a responder las preguntas. 

1. After flooding the IIS host with rapid-fire probes, the attacker reveals their origin. Which IP address generated this reconnaissance traffic?

Para esto podemos usar el siguiente comando: 

```bash 
┌──(kali㉿kali)-[~/labs2/labs/analisis_zeek]
└─$ tshark -r capture.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0" | head -n 20
    7   0.957982    10.0.2.15 49684 20.242.39.171 443 TCP 66 49684 → 443 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
   44  53.663407    10.0.2.15 49685 216.58.200.163 80 TCP 66 49685 → 80 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
   53  53.750251    10.0.2.15 49686 23.58.93.34  80 TCP 66 49686 → 80 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
   60  56.881937    10.0.2.15 49687 23.58.93.34  80 TCP 66 49687 → 80 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
   74  78.082576     10.0.2.4 55475 10.0.2.15    113 TCP 60 55475 → 113 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   76  78.084042     10.0.2.4 55475 10.0.2.15    135 TCP 60 55475 → 135 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   78  78.085296     10.0.2.4 55475 10.0.2.15    5900 TCP 60 55475 → 5900 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   79  78.085296     10.0.2.4 55475 10.0.2.15    143 TCP 60 55475 → 143 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   83  78.086841     10.0.2.4 55475 10.0.2.15    587 TCP 60 55475 → 587 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   85  78.087814     10.0.2.4 55475 10.0.2.15    1025 TCP 60 55475 → 1025 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   86  78.087814     10.0.2.4 55475 10.0.2.15    110 TCP 60 55475 → 110 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   89  78.088707     10.0.2.4 55475 10.0.2.15    8080 TCP 60 55475 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   91  78.090290     10.0.2.4 55475 10.0.2.15    445 TCP 60 55475 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   93  78.091116     10.0.2.4 55475 10.0.2.15    256 TCP 60 55475 → 256 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   96  78.092399     10.0.2.4 55475 10.0.2.15    1720 TCP 60 55475 → 1720 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
   98  78.094191     10.0.2.4 55475 10.0.2.15    111 TCP 60 55475 → 111 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
  100  78.095307     10.0.2.4 55475 10.0.2.15    443 TCP 60 55475 → 443 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
  101  78.095307     10.0.2.4 55475 10.0.2.15    22 TCP 60 55475 → 22 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
  104  78.100075     10.0.2.4 55475 10.0.2.15    3306 TCP 60 55475 → 3306 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
  105  78.100075     10.0.2.4 55475 10.0.2.15    80 TCP 60 55475 → 80 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
```
Claramente vemos una enumeraciòn hacia la ip `10.0.2.15`(con esto podemos asegurar que este es nuestro servidor), todo esto priveniente de `10.0.2.4`. 

2. Zeroing in on a single open service to gain a foothold, the attacker carries out targeted enumeration. Which MITRE ATT&CK technique ID covers this activity?

Para esto usè el siguiente comando:

```bash 
┌──(kali㉿kali)-[~/labs2/labs/analisis_zeek]
└─$ tshark -r capture.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0" | tail -n 20
 2525 165.980232     10.0.2.4 53004 10.0.2.15    445 TCP 74 53004 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564845 TSecr=0 WS=128
 2530 165.985440     10.0.2.4 53018 10.0.2.15    445 TCP 74 53018 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564850 TSecr=0 WS=128
 2535 165.989234     10.0.2.4 53032 10.0.2.15    445 TCP 74 53032 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564854 TSecr=0 WS=128
 2540 165.993048     10.0.2.4 53040 10.0.2.15    445 TCP 74 53040 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564857 TSecr=0 WS=128
 2545 165.996845     10.0.2.4 53056 10.0.2.15    445 TCP 74 53056 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564861 TSecr=0 WS=128
 2550 166.000409     10.0.2.4 53066 10.0.2.15    445 TCP 74 53066 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564865 TSecr=0 WS=128
 2555 166.005855     10.0.2.4 53068 10.0.2.15    445 TCP 74 53068 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564869 TSecr=0 WS=128
 2560 166.010809     10.0.2.4 53078 10.0.2.15    445 TCP 74 53078 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564875 TSecr=0 WS=128
 2565 166.014859     10.0.2.4 53082 10.0.2.15    445 TCP 74 53082 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564879 TSecr=0 WS=128
 2570 166.018352     10.0.2.4 53094 10.0.2.15    445 TCP 74 53094 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564883 TSecr=0 WS=128
 2575 166.022285     10.0.2.4 53110 10.0.2.15    445 TCP 74 53110 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564886 TSecr=0 WS=128
 2580 166.041406     10.0.2.4 663 10.0.2.15    445 TCP 74 663 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134564905 TSecr=0 WS=128
 2612 239.311205     10.0.2.4 56392 10.0.2.15    445 TCP 74 56392 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134638166 TSecr=0 WS=128
 2644 240.887937     10.0.2.4 52600 10.0.2.15    139 TCP 74 52600 → 139 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134639743 TSecr=0 WS=128
 2652 240.892944     10.0.2.4 52616 10.0.2.15    139 TCP 74 52616 → 139 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134639749 TSecr=0 WS=128
 2660 263.271179     10.0.2.4 37338 10.0.2.15    445 TCP 74 37338 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134662138 TSecr=0 WS=128
 2750 312.291068     10.0.2.4 54588 10.0.2.15    80 TCP 74 54588 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2134711182 TSecr=0 WS=128
 3585 401.496667    10.0.2.15 49688 10.0.2.4     4443 TCP 66 49688 → 4443 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
 4001 573.288138    10.0.2.15 49689 20.42.73.29  443 TCP 74 49689 → 443 [SYN, ECE, CWR] Seq=0 Win=65160 Len=0 MSS=1460 WS=256 SACK_PERM TSval=1450485 TSecr=0
 5124 1030.943915    10.0.2.15 49691 20.198.119.143 443 TCP 66 49691 → 443 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
```

En este punto vemos que el atacante ya está analizando servicios especìficos, como los puertos 445(SMB), 139(NetBIOS) y 80(HTTP), este comportamiento corresponde a la técnica T1046 de MITRE: 

![](../assets/images/cyber-lockdown/1.png)

3. While reviewing the SMB traffic, you observe two consecutive Tree Connect requests that expose the first shares the intruder probes on the IIS host. Which two full UNC paths are accessed?

Recordando un poco sobre SMB, es un protocolo de red para compartir ficheros, impresoras, pipes y otros recursos en redes Windows (y sistemas que implementan CIFS/SMB como Samba). Las versiones modernas son SMB2 y SMB3; SMB1 está obsoleta. 

Una ruta UNC es una Universal Naming Convention, su sintaxis general es: \\<servidor>\<recurso>\<ruta opcional>. Por ejemplo: 
\\10.0.2.15\Documents = conecta al servidor cuyo IP es 10.0.2.15 y solicita el share llamado Documents.

IPC$ es un share especial (IPC = Inter-Process Communication). No es un directorio de ficheros: sirve como canal para named pipes y para ejecutar RPCs sobre SMB (MS-RPC sobre named pipes). IPC$ no gestiona las conexiones SMB en sí; el protocolo SMB ya tiene su propio flujo interno (NEGOTIATE → SESSION_SETUP → TREE_CONNECT → …). 
IPC$ es un share especial que actúa como punto de acceso para canales de comunicación internos, llamados named pipes, que permiten ejecutar servicios remotos y RPCs sobre SMB.

- SMB = el edificio.
- IPC$ = la puerta que da acceso al pasillo administrativo del edificio.
- Named pipes = puertas a oficinas específicas (SAM, Servicios, LSA, Registro…).
- RPC = la interacción con las personas dentro de esas oficinas (pedirles que te den info, arranquen un servicio, enumeren shares, etc.).

Podemos ver esto rápidamente con el siguiente comando: 

```bash 
┌──(kali㉿kali)-[~/labs2/labs/analisis_zeek]
└─$ tshark -r capture.pcapng -Y "smb2.tree" | grep "Tree" 
 2629 240.778552     10.0.2.4 56392 10.0.2.15    445 SMB2 162 Tree Connect Request, Tree: '\\10.0.2.15\IPC$'
 2641 240.885199     10.0.2.4 56392 10.0.2.15    445 SMB2 126 Tree Disconnect Request, Tree: '\\10.0.2.15\IPC$'
 2642 240.885365    10.0.2.15 445 10.0.2.4     56392 SMB2 126 Tree Disconnect Response, Tree: '\\10.0.2.15\IPC$'
 2672 263.304629     10.0.2.4 37338 10.0.2.15    445 SMB2 162 Tree Connect Request, Tree: '\\10.0.2.15\IPC$'
 2676 263.309040     10.0.2.4 37338 10.0.2.15    445 SMB2 126 Tree Disconnect Request, Tree: '\\10.0.2.15\IPC$'
 2677 263.309248    10.0.2.15 445 10.0.2.4     37338 SMB2 126 Tree Disconnect Response, Tree: '\\10.0.2.15\IPC$'
 2678 263.312045     10.0.2.4 37338 10.0.2.15    445 SMB2 172 Tree Connect Request, Tree: '\\10.0.2.15\Documents'
                                                                                                                  
```
4. Inside the share, the attacker plants a web-accessible payload that will grant remote code execution. What is the filename of the malicious file they uploaded, and what byte length is specified in the corresponding SMB2 Write Request?

Podemos ver fácilmente con el siguiente comando:

```bash 
┌──(kali㉿kali)-[~/labs2/labs/analisis_zeek]
└─$ tshark -r capture.pcapng -Y "smb2.tree" | tail -n 25  
 2696 265.823468    10.0.2.15 445 10.0.2.4     37338 SMB2 154 GetInfo Response
 2697 265.826204     10.0.2.4 37338 10.0.2.15    445 SMB2 146 Close Request, File: <share>
 2698 265.826826    10.0.2.15 445 10.0.2.4     37338 SMB2 182 Close Response
 2704 272.391299     10.0.2.4 37338 10.0.2.15    445 SMB2 179 Create Request, File: <share>
 2705 272.392103    10.0.2.15 445 10.0.2.4     37338 SMB2 210 Create Response, File: <share>
 2707 272.394643     10.0.2.4 37338 10.0.2.15    445 SMB2 156 Find Request, File: <share>, SMB2_FIND_ID_BOTH_DIRECTORY_INFO, Pattern: *
 2708 272.401316    10.0.2.15 445 10.0.2.4     37338 SMB2 614 Find Response, SMB2_FIND_ID_BOTH_DIRECTORY_INFO, Pattern: *, 4 matches
 2709 272.403711     10.0.2.4 37338 10.0.2.15    445 SMB2 156 Find Request, File: <share>, SMB2_FIND_ID_BOTH_DIRECTORY_INFO, Pattern: *
 2710 272.412101    10.0.2.15 445 10.0.2.4     37338 SMB2 130 Find Response, Error: STATUS_NO_MORE_FILES, SMB2_FIND_ID_BOTH_DIRECTORY_INFO, Pattern: *
 2711 272.415606     10.0.2.4 37338 10.0.2.15    445 SMB2 146 Close Request, File: <share>
 2712 272.417640    10.0.2.15 445 10.0.2.4     37338 SMB2 182 Close Response
 2717 273.829153     10.0.2.4 37338 10.0.2.15    445 SMB2 210 Create Request, File: information.txt
 2719 273.864626    10.0.2.15 445 10.0.2.4     37338 SMB2 210 Create Response, File: information.txt
 2721 273.867056     10.0.2.4 37338 10.0.2.15    445 SMB2 163 GetInfo Request FILE_INFO/SMB2_FILE_ALL_INFO, File: information.txt
 2722 273.867621    10.0.2.15 445 10.0.2.4     37338 SMB2 234 GetInfo Response
 2723 273.869424     10.0.2.4 37338 10.0.2.15    445 SMB2 171 Read Request Len:150 Off:0, File: information.txt
 2724 273.870646    10.0.2.15 445 10.0.2.4     37338 SMB2 288 Read Response
 2725 273.872306     10.0.2.4 37338 10.0.2.15    445 SMB2 146 Close Request, File: information.txt
 2726 273.872828    10.0.2.15 445 10.0.2.4     37338 SMB2 182 Close Response
 2783 342.482279     10.0.2.4 37338 10.0.2.15    445 SMB2 198 Create Request, File: shell.aspx
 2784 342.501269    10.0.2.15 445 10.0.2.4     37338 SMB2 210 Create Response, File: shell.aspx
 3505 342.611215     10.0.2.4 37338 10.0.2.15    445 SMB2 494 Write Request Len:1015024 Off:0, File: shell.aspx
 3507 342.612433    10.0.2.15 445 10.0.2.4     37338 SMB2 138 Write Response
 3509 342.614219     10.0.2.4 37338 10.0.2.15    445 SMB2 146 Close Request, File: shell.aspx
 3510 342.616016    10.0.2.15 445 10.0.2.4     37338 SMB2 182 Close Response
```

5. The newly planted shell calls back to the attacker over an uncommon but firewall-friendly port. Which listening port did the attacker use for the reverse shell?

Para responder esto podemos usar el siguiente comando para ver unicamente las conexiones iniciadas por la víctima: 

```bash 
┌──(kali㉿kali)-[~/labs2/labs/analisis_zeek]
└─$ tshark -r capture.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==10.0.2.15"
    7   0.957982    10.0.2.15 49684 20.242.39.171 443 TCP 66 49684 → 443 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
   44  53.663407    10.0.2.15 49685 216.58.200.163 80 TCP 66 49685 → 80 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
   53  53.750251    10.0.2.15 49686 23.58.93.34  80 TCP 66 49686 → 80 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
   60  56.881937    10.0.2.15 49687 23.58.93.34  80 TCP 66 49687 → 80 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
 3585 401.496667    10.0.2.15 49688 10.0.2.4     4443 TCP 66 49688 → 4443 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
 4001 573.288138    10.0.2.15 49689 20.42.73.29  443 TCP 74 49689 → 443 [SYN, ECE, CWR] Seq=0 Win=65160 Len=0 MSS=1460 WS=256 SACK_PERM TSval=1450485 TSecr=0
 5124 1030.943915    10.0.2.15 49691 20.198.119.143 443 TCP 66 49691 → 443 [SYN, ECE, CWR] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
```

Vemos que la víctima inicia una conexión por el puerto 4443 hacia la ip que ya habíamos identificado como el atacante. 

6. Your memory snapshot captures the system’s kernel in situ, providing vital context for the breach. What is the kernel base address in the dump?

Para esto tenemos que usar volatility3, usamos el siguiente comando: 

```bash 
┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ /home/kali/blue-labs/volatility3/vol.py -f memdump.mem windows.info > analisis_memoria/windows.info
                                                                                                                                                                                            
┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ cat analisis_memoria/windows.info
Volatility 3 Framework 2.26.2

Variable        Value

Kernel Base     0xf80079213000
DTB     0x1aa000
Symbols file:///home/kali/blue-labs/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/EF9A48AFA50FF07C616585BB01919536-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf80079613f10
Major/Minor     15.17763
MachineType     34404
KeNumberProcessors      4
SystemTime      2024-09-10 06:14:13+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductServer
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Sun Nov 10 07:20:39 2075
```

7. A trusted service launches an unfamiliar executable residing outside the usual IIS stack, signalling a persistence implant. What is the final full on-disk path of that executable, and which MITRE ATT&CK persistence technique ID corresponds to this behaviour?

Para esto, estuve buscando una referencia al fichero `shell.aspx` con los diferentes plugins que tiene volatility, encontré algo en los ficheos: 

```bash 
┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ /home/kali/blue-labs/volatility3/vol.py -f memdump.mem windows.filescan > analisis_memoria/windows.filescan                                                                                                                                                                                                                   
┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ grep "shell" analisis_memoria/windows.filescan
0xce0654c41b50  \Windows\System32\shell32.dll
0xce0654c5b3f0  \Windows\SysWOW64\shell32.dll
0xce0657648e10  \Windows\System32\WindowsPowerShell\v1.0\powershell.exe
0xce06577cd470  \Windows\System32\twinui.pcshell.dll
0xce06577ce0f0  \Windows\System32\en-US\shell32.dll.mui
0xce06577d68e0  \Windows\System32\windows.immersiveshell.serviceprovider.dll
0xce06577e4e90  \Windows\System32\en-US\twinui.pcshell.dll.mui
0xce0657972bb0  \Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe
0xce0657c48530  \Windows\System32\netshell.dll
0xce0657d3bb60  \Windows\Resources\Themes\aero\shell\normalcolor\shellstyle.dll
0xce0657d68ed0  \Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\e22c2559\92c7e946\shell.aspx.e819a670.compiled
0xce0657f14ae0  \Windows\System32\shell32.dll
0xce0657f284f0  \Windows\System32\en-US\shell32.dll.mui
```

La línea relevante:

´\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\e22c2559\92c7e946\shell.aspx.e819a670.compiled´

Esto nos dice varias cosas importantes:

a) El atacante subió shell.aspx vía SMB y lo ejecutó a través de IIS.

Cuando IIS ejecuta páginas ASP.NET, compila el .aspx a un ensamblado temporal dentro de:

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\`

Este directorio contiene compilaciones JIT de páginas ASP.NET.

Por eso aparece:

`shell.aspx.e819a670.compiled`

Este archivo no es el original .aspx, sino su versión compilada generada por el CLR cuando IIS la ejecutó.

Es evidencia definitiva de que IIS sí ejecutó la webshell.

> La compilación JIT (Just-In-Time) en ASP.NET es el proceso donde el Common Language Runtime (CLR) de .NET convierte el código de las páginas (como C# o VB.NET) de Lenguaje Intermedio Común (CIL) a código máquina nativo directamente en el momento de la ejecución (tiempo de ejecución), mejorando el rendimiento al compilar solo el código necesario bajo demanda y optimizándolo para la plataforma específica. Esto ocurre la primera vez que se solicita una página, haciendo que las llamadas posteriores sean más rápidas desde una caché.

Para esto, el laboratorio ya nos proporciona el fichero malicioso de nombre "updatenow.exe", revisando el hash en virustotal confirmamos que es malicioso. Ahora buscamos referencias de este archivo en el volcado de memoria usando los plugins de volatility: 

```bash
┌──(kali㉿kali)-[~/labs2/labs]
└─$ grep "updatenow" analisis_memoria/windows.cmdline
900     updatenow.exe   "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe"

┌──(kali㉿kali)-[~/labs2/labs]
└─$ grep "updatenow" analisis_memoria/windows.pstree
**** 900        4332    updatenow.exe   0xce0657ddb1c0  3       -       0       True    2024-09-10 06:08:23.000000 UTC      N/A     \Device\HarddiskVolume1\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\updatenow.exe     "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe"        C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe
```

La ruta `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` corresponde a uno de los mecanismos clásicos de persistencia en Windows, concretamente la carpeta de inicio (Startup folder) del menú de inicio. Cualquier ejecutable o acceso directo colocado ahí se lanza automáticamente cada vez que un usuario inicia sesión.

Es la Startup Folder global, también llamada:

- Common Startup Folder
- Carpeta de inicio para todos los usuarios

Su función es cargar programas cuando cualquier usuario del sistema inicia sesión. Es distinta de la carpeta de inicio individual del perfil de cada usuario.

Windows mantiene dos carpetas de inicio. 

| Tipo                | Ruta                                                                               | Característica                       |
| ------------------- | ---------------------------------------------------------------------------------- | ------------------------------------ |
| Startup global      | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`                     | Se ejecuta para *todos* los usuarios |
| Startup por usuario | `C:\Users\<usuario>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` | Se ejecuta solo para ese usuario     |

Windows, durante la fase de creación del entorno de escritorio tras el login, examina esa carpeta. Todo lo que encuentre se ejecuta automáticamente:

- .exe
- Accesos directos .lnk
- Scripts .bat, .ps1, .vbs

Por tanto, colocar ahí un binario malicioso permite:

- Ejecución automática en cada inicio de sesión.
- Persistencia sin necesidad de modificar claves de registro más vigiladas (como Run o RunOnce).- Bajo perfil, porque muchos administradores no revisan manualmente esta carpeta.

Esto corresponde a la siguiente técnica MITRE: 

![](../assets/images/cyber-lockdown/2.png)

8. The reverse shell’s outbound traffic is handled by a built-in Windows process that also spawns the implanted executable. What is the name of this process, and what PID does it run under?

Para esto ya hemos identificado el proceso malicioso, así que podemos filtrar por su PPID: 

```bash 
┌──(kali㉿kali)-[~/labs2/labs]
└─$ grep -E "900|4332" analisis_memoria/windows.pslist
4332    2452    w3wp.exe        0xce06574ca080  0       -       0       False   2024-09-10 05:44:45.000000 UTC      2024-09-10 06:10:48.000000 UTC  Disabled
900     4332    updatenow.exe   0xce0657ddb1c0  3       -       0       True    2024-09-10 06:08:23.000000 UTC      N/A     Disabled
```

w3wp.exe es el IIS Worker Process (IIS = Internet Information Services).
Es el proceso que ejecuta aplicaciones web en un servidor IIS.

Normalmente se encuentra en:

`C:\Windows\System32\inetsrv\w3wp.exe`

Es un proceso legítimo, pero además es una elección clásica para los atacantes en entornos Windows con IIS por dos motivos:

a) Tiene permisos adecuados

Como proceso del servidor web, suele ejecutarse con privilegios suficientes para:
- cargar módulos,
- ejecutar código,
- lanzar procesos hijo.

b) Tiene salida a Internet

Un proceso de servidor web suele tener capacidad para generar tráfico de salida, lo que facilita:

- descargar payloads,
- establecer reverse shells,
- tunelizar tráfico sin crear nuevos procesos sospechosos.

Por eso, si un atacante explota una vulnerabilidad en IIS, w3wp.exe es habitualmente el proceso comprometido que luego:

- ejecuta la primera carga útil,
- descarga o lanza el malware final,
- maneja la comunicación con el atacante.

9. Static inspection reveals the binary has been packed to hinder analysis. Which packer was used to obfuscate it?

Un binario empaquetado es un ejecutable que ha sido comprimido y/o ofuscado mediante un packer con dos fines principales:

a) Reducir tamaño
El ejecutable se comprime para que ocupe menos espacio.

b) Dificultar el análisis

La compresión hace que:

- El contenido del binario no sea legible.
- Se oculten strings, imports y estructuras PE.
- Las herramientas de análisis estático (como strings, pefile) vean información incompleta.
- Los analistas tengan dificultades para ver el código real sin desempaquetarlo.

Así que podemos usar los siguiente comandos para verificar esto: 

```bash 
┌──(kali㉿kali)-[~/labs2/labs]
└─$ file updatenow.exe     
updatenow.exe: PE32 executable for MS Windows 5.01 (GUI), Intel i386, UPX compressed, 3 sections
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs2/labs]
└─$ rabin2 -S updatenow.exe
nth paddr          size vaddr         vsize perm flags      type name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000400      0x0 0x00401000  0xbe000 -rwx 0xe0000080 ---- UPX0
1   0x00000400  0x56400 0x004bf000  0x57000 -rwx 0xe0000040 ---- UPX1
2   0x00056800  0x3c800 0x00516000  0x3d000 -rw- 0xc0000040 ---- .rsrc
```

UPX (Ultimate Packer for eXecutables) es un packer legítimo, libre y muy común.
Soporta formatos como PE (Windows), ELF (Linux) y otros.

Características clave:

- Comprime el binario en secciones llamadas UPX0 y UPX1.
- Añade un stub (código inicial) que descomprime el ejecutable en memoria cuando se ejecuta.
- Fácil de usar y rápido.
- Muchos malware lo utilizan por su sencillez.

10. Threat-intel analysis shows the malware beaconing to its command-and-control host. Which fully qualified domain name (FQDN) does it contact?

Para esto primero tenemos que calcular el hash: 

```bash 
┌──(kali㉿kali)-[~/labs2/labs]
└─$ sha256sum updatenow.exe 
c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f  updatenow.exe
```
Subimos a virustotal, en la sección de *behavior* podemos ver una petición dns y tráfico IP bastantes extraños: 

![](../assets/images/cyber-lockdown/3.png)

Viendo el análisis de la ip vemos que efectivamente tiene historial malicioso. 

11. Open-source intel associates that hash with a well-known commodity RAT. To which malware family does the sample belong?

Esto lo encontré con el siguiente reporte: `https://bazaar.abuse.ch/sample/c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f/`

Se trata de un AgentTesla, que es una familia de malware del tipo infostealer (ladrón de información) escrita en .NET, activa desde aproximadamente 2014 y utilizada de forma masiva en campañas de phishing. Su propósito principal es robar credenciales y datos sensibles del sistema comprometido.

