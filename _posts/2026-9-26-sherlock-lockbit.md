
---

**Scenario: You are a Digital Forensics and Incident Response (DFIR) analyst tasked with investigating a ransomware attack that has affected a company's system. The attack has resulted in file encryption, and the attackers are demanding payment for the decryption of the affected files. You have been given a memory dump of the affected system to analyze and provide answers to specific questions related to the attack.**

--------

Para este laboratorio nos dan un solo fichero, una extracción de memoria:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/lockbit]
└─$ file Lockbit.vmem 
Lockbit.vmem: data
```

Así que pasamos rápido a las preguntas.

--------

**1\. Can you determine the date and time that the device was infected with the malware? (UTC, format: YYYY-MM-DD hh:mm:ss)**

Primero empezamos obteniendo la información del sistema:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/lockbit]
└─$ python3 ~/blue-labs/volatility3/vol.py -f Lockbit.vmem windows.info
Volatility 3 Framework 2.26.2
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. Lockbit.vmem and Lockbit.vmss.
Progress:  100.00               PDB scanning finished                                                                                              
Variable        Value

Kernel Base     0xf80002a18000
DTB     0x187000
Symbols file:///home/kali/blue-labs/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/25F4F1A66D0C4385902C9414E61870A2-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdDebuggerDataBlock     0xf80002bfb130
NTBuildLab      7601.26111.amd64fre.win7sp1_ldr_
CSDVersion      1
KdVersionBlock  0xf80002bfb0e8
Major/Minor     15.7601
MachineType     34404
KeNumberProcessors      2
SystemTime      2023-04-13 10:07:08+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  6
NtMinorVersion  1
PE MajorOperatingSystemVersion  6
PE MinorOperatingSystemVersion  1
PE Machine      34404
PE TimeDateStamp        Tue Aug  9 03:04:25 2022
```

Ahora obtenemos la lista de procesos:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/lockbit]
└─$ python3 ~/blue-labs/volatility3/vol.py -f Lockbit.vmem windows.pslist > windows.pslist


```

-----

**2\. What is the name of the ransomware family responsible for the attack?**

*******

Submit Task
Task 2

Hint
What file extension is appended to the encrypted files by the ransomware?

.*******

Submit Task
Task 3

Hint
What is the TLSH (Trend Micro Locality Sensitive Hash) of the ransomware?

************************************************************************

Submit Task
Task 4

Hint
Which MITRE ATT&CK technique ID was used by the ransomware to perform privilege escalation?

*****

Submit Task
Task 5

Hint
What is the SHA256 hash of the ransom note dropped by the malware?

****************************************************************

Submit Task
Task 6

Hint
What is the name of the registry key edited by the ransomware during the attack to apply persistence on the infected system?
