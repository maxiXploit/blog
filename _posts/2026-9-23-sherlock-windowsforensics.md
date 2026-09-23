

----------

**Scenario: A targeted phishing campaign is carried out against our organization, and so far the phishing mail has been opened by 3 systems in our network. A quick triage image was collected from one of the infected systems and Provided to you for identification of TTP being used by attackers. Identify the Techniques and tactics used by the attacker so our incident response team can respond and mitigate any further compromises across the network.**

Para este lab se nos da un `.ad1`, por lo que vamos a montarlo con ´FTK Imager`.

---------

**1\. Initial Access was made through a Malicious Document delivered through email. What Was the full path where the document was downloaded?**

Después de montar en FTK tenemos que acceder al Registry de Windows, específicamente al Hive de usuario, donde encontraremos los shellbags, donde veremos el historial de carpetas/rutas navegadas por el usuario, estas Hives están en:

```txt
C:\Users\<USUARIO>\NTUSER.DAT
C:\Users\<USUARIO>\AppData\Local\Microsoft\Windows\UsrClass.dat
```


Abrimos `Shellbag explorer` y veremos la evidencia:

![](../assets/images/sherlock-windowsforensics/1.png)

--------

**2\. What's the document name? (The document which was delivered via phishing)**

```powershell
PS C:\Users\Lenovo\Downloads\compartida\RBCmd> .\RBCmd.exe -f "C:\Users\Lenovo\tmp\RecycleBin\S-1-5-21-1187034906-4050784041-186213912-1001\IWKWHDC.docx"                                                                                       RBCmd version 2026.5.0                                                                                                                                                                                                                          Author: Eric Zimmerman (saericzimmerman@gmail.com)                                                                      https://github.com/EricZimmerman/RBCmd                                                                                                                                                                                                          Command line: -f C:\Users\Lenovo\tmp\RecycleBin\S-1-5-21-1187034906-4050784041-186213912-1001\IWKWHDC.docx              Warning: Administrator privileges not found!                                                                                                                                                                                                    Found 1 files. Processing...                                                                                                                                                                                                                    Source file: C:\Users\Lenovo\tmp\RecycleBin\S-1-5-21-1187034906-4050784041-186213912-1001\IWKWHDC.docx                                                                                                                                          Version: 2 (Windows 10/11)                                                                                              File size: 12,411 (12.1KB)                                                                                              File name: C:\Users\CyberJunkie\Downloads\MailDownloads\Security Awareness.docx                                         Deleted on: 2022-08-21 08:03:33                                                                                                                                                                                                                                                                                                                                         Processed 1 out of 1 files in 0.1701 seconds    
```







