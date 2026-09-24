

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

Para esto revisamos el `$Recycle.bin`, ya que el documento de phishing pudo haber sido descargado y posteriormente eliminado por el usuario, pero su rastro todavía puede quedar registrado en la papelera.
Cuando un archivo se elimina normalmente, Windows no lo borra inmediatamente. Lo mueve a $Recycle.Bin y conserva información que puede ser muy útil forensemente.

Usando `RBCmd.exe` de Zimmerman:

```powershell
PS C:\Users\User\Downloads\compartida\RBCmd> .\RBCmd.exe -f "C:\Users\User\tmp\RecycleBin\S-1-5-21-1187034906-4050784041-186213912-1001\IWKWHDC.docx"                                                                                       
RBCmd version 2026.5.0                                                                                                                                                                                                                          
Author: Eric Zimmerman (saericzimmerman@gmail.com)                                                                      
https://github.com/EricZimmerman/RBCmd                                                                                                                                                                                                          
Command line: -f C:\Users\User\tmp\RecycleBin\S-1-5-21-1187034906-4050784041-186213912-1001\IWKWHDC.docx              
Warning: Administrator privileges not found!                                                                                                                                                                                                    
Found 1 files. Processing...                                                                                                                                                                                                                    
Source file: C:\Users\User\tmp\RecycleBin\S-1-5-21-1187034906-4050784041-186213912-1001\IWKWHDC.docx                                                                                                                                          
Version: 2 (Windows 10/11)                                                                                              
File size: 12,411 (12.1KB)                                                                                              
File name: C:\Users\CyberJunkie\Downloads\MailDownloads\Security Awareness.docx                                         
Deleted on: 2022-08-21 08:03:33                                                                                                                                                                                                                                                                                                                                         
Processed 1 out of 1 files in 0.1701 seconds
```

Fue esto eliminado a las `2022-08-21 08:03:33`
--------

**3\. What's the stager name which connected to the attacker C2 server(Fullpath\name)**

El stager, como sugiere la pregunta, es el programa encargado en conectarse al C2 para recibir instrucciones, para rastrear esto tenemos que buscar en el Prefetch, que crea un registro para cada archivo ejecutado.
Parseamos el `Prefetch` y en TimeLine Explorer revisamos el .csv:

![](../assets/images/sherlock-windowsforensics/2.png)

Vemos un par de nombres sospechosos, que están en el rango de tiempo cercano a la eliminación del archivo de la pregunta anterior.

---------

**4\. The attacker manipulated MACB Timestamps of the stager executable to confuse Analysts. Analyze the timestamps of the stager and verify the original timestamp and tampered one. (ORIGINAL TIMESTAMP : TAMPERED TIMESTAMP)**

Esto lo verificamos en la MFT, parseamos a .csv y filtramos por nombre:

![](../assets/images/sherlock-windowsforensics/3.png)

----------

**4\. The attacker set up persistence by manipulating registry keys. All we know is that GlobalFlags image file technique was used to set up persistence. When exiting a certain process, the attacker persistence executable is executed. What's the name of that process?**

Esto lo encontraremos en la hive de `SOFTWARE` -> `HKLM\SOFTWARE` -> Config de software y del SO válida para todo el sistema.

Tanto IFEO (Image File Execution Options) como SilentProcessExit son mecanismos del sistema operativo. Los lee Windows sin importar qué usuario ejecute el proceso, así que están en `C:\Windows\System32\config\SOFTWARE`. Esto también nos dice algo del atacante: para escribir en HKLM necesitó privilegios de administrador.

**Es una función de depuración. Sirve para investigar por qué un proceso termina inesperadamente y sin crash, por ejemplo cuando un servicio "se muere solo" sin dejar rastros.**

Las configuraciones involucradas:

- `Image File Execution Options\<proceso.exe>`: aquí se activa el monitoreo con el valor `GlobalFlag`. Ese valor es un bitmask del NT Global Flag (lo que manipula la herramienta `gflags.exe`). El bit `0x200` (`FLG_MONITOR_SILENT_PROCESS_EXIT`) significa "vigila cuando este proceso salga".

b) SilentProcessExit\<proceso.exe>: aquí se configura qué hacer cuando ese proceso termina. Los valores principales son:

ReportingMode: bitmask. 0x1 lanza un proceso monitor, 0x2 genera un dump local, 0x4 manda una notificación.
MonitorProcess: ruta del ejecutable que se lanza al salir el proceso.
LocalDumpFolder y DumpType: dónde y cómo guardar el dump.

"Silent exit" significa que el proceso terminó por ExitProcess o TerminateProcess, es decir, sin crash. Windows lo detecta, y el que orquesta la reacción es WerFault.exe (Windows Error Reporting).



