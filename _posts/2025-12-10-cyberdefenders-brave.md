
1.- What time was the RAM image acquired according to the suspect system?

Para esto usamos el plugin de `windows.info`: 

```bash 
┌──(venv)─(kali㉿kali)-[~/labs2/labs/temp_extract_dir/c49-AfricanFalls2]
└─$ /home/kali/blue-labs/volatility3/vol.py -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.info > analisis_memoria/windows.info

┌──(venv)─(kali㉿kali)-[~/labs2/labs/temp_extract_dir/c49-AfricanFalls2]
└─$ cat analisis_memoria/windows.info
Volatility 3 Framework 2.26.2

Variable        Value

Kernel Base     0xf8043cc00000
DTB     0x1aa000
Symbols file:///home/kali/blue-labs/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/769C521E4833ECF72E21F02BF33691A5-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf8043d80f368
Major/Minor     15.19041
MachineType     34404
KeNumberProcessors      4
SystemTime      2021-04-30 17:52:19+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Tue Oct 11 07:04:26 1977
```

2.- What is the SHA256 hash value of the RAM image?

Calculamos esto con el siguiente comando: 

```bash
┌──(venv)─(kali㉿kali)-[~/labs2/labs/temp_extract_dir/c49-AfricanFalls2]
└─$ sha256sum 20210430-Win10Home-20H2-64bit-memdump.mem
9db01b1e7b19a3b2113bfb65e860fffd7a1630bdf2b18613d206ebf2aa0ea172  20210430-Win10Home-20H2-64bit-memdump.mem
```

3.- What is the process ID of brave.exe?

Para esto podemos usar el plugin `windows.pslist`: 

```bash 
┌──(venv)─(kali㉿kali)-[~/labs2/labs/temp_extract_dir/c49-AfricanFalls2]
└─$ /home/kali/blue-labs/volatility3/vol.py -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.pslist > analisis_memoria/windows.pslist

┌──(venv)─(kali㉿kali)-[~/labs2/labs/temp_extract_dir/c49-AfricanFalls2]
└─$ grep "brave"  analisis_memoria/windows.pslist
4856    1872    brave.exe       0xbf0f6ca782c0  0       -       1       False   2021-04-30 17:48:45.000000 UTC  2021-04-30 17:50:56.000000 UTC  Disabled
```

4.- How many established network connections were there at the time of acquisition?

Para esto tuve un par de problemas, el plugin de volatility3 para esto parecìa no funcionar, entonces recurrì a la herramienta de MemProcFS, pero el registro de netscan de esta herramienta solo me mostraba 9 conexiones establecidas. 
Finalmente usé Volatility Workbench para ver si aquí el plugin de netstat o netscan funcinaba, al terminar la ejecución del comando guarde la salida del comando, pasé el fichero a mi mmáquina linux y finalmente pude obtener la respuesta correcta. 

```bash
┌──(venv)─(kali㉿kali)-[~/labs2/labs/mem_dump]
└─$ grep -i "established" windows.netstat 
0xbf0f6a53ca20  TCPv4   10.0.2.15       49833   52.230.222.68   443     ESTABLISHED     2812    svchost.exe     2021-04-30 17:50:07.000000 UTC
0xbf0f6ad16050  TCPv4   10.0.2.15       49829   142.250.191.208 443     ESTABLISHED     5624    svchost.exe     2021-04-30 17:49:58.000000 UTC
0xbf0f6ad1fad0  TCPv4   10.0.2.15       49847   52.230.222.68   443     ESTABLISHED     2812    svchost.exe     2021-04-30 17:52:17.000000 UTC
0xbf0f6c6352b0  TCPv4   10.0.2.15       49842   52.113.196.254  443     ESTABLISHED     5104    SearchApp.exe   2021-04-30 17:51:25.000000 UTC
0xbf0f6c7104d0  TCPv4   10.0.2.15       49778   185.70.41.130   443     ESTABLISHED     1840    chrome.exe      2021-04-30 17:45:00.000000 UTC
0xbf0f6cd4fa20  TCPv4   10.0.2.15       49837   204.79.197.200  443     ESTABLISHED     5104    SearchApp.exe   2021-04-30 17:51:18.000000 UTC
0xbf0f6d0c64a0  TCPv4   10.0.2.15       49843   204.79.197.222  443     ESTABLISHED     5104    SearchApp.exe   2021-04-30 17:51:26.000000 UTC
0xbf0f6d51c4a0  TCPv4   10.0.2.15       49838   13.107.3.254    443     ESTABLISHED     5104    SearchApp.exe   2021-04-30 17:51:23.000000 UTC
0xbf0f6d525a20  TCPv4   10.0.2.15       49845   23.101.202.202  443     ESTABLISHED     1156    MsMpEng.exe     2021-04-30 17:51:36.000000 UTC
0xe80000193a20  TCPv4   10.0.2.15       49845   23.101.202.202  443     ESTABLISHED     1156    MsMpEng.exe     2021-04-30 17:51:36.000000 UTC
                                                                                                                                                                                            
┌──(venv)─(kali㉿kali)-[~/labs2/labs/mem_dump]
└─$ grep -i "established" windows.netstat | wc -l 
10
```

5.- Which domain name does Chrome have an established network connection with?

Para esto ejecutamos el siguiente comando para realizar una búsqueda inversa DNS: 

```bash 
┌──(venv)─(kali㉿kali)-[~/labs2/labs/mem_dump]
└─$ nslookup 185.70.41.130          
130.41.70.185.in-addr.arpa      name = 185-70-41-130.protonmail.ch.

Authoritative answers can be found from:

```

> El 185-70-41-130 antes del dominio protonmail.ch es simplemente una representación del nombre de host asignado a esa dirección IP en el registro PTR. 
> Este nombre puede ser útil para verificar la identidad del servidor o del servicio que está utilizando esa IP.

6.- What is the MD5 hash value of the process executable for PID 6988?

Para esto podemos usar el siguiente comando: 

┌──(venv)─(kali㉿kali)-[~/labs2/labs/6988_dumpfiles]
└─$ /home/kali/blue-labs/volatility3/vol.py -o dumpfiles -f temp_extract_dir/c49-AfricanFalls2/20210430-Win10Home-20H2-64bit-memdump.mem windows.dumpfiles --pid 6988 

```bash
┌──(venv)─(kali㉿kali)-[~/labs2/labs/6988_dumpfiles]
└─$ /home/kali/blue-labs/volatility3/vol.py -f ../temp_extract_dir/c49-AfricanFalls2/20210430-Win10Home-20H2-64bit-memdump.mem windows.pslist.PsList --pid 6988 --dump 
Volatility 3 Framework 2.26.2
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

6988    4352    OneDrive.exe    0xbf0f6d4262c0  26      -       1       True    2021-04-30 17:40:01.000000 UTC  N/A     6988.OneDrive.exe.0x1c0000.dmp
                                                                                                                                                                                             
┌──(venv)─(kali㉿kali)-[~/labs2/labs/6988_dumpfiles]
└─$ md5sum  6988.OneDrive.exe.0x1c0000.dmp 
0b493d8e26f03ccd2060e0be85f430af  6988.OneDrive.exe.0x1c0000.dmp
```

7.- Para esto podemos usar la herramienta HxD, con `control + g` buscamos el offset que nos interesa, contamos 6 bytes y encontramos la palabra buscada. 



8.- What is the creation date and time of the parent process of powershell.exe?

Podemos buscar este proceso con el plugin de `pslist` de volatility

```bash 
┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ /home/kali/blue-labs/volatility3/vol.py -f temp_extract_dir/c49-AfricanFalls2/20210430-Win10Home-20H2-64bit-memdump.mem windows.pslist > mem_dump/windows.pslist

┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ grep "powershell"  mem_dump/windows.pslist 
5096    4352    powershell.exe  0xbf0f6d97f2c0  12      -       1       False   2021-04-30 17:51:19.000000 UTC  N/A     Disabled
                                                                                                                             
┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ grep "4352"  mem_dump/windows.pslist       
4352    4296    explorer.exe    0xbf0f6ca662c0  82      -       1       False   2021-04-30 17:39:48.000000 UTC  N/A     Disabled
6772    4352    SecurityHealth  0xbf0f6d493080  1       -       1       False   2021-04-30 17:40:00.000000 UTC  N/A     Disabled
6884    4352    VBoxTray.exe    0xbf0f6d186080  11      -       1       False   2021-04-30 17:40:01.000000 UTC  N/A     Disabled
6988    4352    OneDrive.exe    0xbf0f6d4262c0  26      -       1       True    2021-04-30 17:40:01.000000 UTC  N/A     Disabled
1328    4352    chrome.exe      0xbf0f6d53e080  26      -       1       False   2021-04-30 17:44:52.000000 UTC  N/A     Disabled
5096    4352    powershell.exe  0xbf0f6d97f2c0  12      -       1       False   2021-04-30 17:51:19.000000 UTC  N/A     Disabled
```

El que nos interesa es el "explorer.exe".


9.- 

```bash 
┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ /home/kali/blue-labs/volatility3/vol.py -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.pstree > analisis_memoria/windows.pstre

┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ grep "notepad" mem_dump/windows.pstree 
2520    2152    notepad.exe     0xbf0f6d8450c0  1       -       1       False   2021-04-30 17:44:28.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\notepad.exe "C:\Windows\system32\NOTEPAD.EXE" C:\Users\JOHNDO~1\AppData\Local\Temp\7zO4FB31F24\accountNum        C:\Windows\system32\NOTEPAD.EXE
``` 


10.- 

Para esto podemos usar el siguiente comando: 

```bash
┌──(venv)─(kali㉿kali)-[~/labs2/labs]
└─$ /home/kali/blue-labs/volatility3/vol.py -r pretty -f temp_extract_dir/c49-AfricanFalls2/20210430-Win10Home-20H2-64bit-memdump.mem windows.registry.userassist > mem_dump/windows.registry.userassist
```

Este comando sirve para extraer y decodificar la clave del Registro de Windows llamada UserAssist, que contiene evidencia forense de los programas ejecutados por el usuario, junto con un contador y un timestamp.

Una vez ejecutado, podemos buscar por brave: 

```bash 
┌──(kali㉿kali)-[~/labs2/labs]
└─$ grep "Brave" mem_dump/windows.registry.userassist
** | 0xa80333cda000 | \??\C:\Users\John Doe\ntuser.dat | ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count | 2021-04-30 17:52:18.000000 UTC | Value |                                                                                                  %ProgramFiles%\BraveSoftware\Temp\GUM20E0.tmp\BraveUpdate.exe | N/A |     0 |           0 | 0:00:03.531000 |                            N/A |
** | 0xa80333cda000 | \??\C:\Users\John Doe\ntuser.dat | ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count | 2021-04-30 17:52:18.000000 UTC | Value |                                                                                                            %ProgramFiles%\BraveSoftware\Update\BraveUpdate.exe | N/A |     0 |           1 | 0:00:24.797000 |                            N/A |
** | 0xa80333cda000 | \??\C:\Users\John Doe\ntuser.dat | ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count | 2021-04-30 17:52:18.000000 UTC | Value |                                                                                                                                                          Brave | N/A |     9 |          22 | 4:01:54.328000 | 2021-04-30 17:48:45.000000 UTC |
** | 0xa80333cda000 | \??\C:\Users\John Doe\ntuser.dat | ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count | 2021-04-30 17:51:18.000000 UTC | Value |                                                                                                                              C:\Users\Public\Desktop\Brave.lnk | N/A |     8 |           0 | 0:00:00.508000 | 2021-04-30 17:48:45.000000 UTC |
```
