

# **Cyberdefenders - DumpMe**

Vamos a estar trabajando con un volcado de memoria de la maquina de un empleado que fue infectado con un malware de meterpreter. 

Para este laboratori se nos proporciona unicamente 1 fichero `.mem` que vamos a estar analizando con `volatility3`, la intalación de esta herramieta es super sencilla. 

El fichero que se nos proporciona: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ ls
Triage-Memory.mem
```

Para instalar volatility: 
```bash 
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 -m venv venv
source venv/bin/activate
cd volatility3
pip install volatility3
```

Volatility no es mas que un framework muy utilizado para realizar analisis forenses de volcados de memoria, la herramienta viene con varios pluggins que nos permiten realizar ciertas tareas de análisis, a medida que avancemos con el laboratorio iremos detallando el funcinamiento de cada pluggin. 
Explicado esto, pasemos rápidamente a las preguntas.

---

<p style="color: cian;">1. ¿Cuál es el hash SHA1 de Triage-Memory.mem (volcado de memoria)?</p>


Siempre es importante demostrar que la información con la que estamos trabajado no ha sido alterado y que es la correcta, esto podemos calcularlo fácilmente desde la termina: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ sha1sum Triage-Memory.mem 
c95e8cc8c946f95a109ea8e47a6800de10a27abd  Triage-Memory.mem
```

---
<p  style;"color: cian;">2. ¿Qué perfil de volatility  es el más apropiado para esta máquina? (por ejemplo: Win10x86_14393)</p>

Para esto podemos usar el siguiente comando, que nos da una información general de la imagen que estamo usando: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ vol -f Triage-Memory.mem windows.info
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished                                                                                              
Variable        Value

Kernel Base     0xf80002808000
DTB     0x187000
Symbols file:///home/kali/blue-labs/volatility3/venv/lib/python3.13/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/2E37F962D699492CAAF3F9F4E9770B1D-2.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdDebuggerDataBlock     0xf800029f80a0
NTBuildLab      7601.18741.amd64fre.win7sp1_gdr.
CSDVersion      1
KdVersionBlock  0xf800029f8068
Major/Minor     15.7601
MachineType     34404
KeNumberProcessors      2
SystemTime      2019-03-22 05:46:00+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  6
NtMinorVersion  1
PE MajorOperatingSystemVersion  6
PE MinorOperatingSystemVersion  1
PE Machine      34404
PE TimeDateStamp        Tue Feb  3 02:25:01 2015
```

Donde: 

* `NtMajorVersion: 6`
* `NtMinorVersion: 1`
* `CSDVersion: 1` → esto indica **Service Pack 1**
* `Is64Bit: True` → arquitectura de 64 bits
* `NTBuildLab: 7601.18741.amd64fre.win7sp1_gdr.` → Windows 7 SP1, build 7601

> `Win7SP1x64`

---
<p style="color: cian;">3. ¿Cuál era el PID  de notepad.exe? </p>


```bash
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ vol -f Triage-Memory.mem windows.pslist > pslist      
                                                                                                                                                                                            
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ grep -E "notepad|PID"  pslist
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output
3032    1432    notepad.exe     0xfa80054f9060  1       60      1       False   2019-03-22 05:32:22.000000 UTC  N/A     Disabled
```

---
<p style="color: cian;">4. Nombra el child process de wscript.exe.</p>

Primero podemos filtrar por el nombre del proceso para obtener su PID, y después ya filtramos por ese PID: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ grep -E "wscript.exe|PID"  pslist
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output
5116    3952    wscript.exe     0xfa8005a80060  8       312     1       True    2019-03-22 05:35:32.000000 UTC  N/A     Disabled
                                                                                                                                                                                            
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ grep -E "wscript.exe|PID|5116"  pslist
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output
5116    3952    wscript.exe     0xfa8005a80060  8       312     1       True    2019-03-22 05:35:32.000000 UTC  N/A     Disabled
3496    5116    UWkpjFjDzM.exe  0xfa8005a1d9e0  5       109     1       True    2019-03-22 05:35:33.000000 UTC  N/A     Disabled
```

Ya podemos ver que es un nombre bastante estraño, si filramos por su PID observamos lo siguiente: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ grep -E "wscript.exe|PID|5116|3496"  pslist
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output
5116    3952    wscript.exe     0xfa8005a80060  8       312     1       True    2019-03-22 05:35:32.000000 UTC  N/A     Disabled
3496    5116    UWkpjFjDzM.exe  0xfa8005a1d9e0  5       109     1       True    2019-03-22 05:35:33.000000 UTC  N/A     Disabled
4660    3496    cmd.exe 0xfa8005bb0060  1       33      1       True    2019-03-22 05:35:36.000000 UTC  N/A     Disabled
```

El `UWkpjFjDzM.exe` inició otro proceso, un `cmd.exe`, ya un IOC bastante importante. 

---
<p style="color: cian;">5. ¿Cuál era la dirección IP de la máquina en el momento en que se creó el volcado de RAM?</p>

Para esto podemos usar el siguiente comando: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ grep -iE "UWkpjFjDzM.exe|proto" netscan
Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created
0x13e397190     TCPv4   10.0.0.101      49217   10.0.0.106      4444    ESTABLISHED     3496    UWkpjFjDzM.exe  N/A
```

Hay que fijarnos en el campo `LocalAddr`, veremos la misma ip que no pertenece al rango de ip's de loopback.

---
<p style="color: cian;">6. Basándose en la respuesta sobre el PID infectado, ¿puede determinar la IP del atacante?</p>


Esto ya lo podemos ver en la línea presentada en la pregunta anterior: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ grep -iE "UWkpjFjDzM.exe|proto" netscan
Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created
0x13e397190     TCPv4   10.0.0.101      49217   10.0.0.106      4444    ESTABLISHED     3496    UWkpjFjDzM.exe  N/A
```

El proceso UWkpjFjDzM.exe mantenía una conexión activa a otro host (10.0.0.106) en el mismo rango de red de la maquina infectada. 

---
<p style="color: cian;">7. ¿Cuántos procesos están asociados con VCRUNTIME140.dll?</p>

Buscando en internet vemos que VCRUNTIME140.dll es un archivo DLL (Dynamic Link Library) que forma parte del paquete redistribuible de Microsoft Visual C++. Este paquete contiene las bibliotecas de tiempo de ejecución necesarias para que las aplicaciones y juegos desarrollados con Visual C++ puedan funcionar correctamente en Windows. 

Así que tenemos que filtrar 
Pero como estoy usando volatility3, tengo un problema para ver la información completa: 

En Volatility 2, el plugin dlllist analiza tanto el PEB (Process Environment Block) como las listas internas del espacio de usuario, lo que permite recuperar una lista completa de DLLs incluso si algunas están parcialmente descargadas o en memoria no estándar.

En Volatility 3, el plugin windows.dlllist depende mucho más del layout estructurado y del correcto parsing del VadRoot (Virtual Address Descriptors). Si ese árbol está dañado o incompleto en el dump (común en Windows 7), puede que Volatility 3 no detecte todas las DLLs cargadas.

Así que instalamaos volatility2, no pasa nada:

```bash
git clone https://github.com/volatilityfoundation/volatility
cd volatility
python3 -m venv venv
pip install pyinstaller
```

Y ya podemos responder a la pregunta: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility2/volatility/labs]
└─$ python2 ../vol.py --profile=Win7SP1x64 -f Triage-Memory.mem dlllist | grep "VCRUNTIME140.dll"
Volatility Foundation Volatility Framework 2.6.1
0x000007fefa5c0000            0x16000             0xffff 4168440                        C:\Program Files\Common Files\Microsoft Shared\ClickToRun\VCRUNTIME140.dll
0x00000000745f0000            0x15000             0xffff 47552144                       C:\Program Files (x86)\Microsoft Office\root\Office16\VCRUNTIME140.dll
0x00000000745f0000            0x15000             0xffff 35953048                       C:\Program Files (x86)\Microsoft Office\root\Office16\VCRUNTIME140.dll
0x00000000745f0000            0x15000                0x3 7109480                        C:\Program Files (x86)\Microsoft Office\root\Office16\VCRUNTIME140.dll
0x00000000745f0000            0x15000             0xffff 5871200                        C:\Program Files (x86)\Microsoft Office\root\Office16\VCRUNTIME140.dll
```

Contamos 5 procesos. 

---
<p style="color: cian;">8. Tras volcar el proceso infectado, ¿cuál es su hash md5?</p>

Bien, anteriormente ya vimos que el PID del malware que nos interesa es el `3496`

Así que obtenemos ese fichero en específico, es más fácil con volatility2: 

```bash
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility2/volatility/labs]
└─$ python2 ../vol.py -f Triage-Memory.mem --profile=Win7SP1x64 procdump -p3496 --dump-dir .
Volatility Foundation Volatility Framework 2.6.1
Process(V)         ImageBase          Name                 Result
------------------ ------------------ -------------------- ------
0xfffffa8005a1d9e0 0x0000000000400000 UWkpjFjDzM.exe       OK: executable.3496.exe
                                                                                                                                                                                            
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility2/volatility/labs]
└─$ ls
executable.3496.exe  Triage-Memory.mem
                                                                                                                                                                                            
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility2/volatility/labs]
└─$ md5sum executable.3496.exe 
690ea20bc3bdfb328e23005d9a80c290  executable.3496.exe
```

---
<p style="color: cian;">9. ¿Cuál es el hash LM de la cuenta de Bob?</p>


Entendamos los conceptos de la pregunta: 

### ¿Qué es un **VAD**?

**VAD** significa **Virtual Address Descriptor**.
Es una estructura interna del sistema operativo Windows que mantiene información sobre los **rangos de memoria virtual** que un proceso tiene asignados.

* Cada vez que un proceso reserva o asigna memoria (por ejemplo, al cargar una DLL o asignar un buffer), Windows crea un **nodo VAD** para describir esa región de memoria.
* Los VADs se organizan en una **estructura de árbol**, lo que permite al sistema localizar regiones de memoria rápidamente.

### ¿Qué es un **VAD node**?

Un **nodo VAD** es simplemente una **entrada individual** en ese árbol.
Cada nodo representa una región de memoria virtual de un proceso específico, y contiene información como:

* Dirección base y tamaño de la región.
* Tipo de protección de memoria (lectura, escritura, ejecución).
* Si la región está compartida, mapeada a un archivo, etc.

### ¿Qué es la "**memory protection**"?

La **protección de memoria** especifica **qué operaciones están permitidas** en una región de memoria:

* `PAGE_READONLY`: solo lectura.
* `PAGE_READWRITE`: lectura y escritura.
* `PAGE_EXECUTE_READ`: se puede leer y ejecutar (por ejemplo, código).
* `PAGE_NOACCESS`: ninguna operación está permitida.

Estas protecciones son importantes para la seguridad y el funcionamiento del sistema operativo, ya que evitan que el código malicioso escriba o ejecute ciertas regiones de memoria.

Sabiendo esto, podemos usar el siguiente comando: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ python2 vol.py --profile=Win7SP1x64 -f  /home/kali/blue-labs/volatility3/labs/temp_extract_dir/Triage-Memory.mem vadinfo | grep "0xfffffa800577ba10" -C 5
Volatility Foundation Volatility Framework 2.6.1
NumberOfMappedViews:                2 NumberOfUserReferences:          3
Control Flags: Commit: 1
First prototype PTE: fffff8a001021f78 Last contiguous PTE: fffff8a001021ff0
Flags2: 

VAD node @ 0xfffffa800577ba10 Start 0x0000000000030000 End 0x0000000000033fff Tag Vad 
Flags: NoChange: 1, Protection: 1
Protection: PAGE_READONLY
Vad Type: VadNone
ControlArea @fffffa8005687a50 Segment fffff8a000c4f870
NumberOfSectionReferences:          1 NumberOfPfnReferences:
```

---
<p style="color: cian;">¿Qué protección de memoria tenía el VAD que empezaba en 0x00000000033c0000 y terminaba en 0x00000000033dffff?</p>

Esto es como la pregunta anterior, aplicamos un filtro por ese nodo 


```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ python2 vol.py --profile=Win7SP1x64 -f  /home/kali/blue-labs/volatility3/labs/temp_extract_dir/Triage-Memory.mem vadinfo | grep "0x00000000033dffff" -C 5
Volatility Foundation Volatility Framework 2.6.1
VAD node @ 0xfffffa80058d9e00 Start 0x0000000003280000 End 0x000000000337ffff Tag VadS
Flags: CommitCharge: 4, PrivateMemory: 1, Protection: 4
Protection: PAGE_READWRITE
Vad Type: VadNone

VAD node @ 0xfffffa80052652b0 Start 0x00000000033c0000 End 0x00000000033dffff Tag VadS
Flags: CommitCharge: 32, PrivateMemory: 1, Protection: 24
Protection: PAGE_NOACCESS
Vad Type: VadNone

VAD node @ 0xfffffa8003f416d0 Start 0x00000000033a0000 End 0x00000000033bffff Tag VadS
```

---
<p style="color: cian;">12. Había un script VBS que se ejecutaba en la máquina. ¿Cuál es el nombre del script? (enviar sin extensión de archivo)</p>



Aplicamos el siguiente comando para obtener comandos ejecutados: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ python2 vol.py --profile=Win7SP1x64 -f  /home/kali/blue-labs/volatility3/labs/temp_extract_dir/Triage-Memory.mem cmdline > cmdline
Volatility Foundation Volatility Framework 2.6.1


┌──(venv)─(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ grep -i vbs -C 2 cmdline                                        
************************************************************************
wscript.exe pid:   5116
Command line : "C:\Windows\System32\wscript.exe" //B //NOLOGO %TEMP%\vhjReUDEuumrX.vbs
************************************************************************
UWkpjFjDzM.exe pid:   3496
```

---
<p style="color: cian;">13. Se ejecutó una aplicación en 2019-03-07 23:06:58 UTC. ¿Cuál es el nombre del programa? (Incluir extensión)</p>


### ¿Qué es el **ShimCache**?

El **ShimCache** (también llamado **Application Compatibility Cache**) es una característica del sistema operativo Windows que fue originalmente diseñada para **compatibilidad de aplicaciones**.
Pero en análisis forense, se usa frecuentemente porque deja rastros de programas ejecutados en el sistema.

### ¿Cómo funciona?

Cada vez que un ejecutable se **ejecuta** (o en algunos casos, cuando simplemente se accede), Windows registra información sobre ese ejecutable en una clave del **registro**:

* Ruta completa del ejecutable (ej. `C:\Program Files\Malware\evil.exe`)
* Fecha y hora de la última modificación del archivo (NO de ejecución directamente)
* Información de compatibilidad (si se aplicaron "shims" o parches para que la app funcione)

**Importante:**
El **ShimCache no garantiza que el ejecutable fue ejecutado realmente**, solo que fue **accedido** o **cargado lo suficiente** como para que Windows lo registre.
Pero en la práctica, es útil para ver qué archivos *probablemente fueron ejecutados*.

El plugin `cachedump` de Volatility analiza la clave del registro donde vive el ShimCache y muestra la lista de ejecutables registrados, incluyendo sus **timestamps**.

> "An application was run at 2019–03–07 23:06:58 UTC. What is the name of the program?"

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ grep "python2 vol.py --profile=Win7SP1x64 -f  /home/kali/blue-labs/volatility3/labs/temp_extract_dir/Triage-Memory.mem shimcache" shimcache

┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility3/labs/temp_extract_dir]
└─$ grep "2019-03-07" shimcache
247     2019-03-07 23:06:58.000000 UTC  N/A     True    N/A     \??\C:\Program Files (x86)\Microsoft\Skype for Desktop\Skype.exe
```

---
<p style="color: cian;">14. ¿Qué se escribió en notepad.exe en el momento en que se capturó el volcado de memoria?</p>

Ya conocemos el PID del notepad.exe: `3032`, hay que dumpear el proceso:
```bash
┌──(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ python2 vol.py --profile=Win7SP1x64 -f  /home/kali/blue-labs/volatility3/labs/temp_extract_dir/Triage-Memory.mem  memdump -p3032 --dump-dir .
```

Aplicamos un filtro: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ strings -e l 3032.dmp| grep -i "flag<"
flag<REDBULL_IS_LIFE>
```

---
<p style="">15. ¿Cuál es el nombre abreviado del archivo en el registro 59045?</p>

Para esto tenemos que exportar el contenido del `mft`, lo podemos hacer con el siguiente comando: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ python2 vol.py --profile=Win7SP1x64 -f  /home/kali/blue-labs/volatility3/labs/temp_extract_dir/Triage-Memory.mem mftparser > mft.txt


┌──(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ grep "59045" -C 20 mft.txt

<SNIP>
***************************************************************************
***************************************************************************
MFT entry found at offset 0x2193d400
Attribute: In Use & File
Record Number: 59045
Link count: 2


$STANDARD_INFORMATION
Creation                       Modified                       MFT Altered                    Access Date                    Type
------------------------------ ------------------------------ ------------------------------ ------------------------------ ----
2019-03-17 06:50:07 UTC+0000 2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:42 UTC+0000   Archive

$FILE_NAME
Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
2019-03-17 06:50:07 UTC+0000 2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:42 UTC+0000   Users\Bob\DOCUME~1\EMPLOY~1\EMPLOY~1.XLS

$FILE_NAME
Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
2019-03-17 06:50:07 UTC+0000 2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:42 UTC+0000   Users\Bob\DOCUME~1\EMPLOY~1\EmployeeInformation.xlsx
<SNIP>
```

---
<p style="color: cian;">16. Esta caja fue explotada y está ejecutando meterpreter. ¿Cuál era el PID infectado?</p>

Ya conocemos el nombre del proceso malicioso, usémoslo para buscar en el `pstree`:

```bash 
┌──(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ python2 vol.py --profile=Win7SP1x64 -f  /home/kali/blue-labs/volatility3/labs/temp_extract_dir/Triage-Memory.mem  pstree > pstree
Volatility Foundation Volatility Framework 2.6.1
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/blue-labs/otro_vol/volatility]
└─$ grep "UWkpjFjDzM.exe" pstree 
... 0xfffffa8005a1d9e0:UWkpjFjDzM.exe                3496   5116      5    109 2019-03-22 05:35:33 UTC+0000
```


