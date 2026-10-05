
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

Nuestro fichero es

```bash
#GUID="EDF674A6-F930-65F1-4C02-000000001200"

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

---------------

What registry path and value was used by the above EXE to gain higher privileges? (path\value)

****:\********\*******\**-********\*****\****\*******\********

Submit Task
Task 3

Hint
The attacker dropped a file. What is the file location?

*:\*****\****\*********\********.***

Submit Task
Task 4

Hint
What are the technique name and ID used by the dropped EXE?

********** *******: *****

Submit Task
Task 5

Hint
What is the name of the attack?

**** *** ****

Submit Task
Task 6

Hint
What EXE did the attacker run using elevated privileges from the above attack?

**********.***

Submit Task
Task 7

Hint
The attacker downloaded and ran a file. What is the filename?

