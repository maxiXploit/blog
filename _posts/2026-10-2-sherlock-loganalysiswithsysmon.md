
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

Para empezar la investigación empezamos por revisar los eventos de más alta señal(**8, 3, 12**)

Con el `CreateRemoteThread (Event ID 8)`, un `StartModule` puede indicar código inyectado que no pertenece a ninguna DLL:

```bash
jq '.Event | select(.System.EventID == 8) | .EventData | {UtcTime, SourceImage, TargetImage, StartModule}' events_sysmon.jsonl | sort | uniq -c | sort -rn


```

Tenemos lo siguiente:

- `<unknown process>` → `CompatTelRunner.exe`, con `KERNELBASE.dll!CtrlRoutine` es el manejador del Ctrl+C de Windows:
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
    
    El `CtrlRoutine` que vemos es `KERNELBASE.dll!CtrlRoutine`





Submit Task
Task 1

Hint
What did the attacker use to bypass UAC? Mention the EXE.

*********.***

Submit Task
Task 2

Hint
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

