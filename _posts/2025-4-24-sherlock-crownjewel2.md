---
layout: single
title: Hack The Box Sherlock - CrownJewel2
excerpt: Una continuación del laboratorio CrownJewel1.
date: 2025-4-24
classes: wide
headers: 
   - ../assets/images/sherlock-compromised/compromised.webp
categories:
   - sherlock-htb
   - dfri
tags:
   - active directory
   - forensics
   - bash
   - chainsaw
---

**CrownJewel2 - Hack The Box**


Este laboratori es la continuación del CrownJewel1, por lo que también estaremos analizando ficheros **`.evtx`** de lo que fue un ataque de NTDS.dit dump. 

También estaremos usando chainsaw para parsear los registros de eventos en windows a un formato más json, el tutorial de como instalar chainsaw esta en la [primera parte](primeraparte), así que ya podemos pasar rápidamente al laboratorio a responder las preguntas. 

Otra herramienta muy ineresante en [Hayabusa](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#git-cloning) para una vista general de los logs antes de pasar a investigar en profundidad en los logs de un entorno real. 

---

Al igual que en la primera parte, primero vamos a ejecutar el siguiente comando para dar una vista general de que es a lo que nos vamos a enfrentar: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/crownjewel2/Artifacts]
└─$ /opt/chainsaw/target/release/chainsaw hunt *.evtx --sigma /opt/chainsaw/sigma --mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml
``` 

![](../images/assets/sherlock-cj2/imagen21.png)

Vemos que Chainsaw ya nos reporta un `Volume Shadow Copy Mount`, que es de lo que trata este laboratorio, así que pasemos a fomato json los ficheros `.evtx`: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/crownjewel2/Artifacts]
└─$ /opt/chainsaw/target/release/chainsaw dump *.evtx --json > ../events.json

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: APPLICATION.evtx, SECURITY.evtx, SYSTEM.evtx (extensions: *)
[+] Loaded 3 forensic artefacts (3.2 MiB)
[+] Done
```

Tambièn podemos usar el formato jsonl, que nos da un formato más amigable para trabajar con scripts

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/crownjewel2/Artifacts]
└─$ /opt/chainsaw/target/release/chainsaw dump --jsonl *.evtx > ../events.jsonl

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: APPLICATION.evtx, SECURITY.evtx, SYSTEM.evtx (extensions: *)
[+] Loaded 3 forensic artefacts (3.2 MiB)
[+] Done
``` 

---
**task 1** 

Cuando se utiliza ntdsutil.exe para dumpear el  NTDS.dit  en el disco, se emplea simultáneamente el servicio Microsoft Shadow Copy Service. ¿Cuál es la marca de tiempo más reciente en la que este servicio entró en estado de ejecución, lo que significa el posible inicio del proceso de volcado del NTDS?


Ya sabemo que el evento 7036 en el canal de System para los EventsID de windows ndica que un servicio del sistema ha cambiado de estado. Los estados típicos son:
- running (ejecutándose)
- stopped (detenido)
- paused
- start pending
- stop pending: 

Así que aplicamos el siguiente filtro para que muestro solo aquellos que están con el estado 'Runnin':

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/crownjewel2]
└─$ cat events.jsonl | jq '.Event | select(.System.Channel =="System" and .System.EventID == 7036 and .EventData.param2 == "running")' -c | grep -i volume | jq .
{
  "System": {
    "Provider_attributes": {
      "Name": "Service Control Manager",
      "Guid": "{555908d1-a6d7-4695-8e1e-26931d2012f4}",
      "EventSourceName": "Service Control Manager"
    },
    "EventID_attributes": {
      "Qualifiers": 16384
    },
    "EventID": 7036,
    "Version": 0,
    "Level": 4,
    "Task": 0,
    "Opcode": 0,
    "Keywords": "0x8080000000000000",
    "TimeCreated_attributes": {
      "SystemTime": "2024-05-15T05:35:29.636707Z"
    },
    "EventRecordID": 3062,
    "Correlation": null,
    "Execution_attributes": {
      "ProcessID": 744,
      "ThreadID": 856
    },
    "Channel": "System",
    "Computer": "DC01.forela.local",
    "Security": null
  },
  "EventData": {
    "param1": "Volume Shadow Copy",
    "param2": "running",
    "Binary": "5600530053002F0034000000"
  }
}
{
  "System": {
    "Provider_attributes": {
      "Name": "Service Control Manager",
      "Guid": "{555908d1-a6d7-4695-8e1e-26931d2012f4}",
      "EventSourceName": "Service Control Manager"
    },
    "EventID_attributes": {
      "Qualifiers": 16384
    },
    "EventID": 7036,
    "Version": 0,
    "Level": 4,
    "Task": 0,
    "Opcode": 0,
    "Keywords": "0x8080000000000000",
    "TimeCreated_attributes": {
      "SystemTime": "2024-05-15T05:39:55.580378Z"
    },
    "EventRecordID": 3129,
    "Correlation": null,
    "Execution_attributes": {
      "ProcessID": 744,
      "ThreadID": 2664
    },
    "Channel": "System",
    "Computer": "DC01.forela.local",
    "Security": null
  },
  "EventData": {
    "param1": "Volume Shadow Copy",
    "param2": "running",
    "Binary": "5600530053002F0034000000"
  }
}
``` 

**Obtenemos 2 logs, pero nos piden el màs reciente, así que tomamos el timestamp del último**

---
**task 2** 


Identifique la ruta completa del archivo NTDS volcado.

Para esto podemos aplicar el siguiente filtro, y como ya sabemos, vamos a tomar aquella ruta que no esté dentro de rutas donde normalemtne se guardaría un backup del **NTDS.dit** dentro del sistema: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/crownjewel2]
└─$ cat events.jsonl | jq . | grep -i "ntds\.dit"
        "C:\\Windows\\NTDS\\ntds.dit",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit"
        "C:\\Windows\\NTDS\\ntds.dit",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit"
        "C:\\Windows\\NTDS\\ntds.dit",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit"
        "C:\\Windows\\NTDS\\ntds.dit",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit"
        "C:\\Windows\\NTDS\\ntds.dit",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit"
        "C:\\Windows\\NTDS\\ntds.dit",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit"
        "C:\\Windows\\NTDS\\ntds.dit",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit"
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit",
        "C:\\$SNAP_202405151039_VOLUMEC$\\Windows\\NTDS\\ntds.dit",
        "C:\\Windows\\Temp\\dump_tmp\\Active Directory\\ntds.dit",
        "C:\\Windows\\Temp\\dump_tmp\\Active Directory\\ntds.dit",
        "C:\\Windows\\Temp\\dump_tmp\\Active Directory\\ntds.dit",
        "C:\\$SNAP_202405151039_VOLUMEC$\\Windows\\NTDS\\ntds.dit",
``` 

---
**task 3**

Para esto podemos usar el siguiente comando para identificar registros que tengan `ntds.dit` en su contenido: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/crownjewel2]
└─$ cat events.jsonl | jq '.Event | select(.System.Channel == "Application") |  select(.EventData.Data[]? | contains("ntds.dit"))
```
**Y debemos fijarnos en la primara marca de tiempo que tenga como ruta C:\\Windows\\Temp\\dump_tmp\\Active Directory\\ntds.dit**.

---
**task 4**

¿Cuándo se consideró que la base de datos recién volcada estaba completa y lista para su uso?

Esto es más sencillo, solo tenemos que poner el la marca de tiempo del último registro que contenga a C:\\Windows\\Temp\\dump_tmp\\Active Directory\\ntds.dit como ruta. El timestamp anterior fue de cuando se creó, que fue el primero, al último es cuando terminó de crearse, que corresponde al último. 

---
**task 5**

La respuesta se puede encontrar en el log proporcionado en la pregunta 3, en este campo en específico: 

```json
"System": {
    "Provider_attributes": {
      "Name": "ESENT"
    },
```

ESENT significa Extensible Storage Engine (ESE), también conocido como JET Blue.

Es una base de datos embebida que usa Windows internamente para varias funciones, como:

- Active Directory (la base de datos ntds.dit justamente usa ESENT).
- Windows Search.
- Windows Update.
- Certificados, WSUS, y más.

Cuando el sistema realiza operaciones sobre bases de datos que usan ESENT (como crear, adjuntar, desmontar o leer bases de datos), los logs se generan bajo el origen de eventos ESENT en el canal de Application.


---
**task 6**


Para esto podemos aplicar el siguiente filtro, que ya sabemos que el EventID 4799 se produce antes de realizar operaciones sensibles(como crear una instantánea de volumen), entonces  el servicio VSS valida los permisos de la cuenta que ejecuta la acción, que puede ser la cuenta de equipo (MACHINE$).

```bash
┌──(kali㉿kali)-[~/blue-labs/DFIR/crownjewel2]
└─$ cat events.jsonl | jq '.Event | select(.System.EventID == 4799) | select(.EventData.CallerProcessName == "C:\\Windows\\System32\\VSSVC.exe") |  .EventData.TargetUserName' | sort | uniq
"Administrators"
"Backup Operators"
```

---
**task 7**

Ahora debe encontrar la hora de inicio de sesión de la sesión maliciosa. Usando el identificador de inicio de sesión, encuentre la hora a la que comenzó la sesión de inicio de sesión del usuario.

4768 – Kerberos Authentication Ticket (TGT) was requested
- Es cuando un usuario solicita un Ticket Granting Ticket (TGT) para autenticarse.
4769 – Kerberos Service Ticket was requested
- Esto ocurre cuando un usuario ya autenticado con un TGT solicita un ticket para un servicio específico.
5379 – Credential Manager credentials were read
- Indica que una app/proceso leyó credenciales almacenadas. No siempre es relevante para la actividad de un atacante (muchas veces es ruido).

En resumen:
- El usuario solicita su TGT → 4768
- Luego solicita acceso a un servicio con un TGS → 4769
- Finalmente, el sistema registra el uso de la credencial protegida → 5379
- Todo esto ocurre en cadena, casi al mismo tiempo.

Así que apliquemos el siguiente filtro para fijarnos unicamente en este tipo de eventos: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/crownjewel2]
└─$ cat events.jsonl | jq '.Event  | select(.System.EventID == 4768 or .System.EventID == 4769 or .System.EventID == 5379 and .EventData.SubjectUserName != "DC01$")' 
``` 

El `.EventData.SubjectUserName != "DC01$"` para acotar aún más los resultados,ya que Los eventos donde TargetUserName es DC01$ o DC01$@FORELA.LOCAL son comunicaciones normales del controlador de dominio — se generan automáticamente y no suelen estar relacionados con usuarios humanos o acciones maliciosas directas.

Una vez obteniendo el resultado tenemos que buscar el primer registro con `TargetUserName: "administrator"`. Esto indica que se solicitó un TGT para el usuario administrator, lo cual no es algo que pase por defecto si nadie está iniciando sesión como ese usuario. Si estás haciendo un ataque tipo Pass-the-TGT o Golden Ticket, este evento se genera justo cuando el ticket se usa por primera vez.

Esto significa que un usuario de alto privilegio (como administrator) solicitando autenticación Kerberos. Si estás buscando un momento en que un atacante se autenticó usando un ticket forjado (por ejemplo, un TGT generado con hash de krbtgt). 

**Básicamente, el inicio de la sesion malicionsa**


