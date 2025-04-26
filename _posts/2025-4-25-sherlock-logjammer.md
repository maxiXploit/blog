---
layout: single
title: Hack The Box Sherlock - LogJammer
excerpt: Anàlis forense de ficheros .evtx después de un ataque NTDS.dit dump.
date: 2025-4-25
classes: wide
categories:
   - sherlock-htb
   - DFRI
tags:
   - active directory
   - chainsaw
   - ntds.dit dump
   - forensics
   - bash
---

<style>
  @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');

  .post-wrapper {
    font-family: 'Roboto', sans-serif;
    color: #e0e0e0;
    padding: 1em;
    line-height: 1.7;
    font-size: 1rem;
  }

  .bold {
    font-weight: 700;
  }

  .highlight {
    color: #00ffd5; /* un cian brillante */
    font-weight: 500;
  }

  .outlined {
    color: transparent;
    -webkit-text-stroke: 0.6px #ffffff;
    font-weight: 300;
  }

  .subtle {
    color: #888;
    font-style: italic;
  }

  h1, h2, h3 {
    color: #ffffff;
    font-weight: 700;
  }

  a {
    color: #00aaff;
    text-decoration: none;
  }

  a:hover {
    text-decoration: underline;
  }
</style>


<div class="post-wrapper">

<h1>Sherlock - LogJammer</h1>

<h2>En este laboratorio estaremos trabajando con ficheros de eventos de windows(.evtx) para investigar la intrusión del usuario CyberJunky en nuestra red, y determinar que acciones maliciosas realizó</h2>

Se nos proporcionan 2 el siguiente contenido para este laboratorio: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/logjamer/Event-Logs]
└─$ ls -lt 
total 17748
-rw-rw-r-- 1 kali kali  2166784 Mar 27  2023  System.evtx
-rw-rw-r-- 1 kali kali 12652544 Mar 27  2023  Powershell-Operational.evtx
-rw-rw-r-- 1 kali kali  1118208 Mar 27  2023 'Windows Defender-Operational.evtx'
-rw-rw-r-- 1 kali kali  1118208 Mar 27  2023 'Windows Firewall-Firewall.evtx'
-rw-rw-r-- 1 kali kali  1118208 Mar 27  2023  Security.evtx
```

Tenemos varias opciones para trabajar con estos logs, en este caso estaremos usando **`Splunk`** para no perder la práctica, pero también podemos usar herramietnas como EvtxEcmd en conjunto con TImelineExplorer o Chainsaw para manejarlo todo desde la terminal y que se nos haga más cómodo. 

El primer paso es parsear los datos a formato json, podemos usar el siguiente comando para hacerlo en powershell:

```powershell
.\EvtxECmd.exe -d "C:\Ruta\datos\evtx" --json "C:\Ruta\Guardar\Resultad"
```

O bien con Chainsaw: 

```bash 
/opt/chainsaw/target/release/chainsaw dump *.evtx --jsonl > results.jsonl
```

Con esto ya podemos insertar los datos dentro de **Splunk**. 
La instalación de Splunk no es nada compleja, solo tenemos que registrarnos en su web con un **correo empresarial**, descargarnos la version gratuita, hacer click en el instalador, darle a `siguiente, siguiente, siguiente` y ya estaría instalado en Windows. En linux solo tenemos que hacer el `wget`  con el enlace que nos proporcionan en su página web. 

Una vez instalado ya podemos insertar los logs dentro de Splunk, primero tenemos que crear un índice en **`Setting>Indexes>New`** 

![](../assets/images/sherlock-logjammer/imagen1.png)

1. Para insertar los datos dentro del nuevo índice podemos ir a **`Add Data>Upload`** seleccionamos o arrastramos el fichero que parseamos posteriormente.
2. En `Set Source Type` elegimos `_json`. 
3. En **`Select Index`** elegimos el índice que creamos, en este caso **logjammer**.
4. Revisamos y hacemos **`submit`**

Esta es una forma de poner los registros dentro de Splunk, pero yo prefiero la terminal a veces. 

---
**task 1** 

¿Cuándo fue la primera vez que el usuario de cyberjunkie se conectó con éxito a su ordenador? (UTC)

Para esto simplemente podemos aplicar el siguiente comando con usando jq: 
```bash 
cat results.jsonl | jq '.Event | select(.System.EventID == 4624 and .EventData.TargetUserName == CyberJunkie)'
``` 
Tenemos que usar el timestamp del primer registro que devuelve el filtro. 


---
**task 2**

El usuario manipuló la configuración del cortafuegos del sistema. Analice los registros de eventos del cortafuegos para averiguar el Nombre de la regla de cortafuegos añadida?


El EventID 2004 proviene del log de eventos del Firewall Avanzado de Windows y significa:

> "A firewall rule has been changed."
> Específicamente, este evento indica que una regla fue activada/modificada (creada, activada, o aplicada por política), y suele registrar el contexto de esa regla.

Sabiendo esto podemos usar el siguietne comando: 

```bash 
cat results.jsonl | jq '.Event | select(.System.EventID == 2004) | .EventData.RuleName'
``` 

Con esto vamos a ver todos los nombres de las reglas de firewall, podemos exclir aquellas que contengan la palabra `microsoft` para tener una visualización mas sencilla: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/logjamer]
└─$ cat results.jsonl | jq '.Event | select(.System.EventID == 2004) | .EventData.RuleName' | sort | uniq | grep -ivE "microsoft|printer|discovery"
"@{1527c705-839a-4832-9118-54d4Bd6a0c89_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://FilePicker/Resources/AppxManifest_DisplayName}"
"ByteCodeGeneration"
"@{c5e2524a-ea46-4f67-841f-6a9465d9d515_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://FileExplorer/Resources/AppxManifest_DisplayName}"
"@{c5e2524a-ea46-4f67-841f-6a9465d9d515_10.0.19041.1949_neutral_neutral_cw5n1h2txyewy?ms-resource://FileExplorer/Resources/AppxManifest_DisplayName}"
"CapturePicker"
"Cloud Identity (TCP-Out)"
"Cortana"
"@{E2A4F912-2574-4A75-9BB0-0D023378592B_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://AppResolverUX/Resources/AppxManifest_DisplayName}"
"@{F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE/Resources/AppxManifest_DisplayName}"
"Firefox (C:\\Program Files\\Mozilla Firefox)"
"Inbound service restriction rule for WinDefend"
"Metasploit C2 Bypass"
"Office"
"OneNote"
"OneNote for Windows 10"
"Outbound service restriction rule for WinDefend"
"PinningConfirmationDialog"
"Python 3.10"
"Solitaire & Casual Games"
"WinDefend Outbound for TCP"
"@{Windows.CBSPreview_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.CBSPreview/resources/DisplayName}"
"windows_ie_ac_001"
"@{Windows.PrintDialog_6.2.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.PrintDialog/resources/DisplayName}"
"Xbox"
"Xbox Game Bar Plugin"
``` 

Con una salida más limpia ya podemos ver una que nos llama la atención, **metasploit**

---
**task 3**

El usuario manipuló la configuración del cortafuegos del sistema. Analice los registros de eventos del cortafuegos para averiguar el Nombre de la regla de cortafuegos añadida?

Para saber esto conozcamos un poco mas de los campos de los logs del firewall: 


| Campo (JSON)           | Significado                                    | Ejemplo / Valor |
|------------------------|------------------------------------------------|-----------------|
| `RuleName`             | Nombre de la regla                             | Metasploit C2 Bypass |
| `Direction`            | Dirección del tráfico                          | `1` = Inbound<br>`2` = Outbound |
| `Action`               | Qué hace la regla                              | `0` = Block<br>`1` = Allow<br>`2` = Bypass<br>`3` = Max (para compatibilidad, generalmente Allow) |
| `Protocol`             | Protocolo                                       | `6` = TCP<br>`17` = UDP<br>`1` = ICMP |
| `LocalPorts`           | Puerto(s) local(es) involucrados               | `"*"` = todos |
| `RemotePorts`          | Puerto(s) remotos involucrados                 | `"4444"` |
| `ApplicationPath`      | Ruta de la aplicación                          | `"C:\\Windows\\System32\\mmc.exe"` (u otra app) |
| `ModifyingUser`        | SID del usuario que creó/modificó la regla     | SID (puedes resolverlo si lo necesitas) |
| `ModifyingApplication` | Aplicación que creó/modificó la regla          | `"C:\\Windows\\System32\\mmc.exe"` |
| `Active`               | ¿Está activa la regla?                         | `1` = Sí, `0` = No |


Así que ya podemos fijarnos en el campo `Direction` del log proporcionado en la pregunta anterior, que está con el valor **`2`**.

---
**task 4**

El usuario ha cambiado la política de auditoría del ordenador. ¿Cuál es la subcategoría de esta política modificada?


System audit policy was changed significa que alguien modificó la política de auditoría del sistema, lo cual puede usarse para ocultar huellas (por ejemplo, desactivando logs de ciertos eventos) o simplemente para ganar persistencia.

El Event Id para este evento es el **`4719`** 

Aplicamos el siguiente filtro:

```bash
┌──(kali㉿kali)-[~/blue-labs/DFIR/logjamer]
└─$ cat results.jsonl | jq '.Event | select(.System.EventID == 4719)'                                                   
{
  "System": {
    "Provider_attributes": {
      "Name": "Microsoft-Windows-Security-Auditing",
      "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D"
    },
    "EventID": 4719,
    "Version": 0,
    "Level": 0,
    "Task": 13568,
    "Opcode": 0,
    "Keywords": "0x8020000000000000",
    "TimeCreated_attributes": {
      "SystemTime": "2023-03-27T14:50:03.721835Z"
    },
    "EventRecordID": 13102,
    "Correlation_attributes": {
      "ActivityID": "986A053F-60B9-0002-5B05-6A98B960D901"
    },
    "Execution_attributes": {
      "ProcessID": 780,
      "ThreadID": 1488
    },
    "Channel": "Security",
    "Computer": "DESKTOP-887GK2L",
    "Security": null
  },
  "EventData": {
    "SubjectUserSid": "S-1-5-18",
    "SubjectUserName": "DESKTOP-887GK2L$",
    "SubjectDomainName": "WORKGROUP",
    "SubjectLogonId": "0x3e7",
    "CategoryId": "%%8274",
    "SubcategoryId": "%%12804",
    "SubcategoryGuid": "0CCE9227-69AE-11D9-BED3-505054503030",
    "AuditPolicyChanges": "%%8449"
  }
}
``` 

Los campos como CategoryId, SubcategoryId, y AuditPolicyChanges aparecen con valores tipo %%8274, %%12804, %%8449, etc.
Eso es porque los logs los representan con identificadores de recursos de texto (placeholders que Windows traduce en la interfaz de visor de eventos).

Para convertirlos, necesitas una tabla de referencia que traduzca esos códigos al texto legible.
Podemos buscar en internet y ver que se trata de "Other Object Access Events".

**"Other Object Access Events"** es una **subcategoría** de auditoría en Windows que se refiere a eventos de acceso a **objetos** que **no caen** en otras categorías más específicas.

- Un **objeto** en Windows no solo es un archivo o carpeta, también puede ser:
  - **Mutexes** (bloqueos de acceso)
  - **Pipes** (canales de comunicación)
  - **Jobs** (colecciones de procesos)
  - **Sections** (áreas de memoria compartida)
  - **Tokens de seguridad** (credenciales de acceso)
  - **Drivers**
  - **Dispositivos virtuales**
  - Etc.

En resumen:
> Son eventos que involucran **acceso a recursos del sistema** menos comunes que archivos, registros, impresoras, etc.

###  ¿Qué eventos se auditan aquí?

Cuando se habilita la auditoría de **Other Object Access Events**, se pueden registrar cosas como:

- Acceso a objetos de **memoria compartida**.
- Uso de **pipes nombrados** para comunicaciones interprocesos (IPC).
- Intentos de abrir objetos del **kernel** (como eventos o semáforos).
- Acceso a **objetos creados por servicios** o **por malware** (como pipes de C2).

Estos accesos son muy importantes en **análisis de malware**, **movimientos laterales** y **persistencia** 🔥.

- Muchas técnicas avanzadas de ataques usan **objetos raros** en lugar de archivos visibles.
- Malware, C2 frameworks (tipo Cobalt Strike, Metasploit, Sliver) usan **pipes** para comunicación sigilosa.
- Herramientas de pentest legítimas también hacen uso de objetos "no normales".

---
**task 5**

El usuario "cyberjunkie" ha creado una tarea programada. ¿Cuál es el nombre de esta tarea?

Para esto podemos usar el siguiente EventID. 


###** Event ID 4698?**

- **Event ID 4698** es un evento de **Security.evtx**.
- Indica que **se creó una nueva tarea programada**.
- Registro: **Security** (no el de TaskScheduler normal).
- Solo se genera **si está activado** el **auditing de "Object Access"** y configurada la política adecuada ("Audit Other Object Access Events" > Success).
  
  > "a veces no aparece"**: si no está bien configurado el auditing de seguridad en la máquina Windows, no se registra el 4698, aunque la tarea exista.

**En resumen**:  
4698 = Creación de tarea programada, en el registro de **Security**, con buena información de quién la creó, pero depende de configuración de auditoría.

### **¿Qué es el Event ID 4104?**

- **Event ID 4104** es de **Microsoft-Windows-PowerShell/Operational**.
- Indica **"Execution of PowerShell script block"**, o sea:
  - Cuando PowerShell **ejecuta bloques de código** (scripts, comandos).
  - Es súper útil para ver **comandos maliciosos** o **payloads** lanzados por Powershell.
- El contenido del script o comando ejecutado suele estar en el campo `"ScriptBlockText"`.


| Event ID  | ¿Qué indica? |
|-----------|--------------|
| 4698      | Tarea programada creada (Security) |
| 106       | Tarea registrada (TaskScheduler) |
| 4104      | PowerShell ejecutó un script |

Sabiendo esto aplicamos el sigiente filtro: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/logjamer]
└─$ cat results.jsonl | jq '.Event | select(.System.EventID == 4698)'                      
    <SNIP>
    
    "TaskContent": "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n  <RegistrationInfo>\r\n    <Date>2023-03-27T07:51:21.4599985</Date>\r\n    <Author>DESKTOP-887GK2L\\CyberJunkie</Author>\r\n    <Description>practice</Description>\r\n    <URI>\\HTB-AUTOMATION</URI>\r\n  </RegistrationInfo>\r\n  <Triggers>\r\n    <CalendarTrigger>\r\n      <StartBoundary>2023-03-27T09:00:00</StartBoundary>\r\n      <Enabled>true</Enabled>\r\n      <ScheduleByDay>\r\n        <DaysInterval>1</DaysInterval>\r\n      </ScheduleByDay>\r\n    </CalendarTrigger>\r\n  </Triggers>\r\n  <Principals>\r\n    <Principal id=\"Author\">\r\n      <RunLevel>LeastPrivilege</RunLevel>\r\n      <UserId>DESKTOP-887GK2L\\CyberJunkie</UserId>\r\n      <LogonType>InteractiveToken</LogonType>\r\n    </Principal>\r\n  </Principals>\r\n  <Settings>\r\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\r\n    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\r\n    <AllowHardTerminate>true</AllowHardTerminate>\r\n    <StartWhenAvailable>false</StartWhenAvailable>\r\n    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n    <IdleSettings>\r\n      <Duration>PT10M</Duration>\r\n      <WaitTimeout>PT1H</WaitTimeout>\r\n      <StopOnIdleEnd>true</StopOnIdleEnd>\r\n      <RestartOnIdle>false</RestartOnIdle>\r\n    </IdleSettings>\r\n    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n    <Enabled>true</Enabled>\r\n    <Hidden>false</Hidden>\r\n    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n    <WakeToRun>false</WakeToRun>\r\n    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>\r\n    <Priority>7</Priority>\r\n  </Settings>\r\n  <Actions Context=\"Author\">\r\n    <Exec>\r\n      <Command>C:\\Users\\CyberJunkie\\Desktop\\Automation-HTB.ps1</Command>\r\n      <Arguments>-A cyberjunkie@hackthebox.eu</Arguments>\r\n    </Exec>\r\n  </Actions>\r\n</Task>",                                                             
``` 

---
**task 6**

¿Cuál es la ruta completa del archivo programado para la tarea?

Esto podemos verlo en la porción del log proporcionado: C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1

---
**task 7**

¿Cuales son los argumentos del comando?

Esto también lo encontramos en el `taskcontent` proporcionado en la pregunta 5: `<Arguments>-A cyberjunkie@hackthebox.eu</Arguments>`
    



--- 
**task 8


```bash 
cat results.jsonl | jq '.Event | select(.System.Provider_attributes.Name == Microsoft-Windows-Windows Defender)' 
```

Vemos que se lanza el Event ID 1117 – Task Scheduler:
- Registro: Microsoft-Windows-TaskScheduler/Operational
  Significado:
  "Task triggered by event", o sea: una tarea programada se disparó porque ocurrió un evento específico (y no simplemente porque era la hora programada).

1. El Event ID 1117 dice que se disparó una tarea en respuesta a un evento.
2. El evento que la disparó proviene del proveedor Windows Defender.

Analizando la información del registro vemos que contiene una referencia **`sharphound`**, es la herramienta que usa BloodHound para recolectar información del Active Directory.

```json
"Path": "containerfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip; file:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip->SharpHound.exe; webfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230327%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230327T144228Z&X-Amz-Expires=300&X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=385323486&response-content-disposition=attachment%3B%20filename%3DSharpHound-v1.1.0.zip&response-content-type=application%2Foctet-stream|pid:3532,ProcessStart:133244017530289775",
``` 

---
**task 9** 

¿Cual es la ruta completa del malware que activó la alerta?

Esto podemos verlo en el fragmento del registro proporcionado en la pregunta anterior: 

```bash 
C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip
``` 


---
**task 10**

¿Qué acción fue tomada por el antivirus?

A continuación se muestra un fragmento del log que muestra campos importantes: 

```bash 
"Severity ID": "4",
    "Severity Name": "High",
    "Category ID": "34",
    "Category Name": "Tool",
    "FWLink": "https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:MSIL/SharpHound!MSR&threatid=2147814944&enterprise=0",
    "Status Code": "103",
    "Status Description": "",
    "State": "2",
    "Source ID": "4",
    "Source Name": "Downloads and attachments",
    "Process Name": "Unknown",
    "Detection User": "DESKTOP-887GK2L\\CyberJunkie",
    "Unused3": "",
    "Path": "containerfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip; file:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip->SharpHound.exe; webfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230327%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230327T144228Z&X-Amz-Expires=300&X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=385323486&response-content-disposition=attachment%3B%20filename%3DSharpHound-v1.1.0.zip&response-content-type=application%2Foctet-stream|pid:3532,ProcessStart:133244017530289775",                                                                                                                    
    "Origin ID": "4",
    "Origin Name": "Internet",
    "Execution ID": "0",
    "Execution Name": "Unknown",
    "Type ID": "0",
    "Type Name": "Concrete",
    "Pre Execution Status": "0",
    "Action ID": "2",
    "Action Name": "Quarantine",
    "Unused4": "",
    "Error Code": "0x80508023",
    "Error Description": "The program could not find the malware and other potentially unwanted software on this device.",
    "Unused5": "",
    "Post Clean Status": "0",
    "Additional Actions ID": "0",
    "Additional Actions String": "No additional actions required",
    "Remediation User": "NT AUTHORITY\\SYSTEM",
    "Unused6": "",
    "Security intelligence Version": "AV: 1.385.1261.0, AS: 1.385.1261.0, NIS: 1.385.1261.0",
    "Engine Version": "AM: 1.1.20100.6, NIS: 1.1.20100.6"
  }
}
``` 

Tablas de valores de **Defender Logs**

###  **Severity ID** (Nivel de severidad)


| Severity ID | Severity Name | Significado |
|-------------|---------------|-------------|
| 0 | Informational | Información, no es amenaza. |
| 1 | Low | Riesgo bajo. |
| 2 | Moderate | Riesgo moderado. |
| 4 | High | Riesgo alto. |
| 5 | Severe | Crítico, amenaza grave. |

### ⚡ **Action ID** (Acción tomada)


| Action ID | Action Name | Significado |
|-----------|-------------|-------------|
| 1 | Clean | Se intentó limpiar el archivo. |
| 2 | Quarantine | Se movió el archivo a cuarentena. |
| 3 | Remove | Se eliminó el archivo. |
| 6 | Allow | Se permitió la acción (excepción). |
| 8 | User Defined | El usuario definió qué hacer. |
| 9 | Block | Se bloqueó la ejecución. |

### **Status Code (Código de estado de remediación)**

| State | Significado |
|-------|-------------|
| 0 | Detectada pero no ejecutada. |
| 1 | Detectada y ejecutada. |
| 2 | Detectada durante el acceso (por ejemplo, al descargar o abrir). |
| 3 | Remediada (limpiada o eliminada). |
| 4 | Remediación fallida. |
| 5 | En cuarentena. |


### **Status Code** (Código de estado de remediación)


| Status Code | Significado |
|-------------|-------------|
| 0 | Sin problemas / Completado exitosamente. |
| 1xx | Remediación exitosa (varios tipos). |
| 2xx | Remediación fallida (depende del error). |
| 103 | Específicamente: **Malware detectado y puesto en cuarentena.**  |


En este caso, fue puesto en cuarentena. 

---
**task 10**

El usuario utilizó Powershell para ejecutar comandos. Qué comando ejecutó el usuario?

Para esto podemos ejecutar el siguiente comando: 

```bash
cat results.jsonl | jq '.Event | select(.System.Provider_attributes.Name == Microsoft-Windows-PowerShell)'  | less
``` 

Vemos bastantes, pero el que nos interesa es el que tiene el siguiente contenido: 

```json
"ContextInfo": "        Severity = Informational\r\n        Host Name = ConsoleHost\r\n        Host Version = 5.1.19041.2673\r\n        Host ID = 014a1fde-4c3a-4658-9521-5933850cff3e\r\n        Host Application = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\n        Engine Version = 5.1.19041.2673\r\n        Runspace ID = d2a1cce6-8566-442d-a53b-d92bd22fa362\r\n        Pipeline ID = 11\r\n        Command Name = Get-FileHash\r\n        Command Type = Function\r\n        Script Name = \r\n        Command Path = \r\n        Sequence Number = 32\r\n        User = DESKTOP-887GK2L\\CyberJunkie\r\n        Connected User = \r\n        Shell ID = Microsoft.PowerShell",                                                                
    "UserData": "",
    "Payload": "CommandInvocation(Get-FileHash): \"Get-FileHash\"\r\nParameterBinding(Get-FileHash): name=\"Algorithm\"; value=\"md5\"\r\nParameterBinding(Get-FileHash): name=\"Path\"; value=\".\\Desktop\\Automation-HTB.ps1\""
``` 

Esto corresponde al comando **`Get-FileHash -Algorithm md5 -Path .\Desktop\Automation-HTB.ps1`**

---
**task 11**

Sospechamos que el usuario borró algunos registros de eventos. ¿Qué archivo de registro de eventos se borró?


Para esto podemos usar el siguiente comando: 

```bash 
cat results.jsonl | jq '.Event | select(.System.EventID == 104)' 
``` 

Nos interesa el ultimo log que nos muestra: 

```json
  "UserData": {
    "LogFileCleared_attributes": {
      "xmlns": "http://manifests.microsoft.com/win/2004/08/windows/eventlog"
    },
    "LogFileCleared": {
      "SubjectUserName": "CyberJunkie",
      "SubjectDomainName": "DESKTOP-887GK2L",
      "Channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
      "BackupPath": ""
    }
  }
``` 
El campo Channel en los eventos de Windows indica de qué fuente o de qué "registro de eventos" (event log) estamos hablando.
Cada "Channel" es un tipo diferente de registro en el sistema.

Cuando alguien borra eventos, Windows registra en el Security Log (si el auditoría está activada) cuál Channel fue limpiado.

Así que:
> La información en Channel te dice exactamente qué log fue eliminado.

**El usuario CyberJunkie limpió el log:**
**Microsoft-Windows-Windows Firewall With Advanced Security/Firewall**

</div>
