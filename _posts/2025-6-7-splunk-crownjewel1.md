---
layout: single
title: Sherlock CrownJewel1 resuelto con splunk
excerpt: Analizamos con splunk registros de seguridad de windows sobre lo que parece un NTDS dumpping attack.
date: 2025-6-7
classes: wide
header:
   teaser: ../assets/images/forwa
   teaser_home_page: true
   icon: ../assets/images/splunk-logo.jpg
categories:
   - splunk
   - windows
   - hack the box 
   - sherlock 
   - active directory
   - DFIR
tags:
   - .evtx
   - evtxecmd
   - splunk
---

Primeramente parseamos los datos a un formato json usando `evtxcmd`:

```powershell
.\EvtxECmd.exe -d "C:\Ruta\a\logjammer\Event-Logs\"  --json "C:\Ruta\salida\events.json"
```

Creamos un nuevo índice en splunk, añadimos los datos y seleccionamos el índice que acabamos para crear para estos datos, en mi caso lo nombré `crownjewel1`. Con esto podemos rápidamente a las preguntas. 

----

<h3 style="color: #9FEF00;">Task 1. Attackers can abuse the vssadmin utility to create volume shadow snapshots and then extract sensitive files like NTDS.dit to bypass security mechanisms. Identify the time when the Volume Shadow Copy service entered a running state. </h3>

El Volume Shadow Copy Service (VSS) es un servicio de Windows que permite crear “instantáneas” (snapshots) en caliente de uno o varios volúmenes del disco. Estas instantáneas contienen un punto en el tiempo del sistema de archivos, de modo que, aun si los archivos están en uso, se puede generar una copia consistente para realizar copias de seguridad, restauraciones, etc.

El servicio se llama en Windows “Volume Shadow Copy” (en el registro de Servicios, normalmente aparece como VSS o “VolSnap”).

Cuando este servicio está en ejecución (running), el sistema ya acepta solicitudes de creación de shadow copies.

Un atacante con privilegios suficientemente altos (por ejemplo, SYSTEM o un usuario con derechos de backup) podría ejecutar:

```powershell
vssadmin create shadow /for=C:
```
para crear una snapshot del volumen C:.

Luego, desde esa snapshot, si se ubica el archivo `:\Windows\NTDS\NTDS.dit`

Entonces, podemos aplicar el siguiente filtro en splunk: 

`index="crownjewel1" EventId=7036 "shadow copy"`

> El eventid 7036 es el mensaje literal que indica que el servicio pasó a “running”. Este evento es generado por el Service Control Manager (SCM).

Esto va a retornar un solo registro: 

```json
{ [-]
   Channel: System
   ChunkNumber: 0
   Computer: DC01.forela.local
   EventId: 7036
   EventRecordId: 2984
   ExtraDataOffset: 0
   HiddenRecord: false
   Keywords: Audit success, classic
   Level: Info
   MapDescription: Service started or stopped
   Payload: {"EventData":{"Data":[{"@Name":"param1","#text":"Volume Shadow Copy"},{"@Name":"param2","#text":"running"}],"Binary":"56-00-53-00-53-00-2F-00-34-00-00-00"}}
   PayloadData1: Name: Volume Shadow Copy | Volume Shadow Copy
   PayloadData2: Status: running
   ProcessId: 784
   Provider: Service Control Manager
   RecordNumber: 135
   SourceFile: C:\Users\Lenovo\Downloads\compartida\compartida\jewel1\SYSTEM.evtx
   ThreadId: 916
   TimeCreated: 2024-05-14T03:42:16.7831058+00:00
}
```

Importante fijarnos en el `param2`, que está en estado activo(running), que es lo que nos interesa. 

----

<h3 style="color: #9FEF00;">Task 2. When a volume shadow snapshot is created, the Volume shadow copy service validates the privileges using the Machine account and enumerates User groups. Find the two user groups the volume shadow copy process queries and the machine account that did it.  </h3>

Antes de realizar operaciones sensibles, como crear una instantánea de volumen, el servicio VSS valida los permisos de la cuenta que ejecuta la acción, que puede ser la cuenta de equipo (MACHINE$).

Para esto podemos buscar por el EventID 4799.

- VSS consulta si esa cuenta pertenece a grupos privilegiados como:
     - Administrators
     - Backup Operators
- Esta consulta genera un evento 4799.

Así que primero vemos qué procesos fueron los que geeraron un eventid 4799: 

```bash
index="crownjewel1" EventId=4799
| dedup PayloadData3 
| table PayloadData3
```

Veremos los siguentes: 
```bash 
CallerProcessName: C:\Windows\System32\svchost.exe
CallerProcessName: C:\Windows\System32\dfsrs.exe
CallerProcessName: C:\Windows\System32\VSSVC.exe
CallerProcessName: C:\Windows\System32\lsass.exe
```

El que nos interesa es el VSSVC, asi que filtramos por este: 

```bash 
index="crownjewel1" EventId=4799 PayloadData3="CallerProcessName: C:\\Windows\\System32\\VSSVC.exe"
| dedup Payload
```

Esto nos devuelve 2 registros, para dos usuarios diferentes,  el nombre de la cuenta lo encontrramos en el campo `"@Name":"SubjectUserName"`

-----

<h3 style="color: #9FEF00;">Task 3. Identify the Process ID (in Decimal) of the volume shadow copy service process. </h3>

Para esto podemos aplicar la siguiene query en splunk: 

```bash
index="crownjewel1" EventId=4799 PayloadData3="CallerProcessName: C:\\Windows\\System32\\VSSVC.exe"
| table PayloadData4
| rename PayloadData4 as CallerProcessId
```

Nos da una tabla con varios registros, que todos son el mismo. 
CallerProcessId: contiene el ID del proceso (PID) que realizó la acción que disparó el evento.

La query nos retorna un valor en hexadecimal, podemos convertirlo con python: 

```powershell
PS C:\Users\Lenovo\Downloads\compartida\EvtxECmd\EvtxeCmd> python
Python 3.11.5 (tags/v3.11.5:cce6ba9, Aug 24 2023, 14:38:34) [MSC v.1936 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x1190
4496
>>>
```

----

<h3 style="color: #9FEF00;">Task 4. Find the assigned Volume ID/GUID value to the Shadow copy snapshot when it was mounted.  </h3>

Para esto podemos filtrar por los siguientes EventId: 

- Event 4: “The NTFS volume has been successfully mounted.”
- Event 9: “NTFS scanned entire volume bitmap.”
- Event 10: “NTFS cached run statistics.”
- Event 300: “The NTFS volume dismount has started.”
- Event 303: “The NTFS volume has been successfully dismounted.”

Así que podemos aplicar el siguiente filtro que es más avanzado: 

```bash 
index="crownjewel1" EventId IN (4,9,10,300,303)
| spath input=Payload path=EventData.Data{} output=DataArray
| mvexpand DataArray
| spath input=DataArray path="@Name" output=Name
| spath input=DataArray path="#text" output=TextValue
| where like(TextValue, "%Shadow%")
```

> Con mvexpand convertimos cada valor del multivalue DataArray en un evento “hijo” separado. Así, de un solo evento con un array de 10 elementos, obtenemos (temporalmente) 10 eventos, cada uno con su propio DataArray
> Con mvexpand convertimos cada valor del multivalue DataArray en un evento “hijo” separado. Así, de un solo evento con un array de 10 elementos, obtenemos (temporalmente) 10 eventos, cada uno con su propio DataArray. Para cada subevento ya podemos aplicar filtrado sobre c


De aquí ya podemos obtener el Volume ID / GUID (VolumeCorrelationId), que es un identificador único que referencia una copia de volumen creada por VSS.

Lo obtenemos del siguiente campo: `"@Name":"VolumeCorrelationId"`

-----

<h3 style="color: #9FEF00;">Task 5. Identify the full path of the dumped NTDS database on disk. </h3>

Esto ya lo explicamos en la [primera resolución de este laboratorio](https://maxixploit.github.io/blog/sherlock-crownjewel1/#), básicamente parseamos la `MFT` con chainsaw a formato json, después filtramos con `.jq` y grep. 

-----

<h3 style="color: #9FEF00;">Task 6. When was newly dumped ntds.dit created on disk?  </h3>

Aquí filtramos por la ruta que obtuvimos en la pregunta anterior, en el registro que retorna podemos ver la fecha. 

---------

<h3 style="color: #9FEF00;">Task 7. A registry hive was also dumped alongside the NTDS database. Which registry hive was dumped and what is its file size in bytes? </h3>

Aqui también buscamos en la MFT, buscamos la `hive SYSTEM`, que se usa para desencriptar el ntds.dit. 


