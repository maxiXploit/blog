---
layout: single
title: Sherlock CrownJewel2 resuelto con splunk
excerpt: Continuación del sherlock CrownJewel1.
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
---


Primeramente parseamos todos los `.evtx` que se nos proporciona en el laboratorio a un formato json, se puede hacer con chainsaw o EvtxEcmd, yo usé la segunda. 
Después creamos un índice en splunk y añadimos aquí nuesto .json. 

Pasamos rápidamente a las preguntas. 

-----

<h3 style="color: #9FEF00;">Task 1. When utilizing ntdsutil.exe to dump NTDS on disk, it simultaneously employs the Microsoft Shadow Copy Service. What is the most recent timestamp at which this service entered the running state, signifying the possible initiation of the NTDS dumping process? </h3>

En splunk aplico lo siguiente: 

```bash 
index="crownjewel2" EventId=7036 
| where like(PayloadData1, "%Shadow%") AND PayloadData2="Status: running"
| sort -_time
```

El timestamp es el del primer registro devuelto. 

----

<h3 style="color: #9FEF00;">Task 2. Identify the full path of the dumped NTDS file. </h3>

El Event ID 325 en el registro de Aplicación (Application) de Windows, cuando proviene del proveedor ESENT, indica que el motor de base de datos interno (Extensible Storage Engine) ha creado una nueva base de datos. En el contexto de Active Directory, esto suele corresponder a la generación o volcado de una copia del archivo ntds.dit.

Así que filtramos por el EventId 325 en splunk: 

```bash 
index="crownjewel2" EventId=325 
| table PayloadData1 
| sort -_time
```

Esto nos devuelve varios registros, el primero muestra una ruta en una carpeta temporal, que es bastante sospechosa ya para almacenar un fichero bastante crítico comom el `ntds.dit`.

-----

<h3 style="color: #9FEF00;">Task 3. When was the database dump created on the disk? </h3>

Para esto modificamos el filtro anterior: 

```bash 
index="crownjewel2" EventId=325
| table PayloadData1, TimeCreated
| sort -_time
```

------

<h3 style="color: #9FEF00;">Task 4. When was the newly dumped database considered complete and ready for use? </h3>

Para esto podemos filtrar por el EventID 327, que significa que se adjuntó (montó o abrió) una base de datos ya existente para usarla.

Es decir, primero se generaría un eventid 325(se creó una copia del ntds.dit) y después un eventid 327(se tomó la base de datos para usarse/leerse/analizarse) para detectar un comportamiento sospechoso.

Aplicamos el siguiente filtro en splunk: 

```bash 
index="crownjewel2" EventId=327 
| table PayloadData1, TimeCreated
| sort -_time
```

Tomamos el timestamp del registro que contiene la ruta sospechasa donde se almacenó el volcado. 

--------

<h3 style="color: #9FEF00;">Task 5. Event logs use event sources to track events coming from different sources. Which event source provides database status data like creation and detachment? </h3>

- Un proveedor (o “source”) es la entidad que escribe eventos en el registro (Event Log). Puede ser un servicio interno de Windows (p. ej. ESENT, NTFRS, DFS-Repl, Schannel, Service Control Manager…) o bien una aplicación de terceros.

- Cada proveedor tiene su propio catálogo de Event IDs. Por ejemplo, ESENT define el 325 para “base de datos creada”; NTFRS también define un Event ID 325, pero con un mensaje distinto y una lógica distinta a ESENT; y así sucesivamente con otros componentes.

En este caso, en splunk muestra en el campo ` Provider` : ESENT, que es "Motor de base de datos interno"(Extensible Storage Engine). Se usa en AD, en Exchange, en perfiles de usuario, etc. 

----

<h3 style="color: #9FEF00;">Task 6. When ntdsutil.exe is used to dump the database, it enumerates certain user groups to validate the privileges of the account being used. Which two groups are enumerated by the ntdsutil.exe process? Give the groups in alphabetical order joined by comma space. </h3>

Esto ya lo sabemos, cuando el servicio VSS va a realizar una operación crítica, valida los permisos del usuario que solicitó el servicio, esto se ve con el filtro 4799. 

Usamos lo siguiente para obtener una tabla: 

```bash 
index="crownjewel2" EventId=4799
| spath input=Payload path=EventData.Data{} output=DataArray
| mvexpand DataArray
| spath input=DataArray path="@Name" output=Name
| spath input=DataArray path="#text" output=TextValue
| where Name="TargetUserName" 
| dedup TextValue
| table TimeCreated, EventId, TextValue
```

Esto nos retorna dos únicamete 2 valores. 

-----

<h3 style="color: #9FEF00;">Task 7. Now you are tasked to find the Login Time for the malicious Session. Using the Logon ID, find the Time when the user logon session started. </h3>

Para esto, aplico el siguiente filtro en splunk: 

```bash 
index="crownjewel2" EventId IN (4768, 4769, 5379)
| spath input=Payload path=EventData.Data{} output=DataArray
| mvexpand DataArray
| spath input=DataArray path="@Name" output=Name
| spath input=DataArray path="#text" output=TextValue
| where Name="SubjectUserName" 
| where (TextValue!="DC01$" AND TextValue!="LOCAL SERVICE")
| sort -_time
```

- El usuario solicita su TGT → 4768
- Luego solicita acceso a un servicio con un TGS → 4769
- Finalmente, el sistema registra el uso de la credencial protegida → 5379
- Todo esto ocurre en cadena, casi al mismo tiempo.

