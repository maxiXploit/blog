---
layout: single
title: Sherlock Campfire resuelto con splunk
excerpt: Investigando un ataque Kerberoasting con splunk. 
date: 2025-6-12
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


Este laboratorio lo estaré resolviendo con splunk, parseamos los .evtx con `.evtxecmd` a formato json, creamos un nuevo índice, ponemos un valor diferente en el campo host y pasamos rápidamente a las preguntas. 

----

<h3 style="color: #9FEF00;"> Task 1. Analyzing Domain Controller Security Logs, can you confirm the date & time when the kerberoasting activity occurred? </h3>

Para esto podemos buscar por el EventID 4769 – A Kerberos service ticket was requested.
> Este evento se genera cuando se solicita un Ticket Granting Service (TGS), lo cual es la base del ataque Kerberoasting. Este es el evento clave para detectar este tipo de actividad.

Asi que aplicamos el siguiente query en splunk: 

``` bash 
index="campfire" host="domaincontroller" EventId=4769
| spath input=Payload path=EventData.Data{} output=DataArray
| mvexpand DataArray
| spath input=DataArray path="@Name" output=Name
| spath input=DataArray path="#text" output=TextValue
| where like(Name, "ServiceName")
| where NOT like(TextValue, "%krbtgt%") AND NOT like(TextValue, "%$%")
```

Pues nos nos interesan los nombres de cuentas del sistema como `DC01$`. 

Esta query nos devuelve un solo registro. 

-----

<h3 style="color: #9FEF00;"> Task 2. What is the Service Name that was targeted? </h3>

En el registro anterior podemos ver que el TGS  se solicitó para el servicio de `MSSQLService`

-----

<h3 style="color: #9FEF00;"> Task 3. It is really important to identify the Workstation from which this activity occurred. What is the IP Address of the workstation? </h3>

Esto también podemos encontrarlo en el registro que hemos encontrado, en la sección de `Payload`.

-----

<h3 style="color: #9FEF00;"> Task 4. Now that we have identified the workstation, a triage including PowerShell logs and Prefetch files are provided to you for some deeper insights so we can understand how this activity occurred on the endpoint. What is the name of the file used to Enumerate Active directory objects and possibly find Kerberoastable accounts in the network? </h3>

Para esto podemos aplicar un filtro por el eventid 4104, que ya sabemos que se genera este evento cada que se ejecuta un script. 

Aplicamos el siguiente filtro en splunk: 

```bash 
index="campfire" host="workstation" EventId=4104
| table PayloadData1
```

Nos devulve varios registro, en todos el mismo payload. 

-----

<h3 style="color: #9FEF00;"> Task 5. When was this script executed? </h3>

Para esto podemos aplicar el siguiente filtro: 

```bash 
index="campfire" host="workstation" EventId=4104
| table TimeCreated, PayloadData1
| sort TimeCreated
```

----

<h3 style="color: #9FEF00;"> Task 6. What is the full path of the tool used to perform the actual kerberoasting attack? </h3>

Esto lo podemos encontrar en el prefectch, parseamos el directorio completo con `PECmd`, abrimos el csv en Timeline Explorer, filtramos por un rango de tiempo, en este caso un rango de unos momentos antes y despué de que haya iniciado el ataque. Podremos ver una herramienta bien conocida: `C:\Users\Alonzo.spire\Downloads\Rubeus.exe` 

-----

<h3 style="color: #9FEF00;"> Task 7. When was the tool executed to dump credentials? </h3>

En el campo que muestra la herramienta podemos ver la fecha de ejecución. 
