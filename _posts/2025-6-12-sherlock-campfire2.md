---
layout: single
title: Sherlock Campfire2 resuelto con splunk
excerpt: Investigando un ataque AsREP roasting attack con splunk.
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


Para esto ya parsee el .evtx usando EvtxEcmd, lo subi a un nuevo index llamado `campfire2` y pasamos rápidamente a las preguntas. 


-------

<h3 style="color: #9FEF00;"> Task 1. When did the ASREP Roasting attack occur, and when did the attacker request the Kerberos ticket for the vulnerable user? </h3>

Para esto podemos monitorear el Event ID 4768 – A Kerberos authentication ticket (TGT) was requested

 - Este evento ocurre cuando un usuario solicita un Ticket Granting Ticket (TGT) al AS (Authentication Service) de Kerberos.
 - Aunque AS-REP Roasting implica usuarios sin pre-authentication, este evento puede estar presente si el atacante hace múltiples pruebas o si hay otros usuarios implicados.

Aplicando el siguiente filtro en splunk: 

```bash 
index="campfire2" EventId=4768
| spath input=Payload path=EventData.Data{} output=DataArray
| mvexpand DataArray
| spath input=DataArray path="@Name" output=Name
| spath input=DataArray path="#text" output=TextValue
| where like(Name, "PreAuthType")
| where like(TextValue, "0")
```

También podemos aplicar lo siguiente: 

```bash 
index="campfire2" EventId=4768
| table PayloadData2, PayloadData6, TimeCreated
| sort TimeCreated
```

Podemos fijarnos en el registro que tiene `PreAuthType: Logon without Pre-Authentication.`

-----

<h3 style="color: #9FEF00;"> Task 2.   </h3>

Podemos modificar los dos filtros anteriores: 

```bash 
index="campfire2" EventId=4768
| spath input=Payload path=EventData.Data{} output=DataArray
| mvexpand DataArray
| spath input=DataArray path="@Name" output=Name
| spath input=DataArray path="#text" output=TextValue
| where like(Name, "PreAuthType")
| where like(TextValue, "0")
| table PayloadData1
```

--------

<h3 style="color: #9FEF00;"> Task 3. What was the SID of the account?  </h3>

Usando alguno de los dos filtros del inicio podemos encontrar la respuesta en el campo `"@Name":"TargetSid"`

-------

<h3 style="color: #9FEF00;"> Task 4. It is crucial to identify the compromised user account and the workstation responsible for this attack. Please list the internal IP address of the compromised asset to assist our threat-hunting team.  </h3>

Tambien podemos verlo en el registro que estamos analizando, en el campo `"@Name":"IpAddress"`

----

<h3 style="color: #9FEF00;"> Task 5. We do not have any artifacts from the source machine yet. Using the same DC Security logs, can you confirm the user account used to perform the ASREP Roasting attack so we can contain the compromised account/s?  </h3>

Para esto podemos aplicar un filtro por el Event ID 4769 – A Kerberos service ticket was requeste

 - Registra la solicitud de un TGS (Ticket Granting Service).
 - Puede aparecer si el atacante, después del AS-REP, intenta obtener un TGS para el mismo usuario o explora otros servicios.

Así que podemos aplicar el siguiente query: 

```bash 
index="campfire2" EventId=4769
| spath input=Payload path=EventData.Data{} output=DataArray
| mvexpand DataArray
| spath input=DataArray path="@Name" output=Name
| spath input=DataArray path="#text" output=TextValue
| where like(TextValue, "%172.17.79.129%")
``` 
