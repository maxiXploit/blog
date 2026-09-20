---
layout: single
title: Sherlock - Google_Cloud_Incident
excerpt: Análisis de logs de GoogleCLoud sobre un ataque de cryptojacking a causa de unas credenciales robadas.
date: 2026-9-20
classes: wide
header:
   teaser: ../assets/images/socs/logoletsdefend.png
   teaser_home_page: true
   icon: ../assets/images/hacktheweb.webp
categories:
   - hackthebox
   - soc 
   - blue team
   - cloud
tags:
   - cloud
   - gcp
   - google-cloud
   - cloud-audit-logs
   - cloud-forensics
   - dfir
   - sherlock
   - htb
   - blue-team
   - soc
   - log-analysis
   - json
   - jq
   - iam
   - service-account
   - compromised-credentials
   - gcloud
   - gce
   - firewall
   - egress
   - cryptojacking
   - quota-exceeded
   - threat-hunting
   - timeline-analysis
   - aws-vs-gcp
---

Scenario:

**A developer accidentally committed a Google Cloud identity’s key to a public repository. You’ve been tasked with investigating an attacker using the compromised identity attached to the exposed key to perform some nefarious activities.**

Para este laboratorio se nos da un unico fichero en formato ´.json´ con los logs del servicio cloud, por lo que avanzaoms rápido con las preguntas.

-------

**1\. What Google Cloud identity is compromised?**

Podemos aplicar el siguiente filtro para ver los correos de los usuarios:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ jq '.[] | .protoPayload.authenticationInfo.principalEmail' gcp.json | sort | uniq -c
     17 "main-dev@cyberwox-labs.iam.gserviceaccount.com"
```

---------

**2\. What IP address is the identity authenticated from?**

Aplicando el siguiente filtro para ver la ip de este usuario:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ jq '.[] | select(.protoPayload.authenticationInfo.principalEmail == "main-dev@cyberwox-labs.iam.gserviceaccount.com" ) | .protoPayload.requestMetadata.callerIp' gcp.json | sort | uniq -c
     17 "160.238.37.7"
```

-------

**3\. What country does the IP originate from?**

Ahora con un `whois` podemos ver el país:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ whois 160.238.37.7 | grep -i "country"
country:        KR
```

Este código de país, de acuerdo a la ISO 3166-1, pertenece a `South Korea`

-------------

**4\. What is the name of the firewall rule the attacker attempted to create?**

Para esto tenemos que revisar los eventos registrados en los logs:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ jq '.[] | .protoPayload.methodName ' gcp.json | sort | uniq -c
      6 "google.api.serviceusage.v1.ServiceUsage.EnableService"
      2 "google.longrunning.Operations.GetOperation"
      2 "v1.compute.firewalls.insert"
      6 "v1.compute.instances.insert"
      1 "v1.compute.networks.insert"
```

Vemos el evento `"v1.compute.firewalls.insert"`,  mirándolo con jq:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ jq '.[] | select(.protoPayload.methodName == "v1.compute.firewalls.insert") ' gcp.json
<SNIP>
   "request": {
      "name": "default",
      "network": "https://compute.googleapis.com/compute/v1/projects/cyberwox-labs/global/networks/default",
      "alloweds": [
        {
          "IPProtocol": "all"
        }
      ],
      "destinationRanges": [
        "0.0.0.0/0"
      ],
      "direction": "EGRESS",
      "priority": "0",
      "@type": "type.googleapis.com/compute.firewalls.insert"
    },
<SNIP>
```

Esta regla tiene configurado la dirección `EGRESS`, que es para conectarse a cualquier IP de internet, definiendo la máxima prioridad con `0`, lo que lo hace ganar sobre cualquier regla `DENY`.

----------

**5\. What priority was the firewall rule?**

Como ya explicamos en la pregunta anterior, la regla tiene la pioridad `0`

--------

**6\. How many times did the attacker attempt to create GCE instances?**

Podemos usar el siguiente comando para ver los eventos de creaciones de instancias:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ jq '.[] | select(.protoPayload.methodName == "v1.compute.instances.insert") | "\(.operation.id)"' gcp.json | sort | uniq -c 
      2 "operation-1688110046883-5ff53bfafaddb-2cd1c7a5-8dc78956"
      2 "operation-1688110085588-5ff53c1fe44a3-fb89c288-83d40ab4"
      2 "operation-1688110241119-5ff53cb437c9b-db4ce97e-e9d505d8"

# O con: 

┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ jq '[.[] | select(.protoPayload.methodName == "v1.compute.instances.insert") | .operation.id] | unique | length' gcp.json 
3

```

Una cosa interesante a notar es el nombre de la instancia:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ jq '.[] | select(.protoPayload.methodName == "v1.compute.instances.insert") | "\(.protoPayload.request.name)"' *.json | sort | uniq -c  
      3 "crypto-instance"
      3 "null"
```

Sugiriendo un ataque de cryptojacking, con el egress abierto sirve para que las VM se comuniquen con un pool de minado.

----------

**7\. What was the first region the attacker attempted to create the instances in?**

Viendo las zonas:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ jq '.[] | select(.protoPayload.methodName == "v1.compute.instances.insert") | "\(.resource.labels.zone)"' *.json       
"europe-west1-b"
"europe-west1-b"
"europe-west1-b"
"europe-west1-b"
"us-east1-b"
"us-east1-b"
```

------------

**8\. Were any of the instances created? (Yes/No)**

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/googlecloudincident]
└─$ jq -r '.[] | select(.protoPayload.methodName=="v1.compute.instances.insert"
                    and .operation.last==true)
       | [.timestamp, .severity, .protoPayload.status.code,
          .protoPayload.status.message] | @tsv' gcp.json

2023-06-30T07:27:36.256986Z     ERROR   8       QUOTA_EXCEEDED
2023-06-30T07:28:12.847224Z     ERROR   8       QUOTA_EXCEEDED
2023-06-30T07:30:49.443219Z     ERROR   8       QUOTA_EXCEEDED
```

Un `statuscode` diferente de `0` indica error, ademas no vemos eventos posteriores como `instances.start`, `instances.get` sobre `crypto-instance`, lo que indica que no se crearon las intancias y por ende no se iniciaron.


