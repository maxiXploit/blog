---
layout: single
title: Sherlock - Google_Cloud_Compromise
excerpt: Ejercicio de análisis de logs en google cloud sobre una exfiltración de datos
date: 2026-9-24
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
   _ googlecloud
   _ gcp
   _ cloud
   _ cloudsecurity
   _ cloudauditlogs
   _ auditlogs
   _ cloudstorage
   _ gcs
   _ storage
   _ iam
   _ api
   _ apis
   _ jq
   _ json
   _ dfir
   _ forensics
   _ loganalysis
   _ timeline
   _ incidentresponse
   _ threatdetection
   _ reconnaissance
   _ enumeration
---

----------

**1\. What’s the name of the project that was compromised?**

Usamos el siguiente comando para obtener el `project_id`:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ jq '.[] | .resource.labels.project_id' gcp.json 
"cryptostartup"
"cryptostartup"
"cryptostartup"
"cryptostartup"
"cryptostartup"
"cryptostartup"
```

-----

**2\.  What google cloud identity is compromised?**

Con el siguiente comando veremos las cuentas presentes en los logs:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ jq '.[] | .protoPayload.authenticationInfo.principalEmail' gcp.json | sort | uniq -c 
      6 "cloud-storage-helper@cryptostartup.iam.gserviceaccount.com"
```

--------

**3\. What IP address is the identity authenticated from?**

Con el siguiente comando:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ jq '.[] | .protoPayload.requestMetadata.callerIp' gcp.json | uniq -c 
      6 "178.132.108.38"
```

----------

**4\. What country does the IP originate from?**

Aplicando un `whois`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ whois 178.132.108.38 | grep -i "country"
country:        RO
```

Este código pertenece a `Romania`.

----

**5\. What device did the attack come from?**

Usamos el siguiente comando:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ jq '.[] | .protoPayload.requestMetadata.callerSuppliedUserAgent' gcp.json | uniq -c                       
      1 "apitools Python/3.11.3 gsutil/5.10 (darwin) analytics/disabled interactive/True command/cp google-cloud-sdk/390.0.0,gzip(gfe)"
      2 "apitools Python/3.11.3 gsutil/5.10 (darwin) analytics/disabled interactive/True command/ls google-cloud-sdk/390.0.0,gzip(gfe)"
      1 "google-cloud-sdk gcloud/390.0.0 command/gcloud.projects.get-iam-policy invocation-id/a4713040dd8e4655acb6c5b4e465f403 environment/None environment-version/None interactive/True from-script/False python/3.11.3 term/xterm-256color (Macintosh; Intel Mac OS X 22.5.0),gzip(gfe)"
      1 "google-cloud-sdk gcloud/390.0.0 command/gcloud.compute.firewall-rules.create invocation-id/6c8ceade824648daaeedad5a6c71db32 environment/None environment-version/None interactive/True from-script/False python/3.11.3 term/xterm-256color (Macintosh; Intel Mac OS X 22.5.0),gzip(gfe)"
      1 "google-cloud-sdk gcloud/390.0.0 command/gcloud.compute.firewall-rules.list invocation-id/e74de2d70ade4ce5826f68469ae37745 environment/None environment-version/None interactive/True from-script/False python/3.11.3 term/xterm-256color (Macintosh; Intel Mac OS X 22.5.0),gzip(gfe)"
```

Vemos la presencia de `Macintosh`, la lìnea de computadoras personales diseñadas por Apple Inc, estos log provienen de `gcloud`, la herramienta de línea de comandos oficial de googlecloud.

-------------

**6\. What was the first failed API call made by this identity?**

Para esto primero vemos los eventos registrados:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ jq -r '.[] | "\(.timestamp) - \(.protoPayload.methodName)"' gcp.json | sort
2023-07-27T00:16:24.221685Z - google.api.serviceusage.v1.ServiceUsage.EnableService
2023-07-27T00:16:43.371638Z - google.api.serviceusage.v1.ServiceUsage.EnableService
2023-07-27T00:17:03.154420Z - google.api.serviceusage.v1.ServiceUsage.EnableService
2023-07-27T00:17:11.553357353Z - storage.buckets.list
2023-07-27T00:17:18.314855805Z - storage.objects.list
2023-07-27T00:17:36.194200418Z - storage.objects.get
```

Con esto ya podemos filtrar por el campo de `.code`, uno distinto de `0` indica error:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ jq -r '.[] |  select((.protoPayload.status.code // 0) != 0) | "\(.protoPayload.methodName)"' gcp.json  
google.api.serviceusage.v1.ServiceUsage.EnableService
google.api.serviceusage.v1.ServiceUsage.EnableService
google.api.serviceusage.v1.ServiceUsage.EnableService
```

-----------

**7\. What storage bucket was enumerated?**

Lo encontramos en el siguiente evento: 

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ jq '.[] | select(.protoPayload.methodName == "storage.objects.list") | "\(.resource.labels.bucket_name)"' gcp.json 
"importantbucket"
```

--------

**8\. What API call was used to exfiltrate an item from this bucket?**

Esto se ve en el siguiente evento: `2023-07-27T00:17:36.194200418Z - storage.objects.get`

-----------

**9\. Which Google Cloud command-line tool was used during the exfiltration attempt?**

Viendo el useragent:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ jq '.[] | select(.protoPayload.methodName == "storage.objects.list") | "\(.protoPayload.requestMetadata.callerSuppliedUserAgent)"' gcp.json 
"apitools Python/3.11.3 gsutil/5.10 (darwin) analytics/disabled interactive/True command/ls google-cloud-sdk/390.0.0,gzip(gfe)"
```

`gsutil` es una aplicación escrita en python que permite acceder y administrar **Cloud Storage**

------

**10\. What is the name of the file that was exfiltrated from the storage bucket?**

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/google]
└─$ jq '.[] | select(.protoPayload.methodName == "storage.objects.get") | "\(.protoPayload.resourceName)"' gcp.json       
"projects/_/buckets/importantbucket/objects/secretcode.java"
```
