---
layout: single
title: Sherlock - AWS_BucketWare
excerpt: Investigación de logs de AWS. 
date: 2026-9-17
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
   - linux
   - aws logs
   - exfiltration
   - persistence
   - cloud
   - grep 
   - awk
   - jq 
---

Scenario:

An attacker used compromised AWS credentials to establish persistence within a cloud environment and propagate large-scale phishing campaigns. In this challenge, as an Incident Responder, you?ll analyze the various steps taken by the attacker to achieve persistence and set up the staging for phishing campaigns from the compromised environment. 

Inspired by a real-world scenario of actual cloud malware: Ransomware in the Cloud.



Para este lab se nos dan un montón de ficheros de logs en formato json, por lo que lo analizaré usando `jq` en la línea de comandos.

----

**1\. What is the compromised identity?**


Con el siguiente comando podemos ver todos los usurios de nuestros logs: 

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/04/25]
└─$ jq '.Records[] | .userIdentity.userName' *.json | sort | uniq -c | sort -rn 
    102 "iamadmin"
     25 null
     15 "s3user"
```

`iamadmin` es una cuenta administrativa, por lo que nos queda el usuario `s3user`, con 15 eventos, suficientes para realizar acciones dirigidas en un ataque.

------

**2\. In order of occurrence, what were the last three reconnaissance API calls the attacker performed using the compromised credentials?**

Ahora enumeramos las acciones de este usuario:

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/04/25]
└─$ jq '.Records[] | select(.userIdentity.userName == "s3user") | "\(.eventTime) \(.eventName) \(.eventSource)"' *.json | sort             
"2023-04-25T15:51:31Z ListUsers iam.amazonaws.com"
"2023-04-25T15:52:33Z ListBuckets s3.amazonaws.com"
"2023-04-25T15:55:49Z ListIdentities ses.amazonaws.com"
"2023-04-25T15:56:51Z ListAccessKeys iam.amazonaws.com"
"2023-04-25T15:57:53Z ListServiceQuotas servicequotas.amazonaws.com"
"2023-04-25T15:58:55Z GetSendQuota ses.amazonaws.com"
"2023-04-25T15:59:56Z CreateUser iam.amazonaws.com"
"2023-04-25T16:00:58Z CreateUser iam.amazonaws.com"
"2023-04-25T16:02:00Z CreateUser iam.amazonaws.com"
"2023-04-25T16:03:02Z GetBucketVersioning s3.amazonaws.com"
"2023-04-25T16:04:06Z PutBucketVersioning s3.amazonaws.com"
"2023-04-25T16:05:08Z ListObjects s3.amazonaws.com"
"2023-04-25T16:05:09Z GetObject s3.amazonaws.com"
"2023-04-25T16:05:11Z DeleteObject s3.amazonaws.com"
"2023-04-25T16:19:15Z PutObject s3.amazonaws.com"
```

Ordenemos esto de forma cronológica junto con la naturaleza de cada acción:


| Hora | Llamada | Tipo |
|---|---|---|
| 15:51:31 | ListUsers | Recon |
| 15:52:33 | ListBuckets | Recon |
| 15:55:49 | ListIdentities | Recon |
| 15:56:51 | ListAccessKeys | Recon |
| 15:57:53 | ListServiceQuotas | Recon |
| 15:58:55 | GetSendQuota | Recon |
| 15:59:56 | CreateUser | **Acción** (persistencia) |
| 16:00:58 | CreateUser | **Acción** (persistencia) |
| 16:02:00 | CreateUser | **Acción** (persistencia) |
| 16:03:02 | GetBucketVersioning | Recon |
| 16:04:06 | PutBucketVersioning | **Acción** (modifica config) |
| 16:05:08 | ListObjects | Recon |
| 16:05:09 | GetObject | Recon |
| 16:05:11 | DeleteObject | **Acción** (destructiva) |
| 16:19:15 | PutObject | **Acción** (impacto/exfil) |


El atacante primero hace un recon "amplio" de la cuenta (usuarios, buckets, SES), luego escala creando 3 usuarios IAM para persistencia, y justo antes de tocar el bucket S3 vuelve a hacer recon puntual sobre ese recurso espec??fico antes de manipularlo.

Entonces, si filtramos  solo las llamadas de reconocimiento (sin las de `Create/Put/Delete`) y tomamos las **últimas tres en orden**, quedan:

- **GetBucketVersioning** -> 16:03:02
- **ListObjects** -> 16:05:08
- **GetObject** -> 16:05:09

---------

**3\. What was the first successful reconnaissance API call?**

Ejecutamos el siguiente comando para ver los códigos de error: 

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/04/25]
└─$ jq '.Records[] | select(.userIdentity.userName == "s3user") | "\(.eventTime) \(.eventName) \(.eventSource) \(.errorCode // "SUCCESS")"' *.json | sort  
"2023-04-25T15:51:31Z ListUsers iam.amazonaws.com AccessDenied"
"2023-04-25T15:52:33Z ListBuckets s3.amazonaws.com SUCCESS"
"2023-04-25T15:55:49Z ListIdentities ses.amazonaws.com AccessDenied"
"2023-04-25T15:56:51Z ListAccessKeys iam.amazonaws.com AccessDenied"
"2023-04-25T15:57:53Z ListServiceQuotas servicequotas.amazonaws.com AccessDenied"
"2023-04-25T15:58:55Z GetSendQuota ses.amazonaws.com AccessDenied"
"2023-04-25T15:59:56Z CreateUser iam.amazonaws.com AccessDenied"
```

Se trata del evento `ListBuckets:2023-04-25T15:52:33Z`.

-------

**4\. How did the attacker attempt to maintain persistence within the environment?**

Ya vimos anteriormente que el atacante intentó crear un usuario:

`CreateUser:15:59:56`

------------

**5\. In order of occurrence, which IAM users were involved in this persistence attempt?**

Podemos ver esto con el siguiente comando:

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/04/25]
└─$ jq '.Records[] | select(.userIdentity.userName == "s3user") | .errorMessage' *.json | sort | uniq -c 
      7 null
      1 "User: arn:aws:iam::670756667180:user/s3user is not authorized to perform: iam:CreateUser on resource: arn:aws:iam::670756667180:user/adm1n because no identity-based policy allows the iam:CreateUser action"
      1 "User: arn:aws:iam::670756667180:user/s3user is not authorized to perform: iam:CreateUser on resource: arn:aws:iam::670756667180:user/dev0ps_user because no identity-based policy allows the iam:CreateUser action"
      1 "User: arn:aws:iam::670756667180:user/s3user is not authorized to perform: iam:CreateUser on resource: arn:aws:iam::670756667180:user/rooter because no identity-based policy allows the iam:CreateUser action"
```

Intentó crear los usuarios `rooter`, `adm1n`, `dev0ps_user`

------------

**6\. Were the persistence attempts successful?**

```bash
"2023-04-25T15:58:55Z GetSendQuota ses.amazonaws.com AccessDenied"
"2023-04-25T15:59:56Z CreateUser iam.amazonaws.com AccessDenied"
"2023-04-25T16:00:58Z CreateUser iam.amazonaws.com AccessDenied"
"2023-04-25T16:02:00Z CreateUser iam.amazonaws.com AccessDenied
``` 

Revisando los logs vemos que el atacante no logró crear el usuario.

--------

**7\. Which S3 bucket was affected in this attack?**

Revisando los logs vemmos que solo tenemos un solo bucket: 

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/04/25]
└─$ jq '.Records[] | select(.userIdentity.userName == "s3user") | .requestParameters.bucketName' *.json | sort | uniq -c
      9 null
      6 "webrew-dev-backup"
```

-------

**8\. How did the attacker check for protection on this resource?**

Esto se trata de `GetBucketVersioning`, es un mecanismmo de protección, si se borra o sobreescribe un objeto no se elimina realmente, solo se guarda una versión anterior.

------

**9\. How did the attacker remove the protection on this resource?**

Después de que el atacante listara el versioning vemos que lo modificó: 

```bash
"2023-04-25T16:03:02Z GetBucketVersioning s3.amazonaws.com"
"2023-04-25T16:04:06Z PutBucketVersioning s3.amazonaws.com"
```

-----------

**10\. What file did the attacker exfiltrate?**

Para esto nos fijamos en el siguiente evento:

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/04/25]
└─$ jq '.Records[] | select(.userIdentity.userName == "s3user" and .eventName == "GetObject")' *.json     
 "resources": [
    {
      "type": "AWS::S3::Object",
      "ARN": "arn:aws:s3:::webrew-dev-backup/highprofilecoffeeorders.csv"
    },
    {
      "accountId": "670756667180",
      "type": "AWS::S3::Bucket",
      "ARN": "arn:aws:s3:::webrew-dev-backup"
    }
  ], 
```

-----------

**11\. What was the name of the ransom note?**

Buscamos en el siguient evento, que indica el evento de un objeto: 

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/04/25]
└─$ jq '.Records[] | select(.userIdentity.userName == "s3user" and .eventName == "PutObject")' *.json 
<SNIP>
 "resources": [
    {
      "type": "AWS::S3::Object",
      "ARN": "arn:aws:s3:::webrew-dev-backup/ransomenote.txt"
    },
    {
      "accountId": "670756667180",
      "type": "AWS::S3::Bucket",
      "ARN": "arn:aws:s3:::webrew-dev-backup"
    }
  ],
<SNIP>
```
