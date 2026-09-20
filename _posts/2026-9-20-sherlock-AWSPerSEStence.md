---
layout: single
title: Sherlock - AWS_PerSEStence
excerpt: Análisis de logs de AWS para la reconstrucción forense de un ataque en un entorno Cloud.
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
   - aws
   - cloud
   - cloudtrail
   - ses
   - iam
   - dfir
   - incident-response
   - threat-hunting
   - log-analysis
   - persistence
   - privilege-escalation
   - mitre-attack
   - awk
   - jq
---


**1\. What is the name of the compromised identity?**

Empezamos viendo los  usuarios: 

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/awspersestence/04]
└─$ jq '.Records[] | .userIdentity.userName' *.json | sort | uniq -c | sort -rn
     98 "iamadmin"
     10 "Bob"
      6 null
``` 

Vemos la cuenta administrativa de `iamadmin` y al usuario `Bob`, con pocos eventos que indican eventos dirigidos de un ataque.

-------

**2\. What were the enumeration API calls the attacker made against this service?**

Viendo los eventos:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/awspersestence/04]
└─$ jq '.Records[] | select(.userIdentity.userName == "Bob") | "\(.eventTime) \(.eventName) \(.eventSource)"' *.json       
"2023-04-04T07:13:02Z GetAccountSendingEnabled ses.amazonaws.com"
"2023-04-04T07:14:01Z GetSendQuota ses.amazonaws.com"
"2023-04-04T07:16:37Z UpdateAccountSendingEnabled ses.amazonaws.com"
"2023-04-04T07:18:02Z CreateUser iam.amazonaws.com"
"2023-04-04T07:19:49Z CreateLoginProfile iam.amazonaws.com"
"2023-04-04T07:20:12Z CreateGroup iam.amazonaws.com"
"2023-04-04T07:20:29Z AttachGroupPolicy iam.amazonaws.com"
"2023-04-04T07:21:14Z AddUserToGroup iam.amazonaws.com"
"2023-04-04T07:22:03Z DeleteAccessKey iam.amazonaws.com"
"2023-04-04T07:18:37Z CreateLoginProfile iam.amazonaws.com"
```

Viendo la secuencia de eventos vemos `GetAccountSendingEnabledGet` y `SendQuota`, que son eventos de reconocimiento de SES(Simple Email Services), ya que son de sololectura y no modifican nada:

- `GetAccountSendingEnabled` revisa si la cuenta tiene el envío de correos habilitado.
- `GetSendQuota` devuelve el límite de envío en 24 h, la tasa máxima por segundo y cuántos correos se han enviado. Sirve para saber cuánto spam o phishing se puede mandar.

-----------

**3\. What API call did the attacker use to activate this service?**

Aquí estamos hablando de `UpdateAccountSendingEnabled`: "2023-04-04T07:16:37Z UpdateAccountSendingEnabled ses.amazonaws.com"

Esto activa o desactiva el envío de correo de toda la cuenta de SES en esa región. Recibe un solo parámetro, `Enabled`(true/false), que en cloudtrail aparece como `requestParameters.enables`.

Las cuentas pueden tener el envió pausado(por un admin o por AWS cuado la reputación cae por bounces o quejas). Reactivarlo es el paso previo para mandar phishing o spam desde infraestructura legítima con buena reputación de dominio.

----------

**4\. What was the initial activity that the attacker performed to establish persistence within the cloud environment?**

Se trata del evento `CreateUser`.

---------

**5\. What was the name of the new identity?** 

Revisando el evento de `CreateUser`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/aws]
└─$ jq '.Records[] | select(.eventName == "CreateUser")' *.json
<SNIP>
  "responseElements": {
    "user": {
      "createDate": "Apr 4, 2023 7:18:02 AM",
      "userName": "ses_catxzy",
      "arn": "arn:aws:iam::670756667180:user/ses_catxzy",
      "path": "/",
      "userId": "AIDAZYLBWP4WAJ3T7FVMS"
    }
  },
```

-----

**6\. What was the name of the new group?**

Revisando el evento de `CreateGroup` vemos que se crea el grupo ` AdminsDDefault`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/aws]
└─$ jq '.Records[] | select(.eventName == "CreateGroup")' *.json 
<SNIP>
  "responseElements": {
    "group": {
      "arn": "arn:aws:iam::670756667180:group/AdminsDDefault",
      "createDate": "Apr 4, 2023 7:20:12 AM",
      "groupId": "AGPAZYLBWP4WE3TG6M727",
      "path": "/",
      "groupName": "AdminsDDefault"
    }
  },
```

----------

**7\. What policy was added to this group?**

Revisando el siguiente evento: 

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/aws]
└─$ jq '.Records[] | select(.eventName == "AttachGroupPolicy")' *.json
  "requestParameters": {
    "groupName": "AdminsDDefault",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  },
```

--------

**8\. How was the new user added to this group?**

Se hizo con el siguiente evento: `"2023-04-04T07:21:14Z AddUserToGroup iam.amazonaws.com"`


--------------

**9\. How did the attacker prevent the compromised user from regaining programmatic access to AWS?**

Esto se hizo con el siguiente evento: `"2023-04-04T07:22:03Z DeleteAccessKey iam.amazonaws.com"`.

Con esta llamada el atacante borró las access key del usuario comprometido. Las access key son las credenciales para acceso programático(CLI, SDKs, API). Sin ellas, el dueño legítimo ya no puede autenticarse por esa vía, y sin poder llamar a la API, tampocopuederevisar CloudTrail, revocar lo que creó el atacante ni limpiar nada. Están negando acceso a la víctima.

--------

**10\. What was the IP address of the attacker?**

Revisando el siguiente campo:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/aws]
└─$ jq '.Records[] | select(.eventName == "GetSendQuota") | "\(.sourceIPAddress)"' *.json 
"185.209.221.97"
```

En resumen:

> Un actor con credenciales comprometidas realizó reconocimiento sobre Amazon SES (GetAccountSendingEnabled, GetSendQuota) y habilitó el envío de correo de la cuenta mediante UpdateAccountSendingEnabled, probablemente para campañas de spam o phishing. Posteriormente estableció persistencia creando un usuario con acceso a consola (CreateUser, CreateLoginProfile), un grupo con la política AdministratorAccess (CreateGroup, AttachGroupPolicy) y vinculó ambos con AddUserToGroup. Finalmente eliminó las access keys del usuario comprometido (DeleteAccessKey) para impedirle recuperar el acceso programático. El laboratorio cubre reconstrucción de la línea de tiempo, identificación de la fase de cada evento, mapeo a MITRE ATT&CK (T1526, T1136.003, T1098.003, T1531) y lógica de detección por correlación.
