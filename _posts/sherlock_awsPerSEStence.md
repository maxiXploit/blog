aws
cloud
cloudtrail
ses
iam
dfir
incident-response
threat-hunting
log-analysis
persistence
privilege-escalation
mitre-attack
awk
jq
Scenario: 

----------

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




---------

**********

Submit Task
Task 5

Hint
What was the name of the new identity?

***_******

Submit Task
Task 6
What was the name of the new group?

**************

Submit Task
Task 7

Hint
What policy was added to this group?

***:***:***::***:******/*******************

Submit Task
Task 8

Hint
How was the new user added to this group?

**************

Submit Task
Task 9

Hint

----------------

How did the attacker prevent the compromised user from regaining programmatic access to AWS?


Con esta llamada el atacante borró las access key del usuario comprometido. Las access key son las credenciales para acceso programático(CLI, SDKs, API). Sin ellas, el dueño legítimo ya no puede autenticarse por esa vía, y sin poder llamar a la API, tampocopuederevisar CloudTrail, revocar lo que creó el atacante ni limpiar nada. Están negando acceso a la víctima.

--------

***************

Submit Task
Task 10

Hint
What was the IP address of the attacker?



