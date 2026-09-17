

Scenario:

Para este lab se nos proporcionan logs de aws que analizaré desde la línea de comandos con `jq`

------

Empezamos nuestro análisis revisando las cuentas de usuario que tenemos en los logs:

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/06/01]
└─$ jq '.Records[] | .userIdentity.userName' *.json | sort | uniq -c
     43 "cloud-ops-intern"
    109 "iamadmin"
      3 null
```

Tenemos la cuenta administrativa `iamadmin` y la cuenta comprometida `cloud-ops-intern`

Revisamos la suencuencia de acciones que realizó la cuenta comprometida con el comando:

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/06/01]
└─$ jq '.Records[] | select(.userIdentity.userName == "cloud-ops-intern") | "\(.eventTime) \(.eventName) \(.eventSource)"' *.json
<SNIP>
```

--------------------

**1\. What is the ARN of the compromised identity?**

Una vez identificada la cuenta comprometida podemos ver el `ARN` con el siguiente comando:

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/06/01]
└─$ jq '.Records[] | select(.userIdentity.userName == "cloud-ops-intern") | "\(.userIdentity.arn)"' *.json | uniq -c
     43 "arn:aws:iam::670756667180:user/cloud-ops-intern"
```

---------

**2\.**
