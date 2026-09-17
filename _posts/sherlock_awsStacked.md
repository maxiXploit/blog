

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

Revisamos la suencuencia de acciones que realizó la cuenta comprometida:

```bash

```

**1\. What is the ARN of the compromised identity?**



