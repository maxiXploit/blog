

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

**2\. How many malicious compute resources were deployed?**

Con el filtro `jq '.Records[] | select(.userIdentity.userName == "cloud-ops-intern") | "\(.userIdentity.arn)"' *.json | uniq -c` veremos la sigiente secuencia de eventos:

```txt
01:09:19  GetTemplateSummary       cloudformation.amazonaws.com
01:11:05  CreateStack              cloudformation.amazonaws.com
01:11:08  CreateUser               iam.amazonaws.com
01:11:09  CreateSecurityGroup      ec2.amazonaws.com
01:11:14  AuthorizeSecurityGroupEgress/Ingress   ec2.amazonaws.com
01:11:18  RunInstances (x3)        ec2.amazonaws.com
01:11:44  PutUserPolicy            iam.amazonaws.com
```

Tenemos el siguiente patrón:

- Hay reconocimiento de CloudFormation(`ListStacks`, `DescribeStacksEvents` repetidos, clara actividad de reconociiento)
- Luego `GetTemplateSummary`, para revisar qué es lo que hace un template antes de lanzarlo, para desspués hacer `CreateStack`

Y segundos después de ese CreateStack, aparecen en cascada: creación de usuario IAM, security group, reglas de ingress/egress, y 3 instancias EC2, todo esto dentro de un margen de ~40 segundos y bajo la misma sesión. Esto no es alguien ejecutando comandos manuales uno por uno; es el comportamiento típico de una stack de CloudFormation desplegando recursos definidos en su template.

Por lo que la respuesta es: AWS CloudFormation, un servicio que es básicamente Infrastructure as Code (IaC) de AWS, donde le das una plantilla (JSON o YAML) que describe qué recursos se quiere, y el servicio se encarga de crear, actualizar o borrar todo eso por el usuario, en el orden correcto y respetando las dependencias entre recursos.

--------
