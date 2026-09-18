

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

**2\.What AWS service was used to deploy malicious resources into the environment?**

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

**Revisando el evento de CreateStack:**

```txt
 "requestParameters": {                                                                                                    "stackName": "CryptoBaby",                                                                                              "parameters": [],                                                                                                       "disableRollback": false,                                                                                               "notificationARNs": [],                                                                                                 "capabilities": [                                                                                                         "CAPABILITY_NAMED_IAM"                                                                                                ],                                                                                                                      "tags": [] 
```

El nombre del stack es bastante descriptivo, el patrón que ya vimmos de `CreateUser, `SecurityGroup` abierto, 3x `RunInstances` huele bastante a Cryptojacking. El atacante desplegó intancias EC2(probablmente tipos grandes/GPU) para minar criptomonedas a costa de las cuentas de la víctima. Es uno de los abusos más comunes cuando se comprometen credenciales AWS.
 
--------

**3\. How many malicious compute resources were deployed?**

Esto ya lo vimos en los evenentos anteriores:

```bash
01:11:18Z  RunInstances  ec2.amazonaws.com
01:11:18Z  RunInstances  ec2.amazonaws.com
01:11:19Z  RunInstances  ec2.amazonaws.com
```

Tres eventos `RunInstances` dentro de la misma ventana de 1 segundo disparado por el mismo `CreateStack` de CloudFormation.

Pero el conteo de eventos no siempre es 1:1 con el conteo de instancias, para confirmar el número real necesitamos ver el `responseElements.instancesSet.items[]` de cada evento RunInstances (ahí lista cada `instanceId` individual creado por esa llamada).

Usamos el siguiente comando: 

```bash
jq -r '.Records[] | select(.eventName=="RunInstances") | .responseElements.instancesSet.items[]?.instanceId' *.json

"i-0126a710605884935"
"i-0df2ed2942dfdd11b"  
```

Ahora solo vemos 2 instancias, para confirmar que hubo un error hacemos: 

```bash
 jq -r '.Records[] | select(.eventName=="RunInstances") | {time: .eventTime, error: .errorCode, errorMsg: .errorMessage, count: ((.responseElements.instancesSet.items // [])|length)}'

{                                                                                                                         "time": "2023-06-01T01:11:19Z",                                                                                         "error": null,                                                                                                          "errorMsg": null,                                                                                                       "count": 1                                                                                                            }
{                                                                                                                         "time": "2023-06-01T01:11:18Z",                                                                                         "error": "Server.InternalError",                                                                                        "errorMsg": "An internal error has occurred",                                                                           "count": 0                                                                                                            }
{                                                                                                                         "time": "2023-06-01T01:11:18Z",                                                                                         "error": null,                                                                                                          "errorMsg": null,                                                                                                       "count": 1                                                                                                            }
```

Confirmando el error del servidor.

-----------------

**4\. What is the instance type observed for these resources?**

Usamos el siguiente comando: 

```bash

```

Esta es una familia de instancias optimizadas para cómputo(Compute-optimized) de AWS, basada en procesadores Intel Xeon Scalable. La `c5.large`

- 2vCPUs
- 4 GB de RAM
- Red hasta 10 Gbps(compartida)

Esta familia prioriza poder de CPU por dólar sobre memoria o storage, esto combinado con `CryptoBaby` es una combinación clásica de **cryptojacking**.
El atacante priorizó CPU dedicada sobre otros recursos y el uso de múltiples instancias de tamaño moderado en vez de una sola instancia grande sugiere un intento de evadir detección basada en anomalías de costo.

-----------

**5\.What IP CIDR Range did the malicious security group allow for inbound access?**

Para esto buscamos en el siguiente evento: 

```bash
┌──(kali㉿kali)-[~/…/us-east-1/2023/06/01]
└─$ jq '.Records[] | select(.eventName == "AuthorizeSecurityGroupIngress") ' *.json
<SNIP>
 "requestParameters": {
    "groupId": "sg-02b01de056a809eda",
    "ipPermissions": {
      "items": [
        {
          "ipProtocol": "tcp",
          "fromPort": 22,
          "toPort": 22,
          "groups": {},
          "ipRanges": {
            "items": [
              {
                "cidrIp": "31.187.69.0/24"
              }
            ]
          },
          "ipv6Ranges": {},
          "prefixListIds": {}
        }
      ]
    }
  },
``` 

---------


What port was allowed for inbound access?


What protocol was allowed for inbound access?



