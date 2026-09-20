
Scenario:

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



----------

*

Submit Task
Task 6

Hint
What was the first region the attacker attempted to create the instances in?

******-*****-*

Submit Task
Task 7

Hint
Were any of the instances created? (Yes/No)

