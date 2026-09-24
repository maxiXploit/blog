
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



-----------

What storage bucket was enumerated?

***************

Submit Task
Task 7

Hint
What API call was used to exfiltrate an item from this bucket?

*******.*******.***

Submit Task
Task 8

Hint
Which Google Cloud command-line tool was used during the exfiltration attempt?

******

Submit Task
Task 9

Hint
What is the name of the file that was exfiltrated from the storage bucket?
