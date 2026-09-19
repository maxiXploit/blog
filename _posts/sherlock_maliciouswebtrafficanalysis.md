


**Scenario:** During a cybersecurity investigation, analysts have noticed unusual traffic patterns that may indicate a problem. We need your help finding out what's happening, so give us all the details.

Para este laboratorio nos dan una captura de red, por lo que podemos pasar rápido a las preguntas analizando con wireshark y tshark.

------------

**1\. What is the IP address of the web server?**

Podemos filtrar por http:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/maliciouswebtrafficanalysis]
└─$ tshark -r capture.pcap -Y "http and ip.addr == 197.32.212.121" -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn 
    221 197.32.212.121  10.1.0.4
    206 10.1.0.4        197.32.212.121
```

Vemos comunicación con una IP privada `197.32.212.121 -> 10.1.0.4` 

-----------------

**2\. What is the IP address of the attacker?**

Podemos revisar primeramente un intento de escaneo:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/maliciouswebtrafficanalysis]
└─$ tshark -r capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn 
    814 10.1.0.4        168.63.129.16
    176 197.32.212.121  10.1.0.4
     40 196.129.183.118 10.1.0.4
     29 62.114.220.119  10.1.0.4
     24 51.77.116.35    10.1.0.4
     18 10.1.0.4        169.254.169.254
      2 5.135.90.165    10.1.0.4
      1 78.153.140.178  10.1.0.4
```

Las IPs `168.63.129.16` y `169.254.169.254` son de microsoft(azure), el mejor candidato sería `197.32.212.121`, podemos confirmarlo viendo el protocolo HTTP como hicimos en la pregunta anterior:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/maliciouswebtrafficanalysis]
└─$ tshark -r capture.pcap -Y "http and ip.addr == 197.32.212.121" | awk -F' ' '{print $9, $10}'| sort | uniq -c | sort -rn 
    206 POST /login.php
    201 HTTP/1.1 200
<SNIP>
```

Vemos una cantidad considerable de peticiones `POST` al sitio web, lo que sugiere un intento de ataque de fuerza bruta.

--------

**3\. The attacker first tried to sign up on the website, however, he found a vulnerability that he could read the source code with. What is the name of the vulnerability?**



----------

There was a note in the source code, what is it?

********

Submit Task
Task 5

Hint
After exploiting the previous vulnerability, the attacker got a hint about a possible username. What is the username that the attacker found?

*****

Submit Task
Task 6

Hint
The attacker tried to brute-force the password of the possible username that he found. What is the password of that user?

********

Submit Task
Task 7

Hint
Once the attacker gained admin access, they exploited another vulnerability that led the attacker to read internal files that were located on the server. Which file did they read? (answer without path)

******

Submit Task
Task 8

Hint
The attacker was able to view all the users on the server. What is the last user that was created on the server?

********

Submit Task
Task 9

Hint
The attacker also found an open redirect vulnerability. What is the URL the attacker tested the exploit with?
