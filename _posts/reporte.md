

Scenario

Can you analyze logs from an attempted RDP bruteforce attack?

One of our system administrators identified a large number of Audit Failure events in the Windows Security Event log.

There are a number of different ways to approach the analysis of these logs! Consider the suggested tools, but there are many others out there!

-----

Question 1) How many Audit Failure events are there

Para esto podemos usar el siguiente comando: 

```bash 
┌──(kali㉿kali)-[~/challenges/brute]
└─$ grep -i "4625" BTLO_Bruteforce_Challenge.txt | wc -l
3104
```

Eliminando la línea vacial del final, nos da un total de 3103. 

------

Question 2) What is the username of the local account that is being targeted?

Para esto podemos usar el siguiente commando:

```bash
┌──(kali㉿kali)-[~/challenges/brute]
└─$ cat BTLO_Bruteforce_Challenge.txt | grep -iE "account name" | sort | uniq -c
   3103         Account Name:           -
   3103         Account Name:           administrator
      9         Account Name:           BTLO
     13         Account Name:           EC2AMAZ-UUEMPAU$
      8         Account Name:           SYSTEM
      4         Network Account Name:   -
```

------

Question 3) What is the failure reason related to the Audit Failure logs?

Podemos verlo con el siguiente comando: 

```bash 
┌──(kali㉿kali)-[~/challenges/brute]
└─$ grep -i "4625" BTLO_Bruteforce_Challenge.txt | tail
Audit Failure   2/12/2022 6:26:52 AM    Microsoft-Windows-Security-Auditing     4625    Logon   "An account failed to log on.
Audit Failure   2/12/2022 6:26:51 AM    Microsoft-Windows-Security-Auditing     4625    Logon   "An account failed to log on.
```

----

Question 4) What is the Windows Event ID associated with these logon failures?

Esto lo podemos ver ya en la respuesta de la pregunta anterior. 

El evento 4625 se activa cuando una solicitud de inicio de sesión no se autentica correctamente.

-----

Question 5) What is the source IP conducting this attack?

Aplicamos el siguiente comando para ver las direcciones, usamos una expresión regular para encontrar ips: 

```bash 
┌──(kali㉿kali)-[~/challenges/brute]
└─$  cat BTLO_Bruteforce_Challenge.txt | grep -iE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"  | sort | uniq -c
   3103         Source Network Address: 113.161.192.227
```

El conteo coincide con los intentos que encontramos anteriormente. 

-----

Question 6) What country is this IP address associated with?

Esto podemos verlo facilmente con el comando whois:

```bash 
┌──(kali㉿kali)-[~/challenges/brute]
└─$ whois 113.161.192.227

<SNIP>

% Information related to '113.161.192.0/19AS45899'

route:          113.161.192.0/19
descr:          VietNam Post and Telecom Corporation (VNPT)
descr:          VNPT-AS-AP
country:        VN
origin:         AS45899
remarks:        mailto: nmc.cmip@vnpt.vn
notify:         hm-changed@vnnic.net.vn
mnt-by:         MAINT-VN-VNPT
last-modified:  2018-08-08T09:24:53Z
source:         APNIC
```

-----

Question 7) What is the range of source ports that were used by the attacker to make these login requests? 

Podemos verlo de la siguiente forma: 

```bash 
┌──(kali㉿kali)-[~/challenges/brute]
└─$  cat BTLO_Bruteforce_Challenge.txt | grep -iE "port|source port|sourceport"  | sort | uniq | head
        Source Port:            -
        Source Port:            49162

┌──(kali㉿kali)-[~/challenges/brute]
└─$  cat BTLO_Bruteforce_Challenge.txt | grep -iE "port|source port|sourceport"  | sort | uniq | tail -n 1
        Source Port:            65534
```



