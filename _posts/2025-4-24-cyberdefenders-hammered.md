---
layout: single
title: Cyberdefenders - Hammered
excerpt: Laboratorio en el que se nos proporcionan un montón de logs de un honeypot. 
date: 2025-05-24
classes: wide
header:
  teaser: ../assets/images/sherlock-bumbleebe/
  teaser_home_page: true
  icon: ../assets/images/logo-icon.svg
categories:
   - cyberdefenders
   - DFIR
   - endpoint forensics
   - linux
tags:
   - grep 
   - bash
---

Para este laboratorio se nos proporciona una gran cantidad de logs:

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ ls
apache2  apt  auth.log  daemon.log  debug  dmesg  dmesg.0  dpkg.log  fontconfig.log  fsck  kern.log  messages  secure  udev  user.log
```

Asi que podemos pasar rápidamete a las preguntas: 

---

<h3 style="color: #0d6efd;">Q1. Which service did the attackers use to gain access to the system? </h3>

Para esto podemos pensar principalmente en el servicio de `ssh`, usado para administrar servidores de forma remota, y también objetivo principal de los atacantes para acceder a la red de una organización. 

Revisamos el `auth.log` para ver cuantos intentos de inicio de sesión tenemos. 

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep "Accepted password" auth.log | wc -l
118

┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep "Failed password" auth.log | wc -l
20338
```

Vemos bastantes fallos de autenticación, lo que nos da una pista de un ataque de fuerza bruta. 

---

<h3 style="color: #0d6efd;">Q2. What is the operating system version of the targeted system? </h3>

Esto podemos verlo en el `kern.log`: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ head -n 10 kern.log
Mar 16 08:09:58 app-1 kernel: Inspecting /boot/System.map-2.6.24-26-server
Mar 16 08:09:58 app-1 kernel: Loaded 28787 symbols from /boot/System.map-2.6.24-26-server.
Mar 16 08:09:58 app-1 kernel: Symbols match kernel version 2.6.24.
Mar 16 08:09:58 app-1 kernel: Loaded 14773 symbols from 62 modules.
Mar 16 08:09:58 app-1 kernel: [    0.000000] Initializing cgroup subsys cpuset
Mar 16 08:09:58 app-1 kernel: [    0.000000] Initializing cgroup subsys cpu
Mar 16 08:09:58 app-1 kernel: [    0.000000] Linux version 2.6.24-26-server (buildd@crested) (gcc version 4.2.4 (Ubuntu 4.2.4-1ubuntu3)) #1 SMP Tue Dec 1 18:26:43 UTC 2009 (Ubuntu 2.6.24-26.64-server)
Mar 16 08:09:58 app-1 kernel: [    0.000000] Command line: root=UUID=a691743a-a4b7-482d-95ff-406e5acd83a3 ro quiet splash
Mar 16 08:09:58 app-1 kernel: [    0.000000] BIOS-provided physical RAM map:
Mar 16 08:09:58 app-1 kernel: [    0.000000]  BIOS-e820: 0000000000000000 - 000000000009f800 (usable)
```

También podemos encontrarlo en otras rutas alternativas: 

/etc/os-release: Contiene datos de identificación del sistema operativo en un formato estructurado, utilizado en las distribuciones Linux modernas.

/etc/lsb-release: Se encuentra en las distribuciones basadas en Debian (como Ubuntu) y proporciona detalles adicionales sobre la versión.

/etc/redhat-release: Específico de las distribuciones basadas en Red Hat, como CentOS y Fedora.

/etc/issue: Muestra la versión del sistema operativo y se utiliza a menudo para la identificación del sistema en el inicio de sesión.

/proc/version: Contiene detalles de la versión del kernel junto con el compilador utilizado para construirlo.

/var/log/dmesg: Registra los mensajes de arranque, que a menudo incluyen información sobre el sistema operativo y el núcleo.

/boot/grub/grub.cfg: A veces contiene detalles de la versión del SO, particularmente para configuraciones relacionadas con el gestor de arranque.



---

<h3 style="color: #0d6efd;">Q3. What is the name of the compromised account? </h3>

Bien, sabemos que se trata de un ataque de fuerza bruta, asi que vamos a ver los usuarios con los que más se intentó acceder: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep "Failed password" auth.log | awk '{print $9}' | sort | uniq -c
     29 backup
     11 bin
     11 daemon
      1 Debian-exim
      2 dhcp
      1 dhg
     35 games
      8 gnats
  14481 invalid
     15 irc
      1 klog
      1 libuuid
     11 list
     23 lp
     27 mail
     14 man
     44 mysql
     22 news
     25 nobody
      4 ntp
     12 proxy
   5479 root
     23 sshd
     12 sync
      9 sys
      1 syslog
      3 user1
      4 user2
      2 user3
     11 uucp
     16 www-data
```

Podemos lograrlo con lo siguiente: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep "Failed password" auth.log | awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' | sort | uniq -c
```

2. **`awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}'`**

   * `NF` es el número de campos (palabras) de la línea, separados por espacios.
   * El bucle `for(i=1;i<=NF;i++)` recorre todos los campos.
   * `if($i=="for")` comprueba si el campo actual es la palabra `for`.
   * `print $(i+1)` imprime el campo justo después de `for`.

    ```bash 
    Apr 26 08:51:44 app-1 sshd[23542]: Failed password for root from 188.131.23.37 port 4280 ssh2
    ```

También podemos verlo con lo siguiente, pero sería engañoso, pues podríamos tener otro intento fallido de inició de sesión con un usuario diferente 

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep "Failed password" auth.log | tail -n 1
Apr 26 08:51:44 app-1 sshd[23542]: Failed password for root from 188.131.23.37 port 4280 ssh2
```


---

<h3 style="color: #0d6efd;">Q4. How many attackers, represented by unique IP addresses, were able to successfully access the system after initial failed attempts? </h3>

Para esto podeos obtener las ip que aparecen tanto en los intentos de login como las ip que aparecen en fallos de login:

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ comm -12 <(grep "Accepted password for root" auth.log | awk '{print $11}' | sort | uniq ) <(grep "Failed password for root" auth.log | awk '{print $11}' | sort | uniq)
10.0.1.2
121.11.66.70
122.226.202.12
188.131.23.37
219.150.161.20
222.169.224.197
222.66.204.246
61.168.227.12
94.52.185.9
```

> Se puede hacer también de la siguiente forma: 
> comm -12 <(grep "Failed password for root" auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq) \
>         <(grep "Accepted password for root" auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq)

Ahora tenemos que quitar aquellas ip que pertenezcan al rango de loopback y las ip que se asignan como ip's privadas: 10.0.0.0 — 10.255.255.255, 172.16.0.0 — 172.31.255.255, 192.168.0.0 — 192.168.255.255


Con esto ya podemos comparar las ip resultantes con aquellas que aparecen muchas veces en fallos de login, veremos que solo las siguientes ip aparecen más de 100 veces: 

121.11.66.70
122.226.202.12
219.150.161.20
222.169.224.197
222.66.204.246
61.168.227.12

---

<h3 style="color: #0d6efd;">Q5. Which attacker's IP address successfully logged into the system the most number of times? </h3>


Para esto solo tenemos que comparar las ip que ya sabemos que pertenecen a los atacantes con las ip que accedieron exitosamente al sistema, la que buscamos es la que más veces aparece. 

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ comm -12 <(grep "Failed password for root" auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq) \
         <(grep "Accepted password for root" auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq)
10.0.1.2
121.11.66.70
122.226.202.12
188.131.23.37
219.150.161.20
222.169.224.197
222.66.204.246
61.168.227.12
94.52.185.9

┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep "Accepted password for root" auth.log | awk '{print $11}' | sort | uniq -c
      1 10.0.1.2
      2 121.11.66.70
      2 122.226.202.12
      1 151.81.204.141
      1 151.81.205.100
      1 151.82.3.201
      1 188.131.22.69
      4 188.131.23.37
      3 190.166.87.164
      1 190.167.70.87
      1 190.167.74.184
      1 193.1.186.197
      1 201.229.176.217
      4 219.150.161.20
      1 222.169.224.197
      1 222.66.204.246
      1 61.168.227.12
      1 94.52.185.9
```

---

<h3 style="color: #0d6efd;">Q6. How many requests were sent to the Apache Server? </h3>

Para esto simplemente aplicamos el siguient comando:

```bash
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ wc -l apache2/www-access.log
365 apache2/www-access.log
```

Ya que es en este fichero donde se registran todas las peticiones al servidor, un apache en este caso. 

----

<h3 style="color: #0d6efd;">Q7. How many rules have been added to the firewall? </h3>

Para esto podemos aplicar el siguiente filtro: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep -iE "ufw|iptables" auth.log
Apr 15 12:49:09 app-1 sudo:   user1 : TTY=pts/0 ; PWD=/opt/software/web/app ; USER=root ; COMMAND=/usr/bin/tee ../templates/proxy/iptables.conf
Apr 15 15:06:13 app-1 sudo:   user1 : TTY=pts/1 ; PWD=/opt/software/web/app ; USER=root ; COMMAND=/usr/bin/tee ../templates/proxy/iptables.conf
Apr 15 15:17:45 app-1 sudo:   user1 : TTY=pts/1 ; PWD=/opt/software/web/app ; USER=root ; COMMAND=/usr/bin/tee ../templates/proxy/iptables.conf
Apr 15 15:18:23 app-1 sudo:   user1 : TTY=pts/1 ; PWD=/opt/software/web/app ; USER=root ; COMMAND=/usr/bin/tee ../templates/proxy/iptables.conf
Apr 20 06:51:38 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 113/Identd
Apr 20 06:52:06 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 113/identd
Apr 20 06:52:15 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 113
Apr 20 06:52:26 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 53
Apr 20 06:54:56 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/etc/init.d/ufw restart
Apr 20 06:56:37 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw status
Apr 20 06:57:03 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw enable
Apr 20 06:57:10 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw status
Apr 20 06:57:22 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/etc/init.d/ufw restart
Apr 20 06:58:19 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 0303 telnet
Apr 20 06:58:42 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 22
Apr 20 06:58:57 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 53
Apr 20 06:59:02 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 113
Apr 20 06:59:40 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/etc/init.d/ufw restart
Apr 20 06:59:46 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw status
Apr 20 07:00:30 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw disable
Apr 20 07:06:11 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 2685/tcp
Apr 20 07:06:22 app-1 sudo:     root : TTY=pts/2 ; PWD=/home/dhg/eggdrop ; USER=root ; COMMAND=/usr/sbin/ufw allow 2685/telnet
Apr 24 19:25:37 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/sbin/iptables -L
Apr 24 19:47:48 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/usr/sbin/ufw allow 53
Apr 24 19:47:56 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/usr/sbin/ufw allow 113
Apr 24 19:48:10 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/usr/sbin/ufw disable
Apr 24 19:48:21 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/usr/sbin/ufw enable
Apr 24 19:50:26 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/usr/sbin/ufw disable
Apr 24 20:03:06 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/sbin/iptables -A INPUT -p ssh -dport 2424 -j ACCEPT
Apr 24 20:03:44 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/sbin/iptables -A INPUT -p tcp -dport 53 -j ACCEPT
Apr 24 20:04:13 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/sbin/iptables -A INPUT -p udp -dport 53 -j ACCEPT
Apr 24 20:06:22 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/sbin/iptables -A INPUT -p tcp --dport ssh -j ACCEPT
Apr 24 20:11:00 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/sbin/iptables -A INPUT -p tcp --dport 53 -j ACCEPT
Apr 24 20:11:08 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/sbin/iptables -A INPUT -p tcp --dport 113 -j ACCEPT
Apr 24 20:17:39 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/usr/sbin/ufw disable
Apr 24 20:18:09 app-1 sudo:     root : TTY=pts/2 ; PWD=/etc ; USER=root ; COMMAND=/usr/sbin/ufw enable
```

Vemos que se agregan varias reglas (-A) con iptables. 

---

<h3 style="color: #0d6efd;">Q8. One of the downloaded files on the target system is a scanning tool. What is the name of the tool? </h3>

Para esto podemos filtrar por la cadena "Setting up" en el fichero "apt/term.log", que es la línea que aparece entre los registro de una instalación, que se escriben en el `term.log`

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep "Setting up" apt/term.log | awk '{print $3}' | sort | uniq
<SNIP>
make
nmap
po-debconf
python-celementtree
python-dateutil
python-elementtree
python-libxml2
python-rpm
python-tz
python-urlgrabber
rpm
shared-mime-info
sudo
tcl8.4
tcl8.5
tcl8.5-dev
tk8.4
tzdata
x11-apps
x11-common
x11-session-utils
x11-utils
x11-xfs-utils
x11-xkb-utils
x11-xserver-utils
xauth
xbase-clients
xinit
yum
```

Podemos ver un escaner de red bastante conocido. 

---

<h3 style="color: #0d6efd;">When was the last login from the attacker with IP 219.150.161.20? Format: MM/DD/YYYY HH:MM:SS AM </h3>

Podemos verlo de las siguientes formas: 

```bash
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep "Accepted password" auth.log | grep "219.150.161.20"
Apr 19 05:41:44 app-1 sshd[8810]: Accepted password for root from 219.150.161.20 port 51249 ssh2
Apr 19 05:42:27 app-1 sshd[9031]: Accepted password for root from 219.150.161.20 port 40877 ssh2
Apr 19 05:55:20 app-1 sshd[12996]: Accepted password for root from 219.150.161.20 port 55545 ssh2
Apr 19 05:56:05 app-1 sshd[13218]: Accepted password for root from 219.150.161.20 port 36585 ssh2

┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep -E "Accepted password.*219.150.161.20" auth.log
Apr 19 05:41:44 app-1 sshd[8810]: Accepted password for root from 219.150.161.20 port 51249 ssh2
Apr 19 05:42:27 app-1 sshd[9031]: Accepted password for root from 219.150.161.20 port 40877 ssh2
Apr 19 05:55:20 app-1 sshd[12996]: Accepted password for root from 219.150.161.20 port 55545 ssh2
Apr 19 05:56:05 app-1 sshd[13218]: Accepted password for root from 219.150.161.20 port 36585 ssh2
```

Para obtener el año: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ ll auth.log
-rw-r----- 1 kali kali 10327345 Jul  3  2010 auth.log
```

---

<h3 style="color: #0d6efd;">Q10. The database showed two warning messages. Please provide the most critical and potentially dangerous one. </h3>


Para esto aplicamos el siguiente filtro: 

```bash
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep -r -i  "warning" *
apt/term.log:/var/lib/python-support/python2.5/yum/__init__.py:1129: Warning: 'with' will become a reserved keyword in Python 2.6
apt/term.log:/var/lib/python-support/python2.5/yum/depsolve.py:73: Warning: 'with' will become a reserved keyword in Python 2.6
apt/term.log:/var/lib/python-support/python2.5/yum/repos.py:236: Warning: 'with' will become a reserved keyword in Python 2.6
apt/term.log:/var/lib/python-support/python2.5/yum/repos.py:260: Warning: 'with' will become a reserved keyword in Python 2.6
apt/term.log:/var/lib/python-support/python2.5/yum/repos.py:263: Warning: 'with' will become a reserved keyword in Python 2.6
apt/term.log:/usr/share/yum-cli/cli.py:614: Warning: 'with' will become a reserved keyword in Python 2.6
apt/term.log:/usr/share/yum-cli/cli.py:615: Warning: 'with' will become a reserved keyword in Python 2.6
apt/term.log:/usr/share/yum-cli/cli.py:616: Warning: 'with' will become a reserved keyword in Python 2.6
daemon.log:Mar 18 10:18:42 app-1 /etc/mysql/debian-start[7566]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Mar 18 17:01:44 app-1 /etc/mysql/debian-start[14717]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Mar 22 13:49:49 app-1 /etc/mysql/debian-start[5599]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Mar 22 18:43:41 app-1 /etc/mysql/debian-start[4755]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Mar 22 18:45:25 app-1 /etc/mysql/debian-start[4749]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Mar 25 11:56:53 app-1 /etc/mysql/debian-start[4848]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Apr 14 14:44:34 app-1 /etc/mysql/debian-start[5369]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Apr 14 14:44:36 app-1 /etc/mysql/debian-start[5624]: WARNING: mysqlcheck has found corrupt tables
daemon.log:Apr 18 18:04:00 app-1 /etc/mysql/debian-start[4647]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Apr 24 20:20:52 app-1 collectdmon[4971]: Warning: collectd was terminated by signal 11
daemon.log:Apr 24 20:21:24 app-1 /etc/mysql/debian-start[5427]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Apr 28 07:34:26 app-1 /etc/mysql/debian-start[4782]: WARNING: mysql.user contains 2 root accounts without password!
daemon.log:Apr 28 07:34:27 app-1 /etc/mysql/debian-start[5032]: WARNING: mysqlcheck has found corrupt tables
daemon.log:Apr 28 07:34:27 app-1 /etc/mysql/debian-start[5032]: warning  : 1 client is using or hasn't closed the table properly
daemon.log:Apr 28 07:34:27 app-1 /etc/mysql/debian-start[5032]: warning  : 1 client is using or hasn't closed the table properly
daemon.log:Apr 28 09:35:31 app-1 collectdmon[5119]: Warning: collectd was terminated by signal 11
daemon.log:May  2 23:05:54 app-1 /etc/mysql/debian-start[4774]: WARNING: mysql.user contains 2 root accounts without password!
```

```bash 
WARNING: mysql.user contains 2 root accounts without password!
```

Tener cuentas root en la tabla mysql.user sin contraseña supone un hueco de seguridad grave, cualquiera podría conectarse como administrador de la base de datos sin necesidad de credenciales. 

---

<h3 style="color: #0d6efd;">Q11. Se crearon varias cuentas en el sistema de destino. ¿Qué cuenta se creó el 26 de abril a las 04:43:15? </h3>

Para esto podemos aplicar el sigiente comando:
```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$ grep "useradd" auth.log
Mar 16 08:12:13 app-1 useradd[4692]: new user: name=user4, UID=1001, GID=1001, home=/home/user4, shell=/bin/bash
Mar 16 08:12:38 app-1 useradd[4703]: new user: name=user1, UID=1001, GID=1001, home=/home/user1, shell=/bin/bash
Mar 16 08:12:55 app-1 useradd[4711]: new user: name=user2, UID=1002, GID=1002, home=/home/user2, shell=/bin/bash
Mar 16 08:25:22 app-1 useradd[4845]: new user: name=sshd, UID=104, GID=65534, home=/var/run/sshd, shell=/usr/sbin/nologin
Mar 18 10:15:42 app-1 useradd[5393]: new user: name=Debian-exim, UID=105, GID=114, home=/var/spool/exim4, shell=/bin/false
Mar 18 10:18:26 app-1 useradd[6966]: new user: name=mysql, UID=106, GID=115, home=/var/lib/mysql, shell=/bin/false
Apr 19 22:38:00 app-1 useradd[2019]: new user: name=packet, UID=0, GID=0, home=/home/packet, shell=/bin/sh
Apr 19 22:45:13 app-1 useradd[2053]: new user: name=dhg, UID=1003, GID=1003, home=/home/dhg, shell=/bin/bash
Apr 24 19:27:35 app-1 useradd[1386]: new user: name=messagebus, UID=108, GID=117, home=/var/run/dbus, shell=/bin/false
Apr 25 10:41:44 app-1 useradd[9596]: new group: name=fido, GID=1004
Apr 25 10:41:44 app-1 useradd[9596]: new user: name=fido, UID=0, GID=1004, home=/home/fido, shell=/bin/sh
Apr 26 04:43:15 app-1 useradd[20115]: new user: name=wind3str0y, UID=1004, GID=1005, home=/home/wind3str0y, shell=/bin/bash
```

---

<h3 style="color: #0d6efd;">Q12. Few attackers were using a proxy to run their scans. What is the corresponding user-agent used by this proxy?  </h3>

Para esto podemos aplicar el siguiente comando: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/ham/temp_extract_dir/Hammered]
└─$  awk '{print $1, substr($0, index($0, $12))}' apache2/www-access.log | grep -v -i -E "mozilla|apple|wordpress"
193.109.122.56 "pxyscand/2.1" oFs91QoAAQ4AAAQFlmcAAAAL 1213441
193.109.122.33 "-" "-" - 29798270
221.194.47.162 "-" "-" K0KW9woAAQ4AAARf79sAAAAJ 10111672
193.109.122.57 "pxyscand/2.1" 1l730AoAAQ4AACkeBjsAAAAB 156351
193.109.122.18 "-" "-" - 29802301
92.62.43.77 "-" "-" -Pu0pQoAAQ4AAEHDCQ8AAAAA 240388
92.62.43.77 "-" "-" DtkzRwoAAQ4AAEHHC2YAAAAE 539228
92.62.43.77 "-" "-" ILrYnwoAAQ4AAEHNCxoAAAAG 241728
92.62.43.77 "-" "-" MqFlkwoAAQ4AAEHMCyAAAAAF 690255
193.109.122.52 "pxyscand/2.1" 54ydwAoAAQ4AAEHECacAAAAB 571386
193.109.122.15 "-" "-" - 29801077
```
- substr($0, index($0, $12)):
- $0 es la línea entera.
- index($0, $12) busca en la línea completa ($0) la posición donde empieza el contenido del campo 12 ($12).
- substr($0, POS) toma la subcadena de $0 desde esa posición POS hasta el final.

En los logs de Apache el User-Agent suele estar compuesto de varios campos (porque lleva espacios), y normalmente empieza alrededor del campo 12. Con este truco recuperas todo el User-Agent completo, no sólo la primera “palabra”.

El patrón "mozill|apple|wordpress" coincidirá con la mayoría de navegadores (Mozilla/Chrome/WebKit, Safari de Apple) y con rastreadores basados en WordPress, eliminaos todas esas visitas “comunes” y nos quedamos sólo con las IPs y agentes menos frecuentes (posiblemente bots o clientes inusuales).

Finalmente vemos `pxyscand`, que es un escáner de proxies de la red IRC (PXYS – IRC(u) Network ProxyScanner) que se presenta en los logs como agente de usuario “pxyscand/2.1”. Básicamente:

* Busca servidores proxy abiertos en Internet, probando puertos (por ejemplo mediante peticiones HTTP CONNECT) para luego reportar o aprovecharlos como intermediarios anónimos.
* Es parte del proyecto PXYS, diseñado para mapear proxies vulnerables desde la red IRC. Se identifica en los encabezados HTTP como `User-Agent: pxyscand/2.1
* Quien lo emplea normalmente quiere recolectar proxies para ocultar su verdadera IP en futuros ataques o para lanzar escaneos masivos de forma anónima.


