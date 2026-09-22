
Todos los show pùblicos son actos polìticos


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

How many privileged commands did the user run?

**

Submit Task
Task 8

Hint
What is the last thing the user searches for in the installed browser?

*** ** ***** * ****** ** ********* ******* ** ** ****

Submit Task
Task 9

Hint
From Q8 we know that the user tried to write a script, what is the script name that the user wrote?

******************.**

Submit Task
Task 10

Hint
What is the URL that the user uses to download the malware?

*****://****.**/************

Submit Task
Task 11

Hint
What is the name of the malware that the user tried to download?

*****

Submit Task
Task 12

Hint
What is the IP address associated with the domain that the user pinged?

***.***.***.***

Submit Task
Task 13

Hint
What is the password hash of the "hackerman" user?

