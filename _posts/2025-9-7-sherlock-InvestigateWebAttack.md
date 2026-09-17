---
layout: single
title: Sherlock - Investigate web attack
excerpt: Ejercicio básico de una investigación de un ataque web.
date: 2026-9-07
classes: wide
header:
   teaser: ../assets/images/socs/logoletsdefend.png
   teaser_home_page: true
   icon: ../assets/images/hacktheweb.webp
categories:
   - hackthebox
   - soc 
   - blue team
tags:
   - linux
   - web attack
   - nikto
   - http
   - grep 
   - awk
---

Scenario:

**We detected some web attacks and need to do deep investigation.**

Para este laboratorio tenemos un unico fichero:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ ls
access.log
```

Asì que pasamos rápido a las preguntas:

-----------

0. Which automated scan tool did attacker use for web reconnaissance?

Para reponder a esto hay que analizar con un enfoque de analista, empezando por las IP's: 

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ awk '{print $1}' access.log | sort | uniq -c 
     29 192.168.199.1
  12528 192.168.199.2
```

Vemos que la IP `192.168.0.199.2` es la que ocupa la mayoría del tráfico.

Ahora tenemos que perfilar los `User-agent`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ awk -F'"' '{print $6}' access.log | sed -E 's/ \(Test:[0-9]+\)//' |sort | uniq -c | sort -rn
   6758 Mozilla/5.00 (Nikto/2.1.6) (Evasions:None)
   4816 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
    234 Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:sitefiles)
    221 Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)
    174 Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
    <SNIP>
```

También podemos usar el siguiente filtro para una visión general de los `User-agent`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ awk -F'"' '{print $6}' access.log |
sed -E 's/ \(Test:[^)]*\)//' |
sort | uniq -c | sort -rn
```

---------

1. After web reconnaissance activity, which technique did attacker use for directory listing discovery?

Ahora que ya tenemos el user agent fijémonos en la firma que usa la herramienta:

`Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`, esta es la firma que manda DIRB--- nadie usa MSIE 6.0, Windows 5.1, un IOC de cabecera.

Con el siguiente filtro podemos ver parte de nuestra respuesta:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ grep 'MSIE 6.0; Windows NT 5.1' access.log | awk -F'"' '{print $2}' | awk -F' ' '{print $2}'
```

En el archivo lo veríamos de la siguiente forma:

```
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.bash_history HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002743)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.forward HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002744)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.history HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002745)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.htaccess HTTP/1.1" 403 303 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002746)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.lynx_cookies HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002747)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.mysql_history HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002748)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.passwd HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002749)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.pinerc HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002750)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.plan HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002751)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.proclog HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002752)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.procmailrc HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002753)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.profile HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002754)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.rhosts HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002755)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.sh_history HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002756)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.ssh HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002757)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.ssh/authorized_keys HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002758)"
192.168.199.2 - - [20/Jun/2021:12:36:40 +0300] "GET /bwapp/.ssh/known_hosts HTTP/1.1" 404 300 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002759)"
1
```

Esto es un `directory brute force`.

Podemos usar los siguientes filtros con awk para practicar:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ awk -F'"' '{print $2}' access.log | awk -F' ' '{print $2}'

                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ awk -F'"' '{split($2,a," "); print a[2]}' access.log

┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ grep 'MSIE 6.0; Windows NT 5.1' access.log | awk -F'"' '{print $2}'  
``` 

-----------

2. What is the third attack type after directory listing discovery?

Para este punto tenemos que entender el ataque de forma cronológica en fases, no en líneas sueltas.
Un analista no busca "el ataque" como evento aislado --- reconstruye la secuencia, ya tenemos lo siguiente:

- Fase 1: reconocimiento(Nikto)
- Fase 2: descubrimiento de directorios(DIRB)

Ahoa lo que buscamos es el siguiente paso en cualquier metodología de pentest(), que es intentar entrar --- Es decir, "el acceso inicial".

Empezamos filtrando y eliminando el ruido del escaneo, eliminando el tráfico generado por las las herramientas para ver los user agent:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ grep -v "MSIE 6.0; Windows NT 5.1" access.log | grep -v "Nikto" | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn | head -20
    174 Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
     74 -
     29 Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0
      5 ./.\\\
      4  
```

Con esto ya nos queda claro: `Se cambió de herramienta, cambió la fase`

Buscando el endopoint que recibe más repetición desde estos `UA`

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ grep "Firefox/52.0" access.log | awk -F'"' '{print $2}' | sort | uniq -c | sort -rn | head                                     
    134 POST /bWAPP/login.php HTTP/1.1
      2 GET /bWAPP/portal.php HTTP/1.1
      2 GET /bWAPP/phpi.php?message=test HTTP/1.1
      2 GET /bWAPP/phpi.php?message=%22%22;%20system(%27net%20user%20hacker%20Asd123!!%20/add%27) HTTP/1.1
      1 POST /bWAPP/portal.php HTTP/1.1
      1 GET /icons/unknown.gif HTTP/1.1
      1 GET /icons/text.gif HTTP/1.1
      1 GET /icons/layout.gif HTTP/1.1
      1 GET /icons/folder.gif HTTP/1.1
      1 GET /icons/blank.gif HTTP/1.1
```

Ahora tenemos que confirmar el patrón de respuesta:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/investigatewebattack]
└─$ grep "POST /bWAPP/login.php" access.log | awk -F'" ' '{print $2}' | awk '{print $1, $2}' | sort | uniq -c 
    132 200 4086
      2 302 -
```

Vemos 132 peticiones con el mismo tamaño de respuesta, hasta que vemos el código HTTP que indica redirección, la prueba de "Fuerza bruta hasta encontrar las llaves correctas" 

-------------

3. Is the third attack successful?

Como vimos en la pregunta anterior, el código de redirección nos indica que el atacante logró acceder al sitio: 

```bash
192.168.199.2 - - [20/Jun/2021:12:49:35 +0300] "POST /bWAPP/login.php HTTP/1.1" 302 - "http://192.168.199.5/bWAPP/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.199.2 - - [20/Jun/2021:12:50:10 +0300] "POST /bWAPP/login.php HTTP/1.1" 302 - "http://192.168.199.5/bWAPP/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.199.2 - - [20/Jun/2021:12:50:10 +0300] "GET /bWAPP/portal.php HTTP/1.1" 200 23369 "http://192.168.199.5/bWAPP/login.php" "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.199.2 - - [20/Jun/2021:12:50:15 +0300] "POST /bWAPP/portal.php HTTP/1.1" 302 23369 "http://192.168.199.5/bWAPP/portal.php" "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"
```

---------------

4. What is the name of fourth attack?

El cuarto ataque se trata de un `Code injection`: 

- 1. Una vez ya autenticado, el atacante abre el módulo vulnerable: `192.168.199.2 - - [20/Jun/2021:12:50:15 +0300] "GET /bWAPP/phpi.php HTTP/1.1" 200 12735 "http://192.168.199.5/bWAPP/portal.php" "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"
`
- 2. Con `GET /bWAPP/phpi.php?message=test HTTP/1.1" 200 12759 "http://192.168.199.5/bWAPP/phpi.php"` prueba el parámetro `message` con un valor inofensivo para ir tanteando el terreno, recibiendo una respuesta positiva(HTTP 200) .

- 3. Luego pasa a la carga real: 

    ```bash
    ?message=";  system('whoami')
    ?message=";  system('net user')
    ?message=";  system('net share')
    ?message=";  system('net user hacker Asd123!! /add')
    ```

    Obteniendo un tamaño de respuesta diferente.

------------

5. What is the first payload for 4th attack?

Revisando los logs podemos ver que el primer comando que se manda es `whoami`:

```bash
192.168.199.2 - - [20/Jun/2021:12:52:36 +0300] "GET /bWAPP/phpi.php?message=%22%22;%20system(%27whoami%27) HTTP/1.1" 200 12778 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"
```

---------

6. Is there any persistency clue for the victim machine in the log file ? If yes, what is the related payload?

En los últimos logs podemos apreciar: 

```bash
phpi.php?message=%22%22;%20system(%27net%20user%20hacker%20Asd123!!%20/add%27) 
```

Que decodificado es `net user hacker Asd123!! /add`, que se encarga de crear un nuevo usuario especificando la contraseña del mismo.


