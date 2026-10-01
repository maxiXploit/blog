

**Sherlock Scenario: A suspicious network capture was collected from an internal CCTV environment following reports of abnormal camera behavior. The traffic indicates reconnaissance activity, authentication attempts, and interaction with camera streaming services.**

**The attacker appears to have scanned the network, identified exposed services, and attempted to access camera streams. Shortly after authentication, anomalies were observed in the video stream, including interruptions and stream restarts.**

--------------

Para este laboratorio se nos da una captura de red analizaremos con `wireshark` y `tshark`, así que pasamos rápido a las preguntas.

```bash
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ ls    
CCTV.pcap
```

Así que pasamos rápido a las preguntas.

-----------

**1\. What is the IP address of the attacker performing the reconnaissance activity?**

Aplicando el clásico filtro para detectar escaneos de red:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn 
     17 192.168.50.200  192.168.50.12
      4 192.168.50.200  192.168.50.5
      2 192.168.50.5    192.168.50.12
      1 192.168.50.5    192.168.50.11
      1 192.168.50.100  192.168.50.5
```

Vemos a la IP `192.168.50.200` con patrones de escaneo hacia la `192.168.50.12` y a la `192.168.50.5` 

----------

**2\. Which camera IP address was directly accessed by the attacker using RTSP requests?**

Aplicanco un filtro por la ip por la IP ya identificada y por el protocolo `RTSP`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "ip.addr == 192.168.50.200 and rtsp"                                                                  
54447 696.973114 192.168.50.200 56765 192.168.50.12 554 RTSP 179 DESCRIBE rtsp://192.168.50.12:554/Streaming/Channels/101 RTSP/1.0
54449 696.999937 192.168.50.12 554 192.168.50.200 56765 RTSP 229 Reply: RTSP/1.0 401 Unauthorized

┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "ip.addr == 192.168.50.200 and rtsp" -T fields -e ip.src -e ip.dst 
192.168.50.200  192.168.50.12
192.168.50.12   192.168.50.200
```

------------------

**3\. How many unique destination ports were scanned by the attacker?**

Aplicando el siguiente filtro:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.addr == 192.168.50.200" -T fields -e tcp.dstport | sort | uniq -c
      1 110
      1 139
      1 143
      1 21
      2 22
      1 23
      1 25
      1 3306
      1 443
      1 445
      1 53
      3 554
      3 80
      1 8000
      1 8080
      1 8443
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.addr == 192.168.50.200" -T fields -e tcp.dstport | sort | uniq -c | wc -l
16
```

-------

**4\. Which open port exposed the camera video streaming service during reconnaissance, and what is the name of that service?**

La respuesta es: `554`, `RTSP`

### ¿Qué es RTSP?

**RTSP (Real Time Streaming Protocol)** es un protocolo de capa de aplicación, definido en la **RFC 2326** (v1.0) y actualizado en la **RFC 7826** (v2.0). Funciona como un "control remoto" para flujos multimedia: **no transporta el video o audio**, solo controla la sesión. El contenido viaja por **RTP/RTCP**.

Características:

- **Basado en texto**, con sintaxis muy parecida a HTTP (líneas de petición, cabeceras, códigos de estado como `200 OK`, `401 Unauthorized`, `404 Not Found`).
- **Con estado (stateful)**, a diferencia de HTTP. El servidor mantiene una sesión identificada por la cabecera `Session`.
- Puerto por defecto **554** (TCP/UDP), con **8554** como alternativo frecuente.
- Cada petición lleva un `CSeq` (número de secuencia) que se repite en la respuesta para correlacionarlas.
- Muy común en **cámaras IP, sistemas CCTV y servidores de streaming**, y por eso aparece seguido en contextos de seguridad.

---------------------

**5\. What was the first RTSP request method used by the attacker?**

Con la IP y el protocolo ya identificados, filtramos para ver la conversación: 

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "ip.addr == 192.168.50.200 and rtsp"
54447 696.973114 192.168.50.200 56765 192.168.50.12 554 RTSP 179 DESCRIBE rtsp://192.168.50.12:554/Streaming/Channels/101 RTSP/1.0
54449 696.999937 192.168.50.12 554 192.168.50.200 56765 RTSP 229 Reply: RTSP/1.0 401 Unauthorized
```

Se usa el protocolo `DESCRIBE`, los que tenemos disponibles son:

## Métodos (RFC 2326)

| Método | Función |
|---|---|
| **OPTIONS** | Pregunta al servidor qué métodos soporta (`Public:` en la respuesta). |
| **DESCRIBE** | Obtiene la descripción del recurso multimedia (normalmente en formato SDP). |
| **ANNOUNCE** | Cliente→servidor: informa de una nueva descripción. Servidor→cliente: avisa de cambios en la descripción. |
| **SETUP** | Establece el transporte para un stream (puertos RTP/RTCP, TCP interleaved, etc.) y crea la sesión. |
| **PLAY** | Inicia o reanuda la transmisión de datos. |
| **PAUSE** | Detiene temporalmente el flujo sin destruir la sesión. |
| **RECORD** | Inicia la grabación de un stream hacia el servidor. |
| **TEARDOWN** | Termina la sesión y libera los recursos. |
| **GET_PARAMETER** | Consulta el valor de un parámetro. También se usa como *keep-alive*. |
| **SET_PARAMETER** | Modifica el valor de un parámetro. |
| **REDIRECT** | El servidor indica al cliente que debe conectarse a otro servidor. |

En RTSP 2.0 se eliminó `RECORD` y se agregó `PLAY_NOTIFY`, pero en la práctica casi todo lo que verás sigue usando 1.0.

`DESCRIBE` solicita la **descripción de la presentación**: qué streams contiene (video, audio), qué códecs usa y cómo acceder a cada uno. La respuesta suele venir en **SDP (Session Description Protocol)**.

---------

**6\. At what timestamp did the attacker first attempt to access the camera stream?**

Ahora hay que fijarnos en este protocolo con la IP que ya identificamos:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "ip.addr == 192.168.50.200 and rtsp" -T fields -e frame.time_utc   
2026-03-12T02:31:37.045849000Z
2026-03-12T02:31:37.072672000Z
```

--------

**7\. What response code indicated that authentication was required?**

Con lo que ya vimos en la pregunta 5, la respuesta del servidor fue la siguiente:

```bash
54449 696.999937 192.168.50.12 554 192.168.50.200 56765 RTSP 229 Reply: RTSP/1.0 401 Unauthorized
```

-------

**8\. What authentication mechanism was requested by the camera server?**

Cuando un servidor RTSP responde `401 Unauthorized`, incluye la cabecera `WWW-Authenticate`, que le indica al cliente qué esquema de autenticación debe usar.

## Con tshark

```bash
tshark -r CCTV.pcap -Y "frame.number == 54449" -O rtsp
```

| Esquema | Cómo se ve | Implicación |
|---|---|---|
| **Basic** | `Basic realm="..."` | Solo trae el `realm`. El cliente enviará `usuario:contraseña` en base64, que es trivial de decodificar. |
| **Digest** | `Digest realm="...", nonce="..."` | Trae `realm` y un `nonce` generado por el servidor. El cliente envía un hash (MD5 normalmente) y la contraseña no viaja en claro. |

-------------

**9\. Which username and password were used during the successful authentication by the attacker?**


username:password

Submit Task
Task 10

Hint
At what frame number does the attacker transition from reconnaissance to exploitation activity?

number, such as 3, 17, or 4567

Submit Task
Task 11

Hint
Which protocol carries the video stream packets?

***

Submit Task
Task 12

Hint
What RTP payload type is used in the video stream and which video codec is used by the CCTV stream?

**, ****

Submit Task
Task 13

Hint
Which RTP SSRC identifiers appear in the second camera, and which one indicates the resumed stream after the interruption?

SSRC, SSRC

Submit Task
Task 14

Hint
What was the duration of the video stream interruption before it resumed?

**.****

Submit Task
Task 15

Hint
Which frame marks the first RTP packet of the resumed stream after the interruption event?

number, such as 3, 17, or 4567

Submit Task
Task 16

Hint
What banner information reveals the device type?
