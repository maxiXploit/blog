

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
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "frame.number == 54449" -O rtsp

Frame 54449: Packet, 229 bytes on wire (1832 bits), 229 bytes captured (1832 bits)
Ethernet II, Src: MotorolaSolu_11:50:12 (00:18:85:11:50:12), Dst: PCSSystemtec_66:77:88 (08:00:27:66:77:88)
Internet Protocol Version 4, Src: 192.168.50.12, Dst: 192.168.50.200
Transmission Control Protocol, Src Port: 554, Dst Port: 56765, Seq: 1, Ack: 126, Len: 175
Real Time Streaming Protocol
    Response: RTSP/1.0 401 Unauthorized\r\n
        Status: 401
        [URL: rtsp://192.168.50.12:554/Streaming/Channels/101]
        Response to frame: 54447
    CSeq: 1
    Server: Hikvision-IP-Camera/5.5.82\r\n
    WWW-Authenticate: Digest realm="IP Camera(CAM2)", nonce="98ab01a7f0", qop="auth"\r\n
    Content-length: 0
    \r\n
```

| Esquema | Cómo se ve | Implicación |
|---|---|---|
| **Basic** | `Basic realm="..."` | Solo trae el `realm`. El cliente enviará `usuario:contraseña` en base64, que es trivial de decodificar. |
| **Digest** | `Digest realm="...", nonce="..."` | Trae `realm` y un `nonce` generado por el servidor. El cliente envía un hash (MD5 normalmente) y la contraseña no viaja en claro. |

-------------

**9\. Which username and password were used during the successful authentication by the attacker?**

Con el siguiente comando vemos las diferentes credenciales que elatacante utilizó hasta lograr autenticarse:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "http.authorization" -T fields -e xml.cdata
admin,12345
admin,password
admin,camera
admin,hikvision
root,root
service,service
admin,admin
```

-----------

**10\. At what frame number does the attacker transition from reconnaissance to exploitation activity?**

Aquí tenemos que identificar el momento en el que el atacante deja realizar acciones de reconocimiento y empieza a intentar acceder al sistema, en este caso sería el momento en el que empieza a acceder al sistema probando contraseñas:

```bash

```

-----------

**11\. Which protocol carries the video stream packets?**

La respuesta es **RTP (Real-time Transport Protocol)**. Es la pieza que complementa a RTSP.

## Separación de planos

| Plano | Protocolo | Función |
|---|---|---|
| **Control** | RTSP | Negocia y controla la sesión (`DESCRIBE`, `SETUP`, `PLAY`...) |
| **Datos** | **RTP** | Transporta los paquetes de video/audio |
| **Retroalimentación** | RTCP | Estadísticas de calidad (pérdida, jitter) y sincronización |

RTSP dice *qué* se transmite y *cuándo*, y RTP es el que lleva los datos. Por eso las cabeceras `Transport` del `SETUP` son tan importantes: ahí se acuerda cómo viajará el RTP.

### RTP (RFC 3550)

Corre normalmente sobre **UDP**, porque en streaming en tiempo real prima la baja latencia sobre la fiabilidad (un paquete tardío es inútil). No garantiza entrega ni orden, pero aporta los campos necesarios para que el receptor reordene y sincronice.

Cabecera mínima de 12 bytes:

| Campo | Para qué sirve |
|---|---|
| **V** (2 bits) | Versión, siempre 2 |
| **P, X, CC** | Padding, extensión, número de CSRC |
| **M** (marker) | Marca eventos relevantes (en video, el último paquete de un frame) |
| **PT** (payload type) | Identifica el códec. Los valores 96-127 son dinámicos y se mapean en el SDP |
| **Sequence number** | Detecta pérdida y reordena paquetes |
| **Timestamp** | Instante de muestreo (reloj de 90 kHz para video) |
| **SSRC** | Identificador único de cada stream |

Aquí se conecta con el `DESCRIBE` que vimos: en el SDP aparecía `a=rtpmap:96 H264/90000`, que significa que los paquetes con PT 96 llevan **H.264** con reloj de 90 kHz. El video H.264 se empaqueta según la RFC 6184: un NAL unit por paquete, o fragmentado en varios (**FU-A**) cuando excede la MTU.

### RTP junto a RTCP

Por convención, RTP usa un puerto par y RTCP el siguiente impar (por ejemplo, 5000 y 5001). Esto lo veríamos en el `SETUP`:

```
Transport: RTP/AVP;unicast;client_port=5000-5001;server_port=6970-6971
```

### Dos formas de transporte:

1. **UDP**: RTP en puertos propios, como arriba. Wireshark solo lo decodifica automáticamente si capturó el `SETUP` y vio el puerto negociado; si no, lo muestra como UDP genérico.
2. **TCP interleaved**: el RTP viaja dentro de la misma conexión TCP del RTSP (puerto 554), con un prefijo `$` + canal + longitud. Se pide con `Transport: RTP/AVP/TCP;interleaved=0-1`. Es común cuando hay firewalls o NAT.

--------------

**12\. What RTP payload type is used in the video stream and which video codec is used by the CCTV stream?

La respuesta suele venir en SDP (Session Description Protocol), que funciona como un «manual de instrucciones» o acuerdo previo entre dos o más dispositivos (endpoints)

Solicitando la información:

```bash

```

El campo **Payload Type (PT)** de la cabecera RTP tiene 7 bits y se divide en dos rangos:

| Rango | Tipo | Ejemplos |
|---|---|---|
| **0-95** | Estático: el significado está fijado por estándar (RFC 3551) | 0 = PCMU, 8 = PCMA, 26 = JPEG, 33 = MPEG-TS |
| **96-127** | **Dinámico**: no significa nada por sí mismo | El significado se negocia por sesión |

H.264 se creó después de que se cerrara la lista estática, así que no tiene un número fijo. Cada sesión elige uno del rango dinámico (muy comúnmente 96) y lo declara en el SDP. Por eso Wireshark solo te muestra `DynamicRTP-Type-96`: el paquete RTP no contiene el nombre del códec.

Esto se lee así:
- m=video 0 RTP/AVP 96 anuncia que el video usará el PT 96.
- a=rtpmap:96 H264/90000 dice que el PT 96 es H.264 con reloj de 90 kHz.
- a=fmtp:96 ... da parámetros del códec (perfil, modo de empaquetado y los SPS/PPS en base64).

La respuesta es `96, h264`

--------------

**13\. Which RTP SSRC identifiers appear in the second camera, and which one indicates the resumed stream after the interruption?**


El SSRC es un identificador de 32 bits que cada fuente RTP elige al azar al iniciar un stream. Si el flujo se corta y la sesión se reinicia (un TEARDOWN y un nuevo SETUP/PLAY, un reinicio de la cámara o una reconexión), lo normal es que aparezca un SSRC nuevo, con seq y timestamp también nuevos. Por eso el SSRC posterior a la pausa suele ser el del "stream reanudado".

Aplicando el siguiente filtro:

```bash
tshark -r CCTV.pcap -T fields -e rtp.ssrc | sort -u
```

El primer SSRC corresponde a la primera cámara, el segundo a la segunda cámara antes de interrumpirse la conexión por lo que el tercer SSRC es de la segunda cámara una vez reanudada la conexión.

----------

**14\. What was the duration of the video stream interruption before it resumed?**

```bash
tshark -r CCTV.pcap -Y "rtp" -T fields -e frame.time_utc_epoch > rtp_times.txt
awk 'NR>1 {print $1-prev} {prev=$1}' rtp_times.txt | sort -nr | head -1

tshark -r CCTV.pcap -Y "rtp && ip.src==CAM2" -T fields \
  -e frame.number -e frame.time_epoch -e rtp.ssrc | \
awk 'NR>1 && $3!=prev {
  printf "SSRC %s -> %s | último frame viejo: %s | primer frame nuevo: %s | gap = %.3f s\n",
         prev, $3, lastf, $1, $2-last
} {prev=$3; last=$2; lastf=$1}'

tshark -r CCTV.pcap -Y "rtp.ssrc==0xAAAAAAAA || rtp.ssrc==0xBBBBBBBB" \
  -T fields -e frame.number -e frame.time_delta_displayed -e rtp.ssrc | \
sort -k2 -n -r | head -3

┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "rtp.ssrc==0x1e8fa396 || rtp.ssrc==0xa6251f2d" -T fields -e frame.number -e frame.time_delta_displayed -e rtp.ssrc | sort -k2 -n -r | head -3

108664  710.352638000   0xa6251f2d
12977   0.152923000     0x1e8fa396
6499    0.152316000     0x1e8fa396

```


----------------------

Which frame marks the first RTP packet of the resumed stream after the interruption event?

number, such as 3, 17, or 4567

Submit Task
Task 16

Hint
What banner information reveals the device type?
