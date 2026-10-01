

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

El protocolo RTSP (Real Time Streaming Protocol o Protocolo de Transmisión en Tiempo Real) es un protocolo de red de la capa de aplicación diseñado para controlar la transmisión de datos multimedia en tiempo real, como audio y video.

Es un protocolo fuera de banda (out of band). Utiliza una conexión (por defecto el puerto TCP 554) para los mensajes de control y otros puertos independientes (usualmente mediante RTP/UDP) para enviar el flujo real de video y audio

`554`, `RTSP`

---------------------

**5\. What was the first RTSP request method used by the attacker?**

Con la IP y el protocolo ya identificados, filtramos para ver la conversación: 

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/nosignal]
└─$ tshark -r CCTV.pcap -Y "ip.addr == 192.168.50.200 and rtsp"
54447 696.973114 192.168.50.200 56765 192.168.50.12 554 RTSP 179 DESCRIBE rtsp://192.168.50.12:554/Streaming/Channels/101 RTSP/1.0
54449 696.999937 192.168.50.12 554 192.168.50.200 56765 RTSP 229 Reply: RTSP/1.0 401 Unauthorized
```

Se usa el protocolo `DESCRIBE`, son 

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

What authentication mechanism was requested by the camera server?

******

Submit Task
Task 9

Hint
Which username and password were used during the successful authentication by the attacker?


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
