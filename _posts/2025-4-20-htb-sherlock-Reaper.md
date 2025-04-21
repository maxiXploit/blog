---
layout: single
title: Hack The Box Sherlock - Reaper
excerpt: Anàlis forense de un ataque NTLM Relay en un entorno de Active Directory.  
date: 2025-4-21
classes: wide
categories: 
   - sherlock-htb
   - DFIR
tags: 
   - smb
   - wireshark
   - thsark
   - evtx
--- 


# **Reaper - Hack The Box**

---

Para este laboratorio se nos proporcionan 2 ficheros, un .pcap que anlizaremos con tshark y un *.evtx* que analizaremos con **EvtxECmd** y **Timeline Explorer**, ambas herramietnas muy poderosas para el análisis forense, porpiedad de Eric Zimmerman. 

Para parsear el .evtx ejecutaos el siguiente comando en powersherll. 
```poweshell
PS C:\Users\Lenovo\Downloads\compartida\EvtxECmd\EvtxeCmd> .\EvtxECmd.exe -d  "C:\Users\Lenovo\Downloads\compartida\Reaper"--csv "C:\Users\Lenovo\Downloads\compartida\Reaper" --csvf logs.csv
```

--- 

En este laboratorio vamos a investigar un NTLM Relay Attack, que es un tipo de ataque que explota el protocolo de autenticación NTLM (NT LAN Manager) para reenviar credenciales válidas de un usuario a otro servicio, sin necesidad de conocer la contraseña. Es una técnica de tipo "pass-the-hash" o "pass-the-challenge", muy utilizada en entornos Windows.

NTLM es un protocolo de autenticación de desafío-respuesta utilizado en redes Windows. Su funcionamiento general:
- El cliente solicita autenticarse.
- El servidor envía un desafío (challenge).
- El cliente responde con un hash cifrado del desafío, usando su contraseña como clave.
- El servidor valida la respuesta

⚠️ En este ataque el adversario actúa como intermediario entre un cliente y un servidor, reenviando mensajes NTLM legítimos para autenticarse en un sistema en nombre del usuario. ⚠️ 

🔁 Proceso simplificado: 
- El atacante pone un servidor falso (por ejemplo, SMB o HTTP) y engaña a un cliente legítimo para que se conecte a él (por ejemplo, mediante phishing o explotación de LLMNR/NBT-NS).
- El cliente intenta autenticarse con NTLM → envía el challenge-response.
- El atacante toma ese challenge-response y lo reenvía a un servidor real, haciéndose pasar por el cliente.
- El servidor real acepta la autenticación → el atacante accede con los privilegios del usuario legítimo.



Con esto ya podemos pasar a las preguntas:
⬇️ ⬇️ ⬇️

--- 
**Task 1**
¿Cuál es la dirección IP de Forela-Wkstn001?

Para responder a esto, podemos aplicar el siguiente filtro con tshark para buscar el nombre del host cuando obtuvo una dirección ip mediante el protocolo `dhcp`: 

```bash
─$ tshark -r ntlmrelay.pcapng -Y "dhcp"                                               
    1 0.000000000 172.17.79.129 68 172.17.79.254 67 DHCP 371 DHCP Request  - Transaction ID 0x988b1646
    2 0.000000191 172.17.79.254 67 172.17.79.129 68 DHCP 342 DHCP ACK      - Transaction ID 0x988b1646
 1119 83.559160245 172.17.79.135 68 255.255.255.255 67 DHCP 311 DHCP Discover - Transaction ID 0x8f841e2
 1127 84.566689196 172.17.79.254 67 255.255.255.255 68 DHCP 342 DHCP Offer    - Transaction ID 0x8f841e2
``` 


```bash
─$ tshark -r ntlmrelay.pcapng -Y "dhcp" -T fields -e dhcp.option.hostname
Forela-Wkstn001

E9OGH1DCE
```

También podemos usar el protocolo `nbns` o NetBIOS Name Service, es un protocolo que resuelve nombres de computadoras en una red local a direcciones IP. Se utiliza en redes NetBIOS sobre TCP/IP (NBT) y es fundamental para que las aplicaciones herencia de NetBIOS puedan funcionar en redes TCP/IP. En esencia, NBNS permite que las computadoras identifiquen a otras computadoras en la red utilizando nombres fáciles de recordar, en lugar de tener que usar solo direcciones IP. 
 . NBNS traduce nombres NetBIOS (como "PC-DE-MARIA") a direcciones IP. 

👇👇👇

```bash 
─$ tshark -r ntlmrelay.pcapng -Y "nbns"
    3 0.001463822 172.17.79.129 137 172.17.79.2  137 NBNS 110 Refresh NB FORELA-WKSTN001<20>
   28 1.499287702 172.17.79.129 137 172.17.79.2  137 NBNS 110 Refresh NB FORELA-WKSTN001<20>
  294 3.014968616 172.17.79.129 137 172.17.79.2  137 NBNS 110 Refresh NB FORELA-WKSTN001<20>
    <SNIP>
```

Un paquete tipo "Refresh NB" significa que un cliente está tratando de mantener su nombre NetBIOS registrado en la red, evitando que expire.
Cuando un dispositivo (como FORELA-WKSTN001) registra su nombre NetBIOS en la red, ese registro tiene una vida útil limitada, similar a cómo los registros DNS tienen un TTL. Para evitar que el servidor NBNS lo elimine después de cierto tiempo, el cliente manda un paquete "Refresh". 


---
**task 2** 
¿Cuál es la dirección IP de Forela-Wkstn002?

Seguimos analizando el protocolo **nbns**, usando el último filtro: 

```bash 
─$ tshark -r ntlmrelay.pcapng -Y "nbns"
  <SNIP>
  658 26.379344226 172.17.79.136 137 172.17.79.2  137 NBNS 110 Refresh NB FORELA-WKSTN002<20>
  659 27.895130013 172.17.79.136 137 172.17.79.2  137 NBNS 110 Refresh NB FORELA-WKSTN002<20>
  660 29.410667067 172.17.79.136 137 172.17.79.2  137 NBNS 110 Refresh NB FORELA-WKSTN002<20
``` 

---
**task 3** 
¿Cuál es el nombre de usuario cuyo hash fue fue robado por el atacante? 


Para esto aplicamos un filtro, esta ve para ntlmssp, que es el protocolo que facilita la autenticación ntlm. 

```bash 
─$ tshark -r ntlmrelay.pcapng -Y "ntlmssp "
 1195 97.975065296 172.17.79.136 50145 172.17.79.135 445 SMB2 220 Session Setup Request, NTLMSSP_NEGOTIATE
 1196 97.976170490 172.17.79.135 445 172.17.79.136 50145 SMB2 347 Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE
 1197 97.976683617 172.17.79.136 50145 172.17.79.135 445 SMB2 635 Session Setup Request, NTLMSSP_AUTH, User: FORELA\arthur.kyle
 1209 97.984658985 172.17.79.136 50145 172.17.79.135 445 SMB2 186 Session Setup Request, NTLMSSP_NEGOTIATE
 1210 97.985540721 172.17.79.135 40252 172.17.79.129 445 SMB2 186 Session Setup Request, NTLMSSP_NEGOTIATE
 1211 97.985911153 172.17.79.129 445 172.17.79.135 40252 SMB2 380 Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE
 1212 97.986639011 172.17.79.135 445 172.17.79.136 50145 SMB2 380 Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE
 1213 97.987030692 172.17.79.136 50145 172.17.79.135 445 SMB2 664 Session Setup Request, NTLMSSP_AUTH, User: FORELA\arthur.kyle
 1214 97.987948636 172.17.79.135 40252 172.17.79.129 445 SMB2 664 Session Setup Request, NTLMSSP_AUTH, User: FORELA\arthur.kyle
 1241 97.997053284 172.17.79.136 50145 172.17.79.135 445 SMB2 186 Session Setup Request, NTLMSSP_NEGOTIATE
 1254 98.048185165 172.17.79.135 445 172.17.79.136 50145 SMB2 316 Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE
 1255 98.048736924 172.17.79.136 50145 172.17.79.135 445 SMB2 594 Session Setup Request, NTLMSSP_AUTH, User: FORELA\arthur.kyle
 1504 116.535344027 172.17.79.136 50157 172.17.79.135 445 SMB2 220 Session Setup Request, NTLMSSP_NEGOTIATE
 1505 116.536081870 172.17.79.135 445 172.17.79.136 50157 SMB2 347 Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE
 1506 116.536497735 172.17.79.136 50157 172.17.79.135 445 SMB2 635 Session Setup Request, NTLMSSP_AUTH, User: FORELA\arthur.kyle
```

Vemos que la ip `172.17.79.135` se está comunicando con la ip del atacante que descubrimos en la respueta anterior, en este caso, el usuario `arthur.kyle`. 

---
**task 4**
¿Cuál es la dirección IP del dispositivo desconocido utilizado por el atacante para interceptar las credenciales?

Bien, sigamos analizando el tráfico `nbns`: 
```bash 
─$ tshark -r ntlmrelay.pcapng -Y "nbns"    
    3 0.001463822 172.17.79.129 137 172.17.79.2  137 NBNS 110 Refresh NB FORELA-WKSTN001<20>
   28 1.499287702 172.17.79.129 137 172.17.79.2  137 NBNS 110 Refresh NB FORELA-WKSTN001<20>
  294 3.014968616 172.17.79.129 137 172.17.79.2  137 NBNS 110 Refresh NB FORELA-WKSTN001<20>
  579 4.471329674 172.17.79.135 57561 172.17.79.1  137 NBNS 92 Name query NBSTAT *<00><00><00><00><00><00><00><00><00><00><00><00><00><00><00>
  580 4.471779579  172.17.79.1 137 172.17.79.135 57561 NBNS 199 Name query response NBSTAT
  585 4.473022033 172.17.79.135 34003 172.17.79.129 137 NBNS 92 Name query NBSTAT *<00><00><00><00><00><00><00><00><00><00><00><00><00><00><00>
  586 4.473304535 172.17.79.129 137 172.17.79.135 34003 NBNS 199 Name query response NBSTAT
  596 4.475016950 172.17.79.135 33988 172.17.79.4  137 NBNS 92 Name query NBSTAT *<00><00><00><00><00><00><00><00><00><00><00><00><00><00><00>
```

Y fijémonos en la ip `172.17.79.135`, que está realizando una consulta NBNS de tipo NBSTAT, donde:

- El atacante está preguntando por los nombre de NetBIOS registrados. 
- El uso del nombre *<00><00>... es una consulta especial que pide el estado completo del NetBIOS del host, incluyendo:
  - Nombre NetBIOS del equipo
  - Lista de servicios NetBIOS
  - Dirección MAC asociada

Esto se usa comúnmente en ataques para reconocer qué dispositivos están activos y qué nombres NetBIOS tienen, lo cual es un paso típico antes de envenenar o interceptar tráfico.

**Básicamente es la ip de nuestro atacante realizando reconocimiento de la red**

---
**task 5**
¿Cuál era el fileshare navegado por la cuenta de usuario de la víctima?

Bien, ahora filtremos por el protocolo smb,que es un protocolo de red que permite compartir archivos, impresoras y otros recursos entre computadoras en una red:
```bash 
─$ tshark -r ntlmrelay.pcapng -Y "smb2" | grep "Tree Connect Request"      
  760 70.805532684 172.17.79.129 60538 172.17.79.4  445 SMB2 182 Tree Connect Request Tree: \\DC01.forela.local\SysVol
 1143 94.174057818 172.17.79.129 60538 172.17.79.4  445 SMB2 178 Tree Connect Request Tree: \\DC01.forela.local\IPC$
 1199 97.977977002 172.17.79.136 50145 172.17.79.135 445 SMB2 146 Tree Connect Request Tree: \\D\IPC$
 1231 97.993065158 172.17.79.136 50145 172.17.79.135 445 SMB2 146 Tree Connect Request Tree: \\D\IPC$
 1232 97.993990427 172.17.79.135 40252 172.17.79.129 445 SMB2 170 Tree Connect Request Tree: \\172.17.79.129\IPC$
 1411 112.556745492 172.17.79.136 50152 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\IPC$
 1418 112.565901644 172.17.79.136 50152 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1420 112.566315545 172.17.79.136 50152 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1422 112.566608349 172.17.79.136 50152 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1424 112.566899230 172.17.79.136 50152 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1426 112.567344810 172.17.79.136 50152 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1428 112.567600707 172.17.79.136 50152 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1430 112.567878203 172.17.79.136 50152 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1432 112.568175286 172.17.79.136 50152 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1508 116.537648196 172.17.79.136 50157 172.17.79.135 445 SMB2 146 Tree Connect Request Tree: \\D\IPC$
 1546 128.099313531 172.17.79.136 50159 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\IPC$
 1553 128.102532294 172.17.79.136 50159 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1555 128.102795083 172.17.79.136 50159 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1557 128.103108146 172.17.79.136 50159 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
 1559 128.103369773 172.17.79.136 50159 172.17.79.4  445 SMB2 152 Tree Connect Request Tree: \\DC01\Trip
```

Vemos múltiples peticiones al fileshare `\\DC01\Trip`, además de ver que la ip de origen es la ip del atacante. 

---
**task 6**
¿Cuál es el puerto de origen utilizado para iniciar sesión en la estación de trabajo de destino utilizando la cuenta comprometida?

Para esto tenemos que navegar entro los logs que nos proporcionaron en el fichero `.evtx`, y hay que buscar un registro con las siguietes características: 

- Con el Event ID 4624 en los logs de seguridad de Windows, que significa "An account was successfully logged on": 
    O sea: inicio de sesión exitoso.

- Security ID = NULL SID:
    Significa que no hay un usuario local autenticado aún; probablemente una autenticación de red externa.

- Logon Type = 3:
    Es un logon de red (típico de SMB o conexiones remotas).

- Logon Process = NtLmSsp y Authentication Package = NTLM:
    Indica que el logon fue hecho usando NTLM, probablemente relayed o capturado.

```plaintext
Se inició sesión correctamente en una cuenta.

Firmante:
	Id. de seguridad:		NULL SID
	Nombre de cuenta:		-
	Dominio de cuenta:		-
	Id. de inicio de sesión:		0x0

Información de inicio de sesión:
	Tipo de inicio de sesión:		3
	Modo de administrador restringido:	-
	Cuenta virtual:		No
	Token elevado:		No

Nivel de suplantación:		Suplantación

Nuevo inicio de sesión:
	Id. de seguridad:		S-1-5-21-3239415629-1862073780-2394361899-1601
	Nombre de cuenta:		arthur.kyle
	Dominio de cuenta:		FORELA
	Id. de inicio de sesión:		0x64A799
	Inicio de sesión vinculado:		0x0
	Nombre de cuenta de red:	-
	Dominio de cuenta de red:	-
	GUID de inicio de sesión:		{00000000-0000-0000-0000-000000000000}

Información de proceso:
	Id. de proceso:		0x0
	Nombre de proceso:		-

Información de red:
	Nombre de estación de trabajo:	FORELA-WKSTN002
	Dirección de red de origen:	172.17.79.135
	Puerto de origen:		40252

Información de autenticación detallada:
	Proceso de inicio de sesión:		NtLmSsp 
	Paquete de autenticación:	NTLM
	Servicios transitados:	-
	Nombre de paquete (solo NTLM):	NTLM V2
	Longitud de clave:		128
``` 

Vemos que la dirección ip de origen es la 172.17.79.135, la misma que detectamos como sospechaso y que realizó una consulta NBNS de tipo NBSTAT. También vemos el puerto de origen. 

---
**task 7**

El campo "Logon ID" (en inglés) o "Id. de inicio de sesión" es un identificador único para una sesión de autenticación específica.
Se representa como un valor hexadecimal (como 0x64A799) y permanece constante durante toda la sesión del usuario.
Es como una huella digital de una sesión activa y es importante para correlacionar evetos e identificar movimiento lateral. 

Esto podemos verlo en la información del registro que presentamos en la pregunta anterior: 
```plaintext
Nuevo inicio de sesión:
    Id. de seguridad:       S-1-5-21-3239415629-1862073780-2394361899-1601
    Nombre de cuenta:       arthur.kyle
    Dominio de cuenta:      FORELA
    Id. de inicio de sesión:        0x64A799
    Inicio de sesión vinculado:     0x0
    Nombre de cuenta de red:    -
    Dominio de cuenta de red:   -
    GUID de inicio de sesión:       {00000000-0000-0000-0000-000000000000}
``` 

---
**task 8**

La detección se basó en una incongruencia entre el nombre de host y la dirección IP asignada. ¿Cuál es el nombre de la estación de trabajo y la dirección IP de origen desde la que se produce el inicio de sesión malicioso?

Bien, ya tenemos el registro que nos interesa, tenemos la ip sospechosai(la que no tenía un nombre otorgado por nbns) y la ip a la que en un principìo la víctima mandó su hash NTLM, así que prestemos más atención al registro que ahora estamos analizando, en específico, el siguiente campo: 

```bash 
Información de red:
    Nombre de estación de trabajo:  FORELA-WKSTN002
    Dirección de red de origen: 172.17.79.135
    Puerto de origen:       40252
``` 

Pero enuestra captura de red(.pcapng) vimos que el host al que pertenecía el nombre `FORELA-WKSTN002` tenía la ip `172.17.79.135`, y es esta la incongruencia de la que se está hablando. 


---
**task 9**

¿A qué hora UTC se produjo el inicio de sesión malicioso?


Esto pedemos verlo en la sección de detalles en el explorador de eventos de windows: 
```plaintext
- System 

  - Provider 

   [ Name]  Microsoft-Windows-Security-Auditing 
   [ Guid]  {54849625-5478-4994-a5ba-3e3b0328c30d} 
 
   EventID 4624 
 
   Version 2 
 
   Level 0 
 
   Task 12544 
 
   Opcode 0 
 
   Keywords 0x8020000000000000 
 
  - TimeCreated 

   [ SystemTime]  2024-07-31T04:55:16.2405897Z 
 
   EventRecordID 14610 
 
  - Correlation 

   [ ActivityID]  {ffedc1a7-e2f8-0005-25c2-edfff8e2da01} 
 
  - Execution 

   [ ProcessID]  784 
   [ ThreadID]  9120 
 
   Channel Security 
 
   Computer Forela-Wkstn001.forela.local 
 
   Security
```

--- 
**task 10**

¿Cuál es el Nombre compartido al que se accede como parte del proceso de autenticación por parte de la herramienta maliciosa utilizada por el atacante?

Para esto podemos buscar por el `Event ID 5140 – A network share object was accessed`
Este evento se genera cuando alguien accede a un recurso compartido (una carpeta o archivo compartido por SMB) en el sistema.
Es una forma clave de detectar actividad lateral o exfiltración de información.


Pero no hay que irnos tan lejos, solo basta recordar que el recurso compartido `\\[host]\IPC$` (**Inter-Process Communication share**) es **accedido automáticamente como parte del proceso de autenticación SMB**, **especialmente en conexiones NTLM y sesiones remotas**.

#### `IPC$`

- Es un **recurso compartido especial** que no contiene archivos, sino que permite **comunicación entre procesos remotos**.
- SMB lo utiliza para establecer **canales de control**, como por ejemplo:
  - Enumerar recursos compartidos
  - Ver usuarios y grupos
  - Conectarse a servicios remotos (WMI, DCOM, etc.)
  - Ejecutar comandos vía `psexec`, `wmiexec`, etc.

Cuando un atacante usa NTLM relay para autenticarse en una máquina víctima, **uno de los primeros recursos que se toca es `IPC$`**. Esto se ve en los logs como acceso a:

```
Share Name: \\D\IPC$
```

Y genera un evento 5140 como el siguiente que podemos ver en el `.evtx` que se nos proporciona: 

```plaintext
¡Estás absolutamente en lo correcto! 👌

### ✅ Tu afirmación es válida:

El recurso compartido `\\[host]\IPC$` (**Inter-Process Communication share**) es **accedido automáticamente como parte del proceso de autenticación SMB**, **especialmente en conexiones NTLM y sesiones remotas**.

---

### 🔍 ¿Qué es `IPC$`?

- Es un **recurso compartido especial** que no contiene archivos, sino que permite **comunicación entre procesos remotos**.
- SMB lo utiliza para establecer **canales de control**, por ejemplo, para:
  - Enumerar recursos compartidos
  - Ver usuarios y grupos
  - Conectarse a servicios remotos (WMI, DCOM, etc.)
  - Ejecutar comandos vía `psexec`, `wmiexec`, etc.

---

### 💡 En contexto de NTLM relay o ataques SMB:

Cuando un atacante usa NTLM relay para autenticarse en una máquina víctima, **uno de los primeros recursos que se toca es `IPC$`**. Esto se ve en los logs como acceso a:

```
Share Name: \\D\IPC$
```

Y genera un evento 5140 como el siguiente que podemos ver en el `.evtx` que se nos proporciona:

```plaintext
Se tuvo acceso a un objeto de recurso compartido de red.
	
Sujeto:
	Id. de seguridad:		S-1-5-21-3239415629-1862073780-2394361899-1601
	Nombre de cuenta:		arthur.kyle
	Dominio de cuenta:		FORELA
	Id. de inicio de sesión:		0x64A799

Información de red:	
	Tipo de objeto:		File
	Dirección de origen:		172.17.79.135
	Puerto de origen:		40252
	
Información de recurso compartido:
	Nombre de recurso compartido:		\\*\IPC$
	Ruta de acceso de recurso compartido:		

Información de solicitud de acceso:
	Máscara de acceso:		0x1
	Accesos:		ReadData (o ListDirectory)
``` 				

El * en este contexto no es un wildcard real, sino que representa una referencia genérica o simbólica al host al que se está conectando.
Es decir:
  \\*\IPC$ simplemente significa:
  “Estoy accediendo al recurso IPC$ de algún host remoto (cuyo nombre/IP está registrado en otro campo del log)”.

Basicamente, algo que haría alguna herramienta como `netexec`. 


