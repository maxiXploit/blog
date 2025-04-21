# **Sherlock Reaper - Hack The Box**

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


