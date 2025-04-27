---
layout: single
title: Sherlock Campfire2 - Hack The Box 
excerpt: Anális forense de un AS-REP Roasting attack en kerberos, exploramos técnicas de detección con EventID's de windows, asi como las técnicas usadas por los atacantes para llevar a cabo este ataque.
date: 2025-4-26
classes: wide
categories: 
   - sherlock-htb
   - DFIR
tags: 
   - kerberos
   - as-rep roast attack
   - evtx
   - impaket
--- 


# **Sherlock - Campfire2**

En este laboratorio estaremos analizando logs de un **`AsREP roasting attack`** en un entorno de Active Directory. 

AS-REP Roasting es una técnica de Credential Access en Active Directory (MITRE ATT&CK T1558.004) que aprovecha cuentas con pre-autenticación Kerberos deshabilitada. Normalmente, Kerberos exige que el cliente cifre un timestamp con la contraseña del usuario antes de solicitar un ticket de concesión (TGT). Si la pre-autenticación está habilitada, el KDC solo emite el TGT si puede descifrar correctamente ese timestamp. En cambio, cuando una cuenta tiene marcada la opción “Do not require Kerberos preauthentication”, un atacante puede enviar directamente una solicitud AS-REQ para esa cuenta sin aportar credenciales adicionales; el controlador de dominio responde con un AS-REP (el TGT) cifrado parcialmente con la clave derivada de la contraseña del usuario. El atacante extrae entonces esa parte cifrada (típicamente con algoritmo débil como RC4) y realiza un ataque offline de fuerza bruta contra la contraseña.
Basicamente, AS-REP Roasting permite robar el “hash” Kerberos de una cuenta (para luego descifrarlo offline) aprovechando que no se requirió pre-autenticación. 

Se nos proporciona unicamete un fichero para este laboratorio, un .evtx con logs de windows que podemos parsear a un formato .jsonl con herramientas como `chainsaw`: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR]
└─$ /opt/chainsaw/target/release/chainsaw dump *.evtx --jsonl > security_results.jsonl

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Security.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (1.1 MiB)
[+] Done
``` 

Con todo esto listo ya podemos empezar la investigación y responder las preguntas. 

---
**task 1**

¿Cuándo se produjo el ataque ASREP Roasting y cuándo solicitó el atacante el ticket Kerberos para el usuario vulnerable?

Para responder a esto tenemos que fijarnos en 2 cosas, el EventID y el tipo en PreAuthType. 

El ID 4768 (TGT solicitado exitosamente): Este evento se genera cuando se emite un Ticket-Granting Ticket. En un AS-REP Roasting malicioso se verá un 4768 con Pre-Authentication Type = 0 (indicando que no se usó pre-autenticación). Además el ServiceName suele ser “krbtgt” (solicitud de TGT) y el Ticket Encryption Type frecuentemente “0x17” (RC4, un cifrado débil). Un ejemplo de entrada maliciosa podría mostrar TargetUserName = la cuenta víctima (sin pre-auth), Pre-Auth Type = 0, TicketEncType = 0x17, y ServiceName = krbtgt. Este patrón (4768 con PreAuthType=0) es característico de AS-REP Roasting.

Sabiendo esto ya podemos aplicar el siguiente filtro:

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR]
└─$ cat security_results.jsonl| jq '.Event | select(.System.EventID == 4768 and .EventData.PreAuthType == "0")' 
{
  "System": {
    "Provider_attributes": {
      "Name": "Microsoft-Windows-Security-Auditing",
      "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D"
    },
    "EventID": 4768,
    "Version": 0,
    "Level": 0,
    "Task": 14339,
    "Opcode": 0,
    "Keywords": "0x8020000000000000",
    "TimeCreated_attributes": {
      "SystemTime": "2024-05-29T06:36:40.246362Z"
    },
    "EventRecordID": 6241,
    "Correlation": null,
    "Execution_attributes": {
      "ProcessID": 752,
      "ThreadID": 3188
    },
    "Channel": "Security",
    "Computer": "DC01.forela.local",
    "Security": null
  },
  "EventData": {
    "TargetUserName": "arthur.kyle",
    "TargetDomainName": "forela.local",
    "TargetSid": "S-1-5-21-3239415629-1862073780-2394361899-1601",
    "ServiceName": "krbtgt",
    "ServiceSid": "S-1-5-21-3239415629-1862073780-2394361899-502",
    "TicketOptions": "0x40800010",
    "Status": "0x0",
    "TicketEncryptionType": "0x17",
    "PreAuthType": "0",
    "IpAddress": "::ffff:172.17.79.129",
    "IpPort": "61965",
    "CertIssuerName": "",
    "CertSerialNumber": "",
    "CertThumbprint": ""
  }
}
```

---
**task 2**

Por favor, confirme la cuenta de usuario que fue objetivo del atacante.

En el log proporcionado podemos encontrar el nombre del usuario de la víctima en el siguiente campo

```bash 
    "TargetUserName": "arthur.kyle"
``` 

---
**task 3** 

¿Cuál era el SID de la cuenta?

Un **SID** es un identificador único que Windows asigna a cada objeto de seguridad: usuarios, grupos, equipos, etc. Es como un DNI (documento de identidad) para cada entidad del dominio o sistema. Aunque el nombre de usuario pueda cambiar, el SID permanece constante. Esto es fundamental en entornos Windows para mantener las referencias internas: permisos, políticas de acceso, logs, etc.

- El nombre de usuario puede cambiar (por ejemplo si un atacante renombra una cuenta), pero el SID nunca cambia.
- Los logs de eventos de seguridad graban el SID, por lo que puedes rastrear de forma fiable qué cuenta realizó cada acción, aunque el nombre haya sido alterado después.
- Permite identificar relaciones entre cuentas, equipos o grupos en el dominio.
- En ataques como AS-REP Roasting, queremos saber qué cuentas no requieren preautenticación (PreAuthType 0) — y con el SID sabemos exactamente qué cuenta fue objetivo o vulnerable, incluso si hay confusión de nombres.

La respuesta a esta pregunta la podemos encontrar en el siguiente campo: 

```bash 
    "TargetSid": "S-1-5-21-3239415629-1862073780-2394361899-1601"
``` 

---
**task 4**

Es crucial identificar la cuenta de usuario comprometida y la estación de trabajo responsable de este ataque. Por favor, indique la dirección IP interna del activo comprometido para ayudar a nuestro equipo de caza de amenazas.

Esto lo podemos encontrar en el siguiente campo: 

```bash 
    "IpAddress": "::ffff:172.17.79.129"
``` 

---
**task 5**

Aún no tenemos ningún artefacto de la máquina de origen. Utilizando los mismos registros de DC Security, ¿puede confirmar la cuenta de usuario utilizada para realizar el ataque ASREP Roasting para que podamos contener la cuenta o cuentas comprometidas?

Podemos aplicar el siguiente filtro: 
```bash 
cat security_results.jsonl| jq '.Event | select(.System.EventID == 4769 and .EventData.IpAddress != "::1")' 
``` 

> ID 4769 (TGS solicitado): Tras el AS-REP, la máquina atacante suele continuar autenticándose normalmente. El registro 4769 (Ticket de servicio solicitado) en la misma IP origen puede ayudar a vincular la cuenta atacante (atacante) y la víctima. Por ejemplo, en casos reales se ha correlacionado un 4768 malicioso en una dirección con un 4769 poco después desde la misma máquina para identificar la cuenta que inició el ataque


```json
{
  "System": {
    "Provider_attributes": {
      "Name": "Microsoft-Windows-Security-Auditing",
      "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D"
    },
    "EventID": 4769,
    "Version": 0,
    "Level": 0,
    "Task": 14337,
    "Opcode": 0,
    "Keywords": "0x8020000000000000",
    "TimeCreated_attributes": {
      "SystemTime": "2024-05-29T06:37:49.227372Z"
    },
    "EventRecordID": 6242,
    "Correlation": null,
    "Execution_attributes": {
      "ProcessID": 752,
      "ThreadID": 3188
    },
    "Channel": "Security",
    "Computer": "DC01.forela.local",
    "Security": null
  },
  "EventData": {
    "TargetUserName": "happy.grunwald@FORELA.LOCAL",
    "TargetDomainName": "FORELA.LOCAL",
    "ServiceName": "DC01$",
    "ServiceSid": "S-1-5-21-3239415629-1862073780-2394361899-1000",
    "TicketOptions": "0x40810000",
    "TicketEncryptionType": "0x12",
    "IpAddress": "::ffff:172.17.79.129",
    "IpPort": "61975",
    "Status": "0x0",
    "LogonGuid": "543ACECF-87DD-45D9-CF0D-6C1F28070DC3",
    "TransmittedServices": "-"
  }
}
```

Una pregunta que podría hacerse es por qué ambas logs tienen la misma ip si son cuetas distintas, y es que en realidad el atacante estaría enumerando usuarios para ver cuales no tiene la preautenticación activada, esto se haría, por ejemplo, con la suite de Impaket, con la herramietna `GetNPUsers.py`

```bash 
/usr/share/doc/python3-impacket/examples/GetNPUsers.py -no-pass -usersfile users.txt FORELA.LOCAL/
``` 
**Entonces:**
- Misma IP = siempre 172.17.79.129 → es la máquina atacante.
- El sondeo inicial se hizo contra arthur.kyle (sin llegar a roast).
- El roasting completo (AS-REQ + TGS-REQ) se hizo contra happy.grunwald@FORELA.LOCAL → esa es la cuenta comprometida que deben contener.


**Otro EventID que podría interesarnos es el ID 4771 (error Kerberos pre-authentication fallida). Este evento aparece si se intenta autenticación a una cuenta que sí requiere preauth y falla (código 0x18). En AS-REP Roasting no habrá 4771, porque la cuenta objetivo no requiere pre-auth; en cambio veremos sólo el 4768 exitoso con PreAuthType=0. (Para el contexto, Microsoft indica que el 4771 se genera cuando falta pre-auth para cuentas normales.

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR]
└─$ cat security_results.jsonl| jq '.Event | select(.System.EventID == 4771)' 
{
  "System": {
    "Provider_attributes": {
      "Name": "Microsoft-Windows-Security-Auditing",
      "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D"
    },
    "EventID": 4771,
    "Version": 0,
    "Level": 0,
    "Task": 14339,
    "Opcode": 0,
    "Keywords": "0x8010000000000000",
    "TimeCreated_attributes": {
      "SystemTime": "2024-05-29T06:35:05.358090Z"
    },
    "EventRecordID": 6221,
    "Correlation": null,
    "Execution_attributes": {
      "ProcessID": 752,
      "ThreadID": 440
    },
    "Channel": "Security",
    "Computer": "DC01.forela.local",
    "Security": null
  },
  "EventData": {
    "TargetUserName": "Administrator",
    "TargetSid": "S-1-5-21-3239415629-1862073780-2394361899-500",
    "ServiceName": "krbtgt/FORELA",
    "TicketOptions": "0x40810010",
    "Status": "0x18",
    "PreAuthType": "2",
    "IpAddress": "::1",
    "IpPort": "0",
    "CertIssuerName": "",
    "CertSerialNumber": "",
    "CertThumbprint": ""
  }
}
```
