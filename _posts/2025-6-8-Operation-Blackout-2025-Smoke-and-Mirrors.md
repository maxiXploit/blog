---
layout: single
title: Operation Blackout 2025 - Smoke and Mirrors.
excerpt: Análisis de fichero .evtx en una intrusión en la que se aplican técnicas de evasión de antivirus. 
date: 2025-6-7
classes: wide
header:
   teaser: ../assets/images/forwa
   teaser_home_page: true
   icon: ../assets/images/splunk-logo.jpg
categories:
   - splunk
   - windows
   - hack the box
   - sherlock
   - active directory
   - DFIR
tags:
   - .evtx
   - evtxecmd
---


Para este laboratorio se nos proprocionan ficheros `.evtx` que parseamos a formato json con `EvtxEcmd`  o con `Chainsaw`. Una vez parseados los introducimos en splunk, en un índice que ya hemos creado previemente, en mi caso lo llamé "smoke". 

Con esto aclarado podemos pasar a las preguntas del laboratorio: 

-------

<h3 style="color:  #9FEF00;">Task1. The attacker disabled LSA protection on the compromised host by modifying a registry key. What is the full path of that registry key? </h3>

Para esto tenemos que entender tres cosas: 

- LSA (Local Security Authority) es el componente que maneja credenciales, tokens, inicio de sesión, etc.
- Protected Process Light hace que LSA sea más difícil de manipular o inspeccionar por herramientas de seguridad.
- Si el atacante desactiva PPL, puede inyectar código o volcar credenciales sin ser detectado por soluciones que dependen de esa protección.

Los EventId por los que podemos buscar: 

| Fuente de eventos              | Event ID | Descripción                                                                         |
| ------------------------------ | -------- | ----------------------------------------------------------------------------------- |
| **Windows Security Log**       | 4657     | “A registry value was modified.”                                                    |
| **Sysmon** (System Monitor)    | 13       | “Registry value set.”                                                               |
| **PowerShell Operational Log** | 4104     | “Script block logging” — permite ver el comando `reg add`, `Set-ItemProperty`, etc. |


Así que podemos intentar filtrar con lo siguiente en splunk: 

```bash 
index="smoke" EventId=13 Provider="Microsoft-Windows-Sysmon" 
| dedup PayloadData5
| table TimeCreated, PayloadData5
| sort -TimeCreated
```

Esto nos da bastante resultados, podemos filtrar directamente por la palabra "lsa", pero no es recomendable filtrar por cadenas de téxto: 

```bash 
B
index="smoke" EventId=13 Provider="Microsoft-Windows-Sysmon"  "lsa"
| dedup PayloadData5
| table TimeCreated, PayloadData5
| sort -TimeCreated
```

La ruta es clara: 

```bash 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL
```

Aquí, el valor RunAsPPL (DWORD) controla si LSA se ejecuta como PPL. Un valor de 1 lo habilita, y un valor de 0 (o su borrado) lo deshabilita.

------

<h3 style="color:  #9FEF00;">Task 2. Which PowerShell command did the attacker first execute to disable Windows Defender?  </h3>

Para esto podemos buscar por el EventId 4104, que ya sabemos que registra bloques de código ejecutados con powershell. 

Para deshabilitar Windows Defender vía PowerShell, los atacantes suelen emplear comandos que modifican las preferencias del módulo de antimalware o detienen y deshabilitan el servicio. Los más frecuentes son: 
- El cmdlet `Set-MpPreference`, que permite desactivar selectivamente varios componentes de Defender
B
- `Disable-WindowsOptionalFeature` en sistemas Windows Server:
- Modificar directamente el registro (menos común desde PS, más con reg.exe): `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f} `

Así que podemos aplicar el siguiente commando:

```bash 
index="smoke" EventId=4104
| table TimeCreated, PayloadData2
| dedup PayloadData2
| where like(lower(PayloadData2), "%set-mppreference%")
| sort TimeCreated
```

La respuesta el el primer resultado devuelto: 


| TimeCreated                      | PayloadData2                                                                                                   |
|----------------------------------|----------------------------------------------------------------------------------------------------------------|
| 2025-04-10T06:31:32.8678260+00:00 | ScriptBlockText: Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true |



----

<h3 style="color:  #9FEF00;">Task 3. The attacker loaded an AMSI patch written in PowerShell. Which function in the DLL is being patched by the script to effectively disable AMSI?</h3>

AMSI (Anti‑Malware Scan Interface) es la API que usa PowerShell (y otras aplicaciones) para que el motor de antimalware escanee scripts y objetos en memoria antes de ejecutarlos.

Si se sobreescribe (patch) la función que realiza el escaneo, se obliga a AMSI a devolver siempre “OK”, anulando cualquier detección. Técnicamente, el atacante usa llamadas como Get-ProcAddress y VirtualProtect para localizar la dirección de la función en amsi.dll, cambiar sus permisos de página y escribir un pequeño stub que simplemente retorna éxito.

Conociendo esto podemos buscar cualquiér referencia a `amsi.dll`, `AmsiScanBuffer` que es la rutina fundamental que inspecciona buffers de memoria es:

```bash 
index="smoke"
| search "amsi\.dll" OR "AmsiScanBuffer" OR "VirtualProtect"
| sort TimeCreated
```

Vamos a ver un registro, con EventId 4104, que contiene una función llamada `public class P`, que hace referencia a amsi.dll y a `AmsiScanBuffer`, siendo ésta función la respuesta que buscamos. Ésta función Recibe el puntero al buffer de datos (por ejemplo, el contenido de un script PowerShell), llama internamente al motor antimalware y devuelve un código de resultado (por ejemplo, AMSI_RESULT_CLEAN o AMSI_RESULT_DETECTED).

---------

<h3 style="color:  #9FEF00;">Task 4. Which command did the attacker use to restart the machine in Safe Mode? </h3>

Para esto buscamos por el EventId en el canal de Sysmon, en el que consultamos los eventos de Process Create, es decir, cada vez que un proceso nuevo se inicia en el sistema. Ese evento incluye, entre otros campos, la ruta al ejecutable y la línea de comandos completa. Este EventId registra el campo Image (ruta al ejecutable) y CommandLine (argumentos), aquí mapeado a ExecutableInfo.

Sysmon vuelca tal cual la línea de comando que recibió el proceso. En el unico log que nos muestra podemos ver: 

```bash 
"C:\WINDOWS\system32\bcdedit.exe" /set safeboot network
```

Eso indica que bcdedit.exe fue ejecutado con los parámetros /set safeboot network, y Sysmon lo capturó íntegro.

    - bcdedit es la herramienta de Microsoft para gestionar la configuración de arranque (BCD – Boot Configuration Data).
    - /set safeboot network le indica al gestor de arranque que el próximo reinicio inicie en Modo Seguro con soporte de red.

    Tras ejecutarse, bastaría con un shutdown /r /t 0 (o reiniciar manualmente) para que el sistema arranque en Safe Mode con servicios de red habilitados.

------

<h3 style="color: #9FEF00;">Task 5. Which PowerShell command did the attacker use to disable PowerShell command history logging? </h3>


Para esto podemos aplicar el siguiente comando: 

```bash 
index="smoke" EventId=4104
| search "Set-PSReadLineOption"
```

Esto devuelve un solo registro con el comando que estamos buscando.
