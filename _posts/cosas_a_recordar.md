
Archivos a los que se accedieron ultimamente en windows? -> **SHERLLBAS**

--------

Persistencia tipo /Run, /RunOnce?, buscar en: 

```bash
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe
    GlobalFlag = 0x200          ← activa el monitoreo

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe
    ReportingMode = 1           ← "lanza un proceso monitor"
    MonitorProcess = C:\ruta\malware.exe   ← qué se ejecuta
```

-------------

**RDP guarda en el caché imágenes de la máquina remota, se parsean con bmc-tools**
RDPieces, que va en la misma línea y busca en GitHub por ese nombre.
-------

Script para detección automática de comportamientos anómalos en los eventos de Windows.

```bash
.\DeepBlue.ps1 .\System.evtx  
```

-------------

Identificar si se trata de un mismo atacante analizando los metadatos de la conexión: El "package hash" en Ray, o cuando se ve una IP, buscar su ASN nos dice qué tipo de infraestructura es, no quién es la persona. Por ejemplo:

Con herramientas online como bgp.he.net o ipinfo.io, metes la IP y te dice el ASN y a quién pertenece. Es un paso estándar en threat intel: antes de asumir "son dos atacantes", siempre vale la pena mirar si las IPs comparten ASN, hosting o cualquier otro indicador de infraestructura compartida.
