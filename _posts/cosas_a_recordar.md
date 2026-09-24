
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


