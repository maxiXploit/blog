

# **Cyberdefenders - RedLine**

El equipo de blueteam nos manda un volcado de memoria para analziar una posible intrusión al equipo de un empleado, tendremos que averiguar qué fue lo que pasó usando herramientas como volatility3. 


---
<p style="color: blue;">1. ¿Cuál es el nombre del proceso malicioso? </p>

Bien, para esto tenemos que usar primeramente el siguiente comando en volatility para ver el listado de procesos: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ vol -f MemoryDump.mem windows.pslist > pslist

```

Y observando un poco vemos que tenemos un proceso relacionado con `dll's` que no tiene como PPID un proceso légitimo que se encargue de esto: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ grep 5896 pslist                               
5896    8844    oneetx.exe      0xad8189b41080  5       -       1       True    2023-05-21 22:30:56.000000 UTC  N/A     Disabled
7732    5896    rundll32.exe    0xad818d1912c0  1       -       1       True    2023-05-21 22:31:53.000000 UTC  N/A     Disabled
```

El proceso `rundll32.exe` (PID 7732) fue iniciado por el proceso `oneetx.exe` (PID 5896). rundll32.exe es una utilidad legítima de Windows usada para ejecutar funciones exportadas desde DLLs, pero comúnmente es utilizada en ataques para ejecutar código malicioso de manera sigilosa, precisamente porque parece legítima.

oneetx.exe no es un proceso estándar de Windows y su nombre no es reconocido como software común o de sistema. Que este proceso sea el padre de rundll32.exe puede indicar una técnica de evasión o persistencia, donde un ejecutable posiblemente malicioso lanza rundll32.exe para ejecutar una DLL o payload en segundo plano.

### **Ejecutables legítimos que manejan DLLs en Windows**

| Ejecutable                        | Descripción                                                                         |
| --------------------------------- | ----------------------------------------------------------------------------------- |
| **rundll32.exe**                  | Ejecuta funciones exportadas de DLLs. Puede ser abusado por malware.                |
| **svchost.exe**                   | Hospeda servicios de Windows que se implementan como DLLs. Muy común.               |
| **dllhost.exe**                   | Ejecuta objetos COM+ alojados en DLLs.                                              |
| **explorer.exe**                  | Interfaz de usuario de Windows. Carga muchas DLLs para funcionalidades del sistema. |
| **services.exe**                  | Responsable de iniciar, detener y manejar servicios. Utiliza DLLs del sistema.      |
| **taskhostw\.exe / taskhost.exe** | Actúa como host para procesos que se ejecutan desde DLLs.                           |

---
<p style="color: blue;"> 2. ¿Cuál es el nombre del proceso hijo del proceso sospechoso? </p>

Esto ya lo cubrimos en la respuesta anterior: `rundll32.exe`

Pero podemos usar otra serie de comandos para llegar a esta conclusión: 

Usamos `malfind` para obtener lo que volatility cree que son procesos sospechosos/maliciosos: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ vol -f MemoryDump.mem windows.malfind > malfind

┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ cat malfind 
Volatility 3 Framework 2.11.0

PID     Process Start VPN       End VPN Tag     Protection      CommitCharge    PrivateMemory   File output     Notes   Hexdump Disasm

5704    RuntimeBroker.  0x21ddbca0000   0x21ddbcaffff   VadS    PAGE_EXECUTE_READ       16      1       Disabled        N/A
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
5896    oneetx.exe      0x400000        0x437fff        VadS    PAGE_EXECUTE_READWRITE  56      1       Disabled        MZ header
4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 MZ..............
b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 ........@.......
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 ................        4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00
7540    smartscreen.ex  0x2505c140000   0x2505c15ffff   VadS    PAGE_EXECUTE_READWRITE  1       1       Disabled        N/A
48 89 54 24 10 48 89 4c 24 08 4c 89 44 24 18 4c H.T$.H.L$.L.D$.L
89 4c 24 20 48 8b 41 28 48 8b 48 08 48 8b 51 50 .L$ H.A(H.H.H.QP
48 83 e2 f8 48 8b ca 48 b8 60 00 14 5c 50 02 00 H...H..H.`..\P..
00 48 2b c8 48 81 f9 70 0f 00 00 76 09 48 c7 c1 .H+.H..p...v.H..        48 89 54 24 10 48 89 4c 24 08 4c 89 44 24 18 4c 89 4c 24 20 48 8b 41 28 48 8b 48 08 48 8b 51 50 48 83 e2 f8 48 8b ca 48 b8 60 00 14 5c 50 02 00 00 48 2b c8 48 81 f9 70 0f 00 00 76 09 48 c7 c1
```

Y podemos aplicar un grep sobre los PID de cada proceso para ver cual es el que podría ser el sospechoso. 

Para confirmarlo descargamos los ficheros y subimos el hash a virustotal: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline/files]
└─$ vol -f ../MemoryDump.mem windows.dumpfile --pid 5896
```


---
<p style="">3. ¿Cuál es la protección de memoria aplicada a la región de memoria del proceso sospechoso? </p>

Esto lo podemos ver en la pregunta anterior: 

`5896    oneetx.exe      0x400000        0x437fff        VadS    PAGE_EXECUTE_READWRITE  56      1       Disabled        MZ header` 

La protección de memoria **`PAGE_EXECUTE_READWRITE`** en sistemas Windows indica que una región de memoria está configurada para permitir las siguientes acciones:

* **READ**: Se puede leer el contenido de esa memoria.
* **WRITE**: Se puede escribir/modificar el contenido de esa memoria.
* **EXECUTE**: Se puede ejecutar código directamente desde esa región de memoria.

Esta configuración es **muy peligrosa desde el punto de vista de la seguridad**, porque:

* Permite que un atacante cargue **código malicioso en memoria**, lo modifique si lo desea, y **lo ejecute directamente**.
* Se **viola el principio W^X** (Write XOR Execute), que sugiere que la memoria debería ser o escribible o ejecutable, pero **nunca ambas cosas al mismo tiempo**, para reducir la superficie de ataque.

---
<p style="color: blue;">4. ¿Cuál es el nombre del proceso responsable de la conexión VPN?</p>

Aqui solo queda explorar el arbol de procesos que se reporta con el siguietne comando: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ vol -f MemoryDump.mem windows.pstree > pstree

┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ cat pstree 
```

Eventaulmente vamos a encontrar el siguiene proceso: 
```bash 
**** 4628       6724    tun2socks.exe   0xad818de82340  0       -       1       True    2023-05-21 22:40:10.000000 UTC  2023-05-21 23:01:24.000000 UTC  \Device\HarddiskVolume3\Program Files (x86)\Outline\resources\app.asar.unpacked\third_party\outline-go-tun2socks\win32\tun2socks.exe        -       -
````
El proceso **`tun2socks.exe`** es, básicamente, un puente entre una interfaz de red virtual (TUN) y un proxy SOCKS. Su función principal es:

1. **Capturar el tráfico IP** que llega o sale de una interfaz TUN (una “túnelización” de red a nivel de paquete).
2. **Encapsular ese tráfico** en solicitudes SOCKS (normalmente SOCKS5).
3. **Enviar/recibir** los datos a través de un servidor SOCKS remoto.

### Se usa frecuentemente para:

* **Aplicaciones VPN y proxy**: Muchas soluciones (por ejemplo, Outline VPN, algunas implementaciones de Shadowsocks o V2Ray) usan `tun2socks.exe` en Windows para desviar TODO el tráfico IP de la máquina a través de un proxy SOCKS, sin necesidad de configurar aplicación por aplicación.
* **Bypass de restricciones de red**: Permite redirigir el tráfico de forma transparente, “engañando” aplicaciones para que crean que se conectan directamente a Internet cuando en realidad pasan por un proxy.
* **Testeo y desarrollo de redes**: En laboratorios o entornos de desarrollo de soluciones de tunneling/proxy.

### Esto puede implicar:

* **Presencia de un cliente VPN/proxy**: Su ejecución indica que, en el momento de la captura, había un túnel de red activo.
* **Posible canal encubierto**: Un atacante o usuario avanzado podría haberlo utilizado para ocultar o redirigir su tráfico fuera del perímetro de seguridad.
* **Objetivo de análisis**: Conviene identificar hacia qué servidor SOCKS estaba apuntando, qué binarios “hijos” abría y qué librerías cargaba, para entender el flujo de red completo.

Podemos intentar identificar módulos cargados por la DLL del driver TUN (por ejemplo, `tap0901.sys` o similar).

Pero lo que nos interesa por ahora es el proceso padre de este`tun2socks.exe`, filtraos por este PPID:

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ grep "6724" pstree
*** 6724        3580    Outline.exe     0xad818e578080  0       -       1       True    2023-05-21 22:36:09.000000 UTC  2023-05-21 23:01:24.000000 UTC  \Device\HarddiskVolume3\Program Files (x86)\Outline\Outline.exe      -       -
**** 4224       6724    Outline.exe     0xad818e88b080  0       -       1       True    2023-05-21 22:36:23.000000 UTC  2023-05-21 23:01:24.000000 UTC  \Device\HarddiskVolume3\Program Files (x86)\Outline\Outline.exe      -       -
**** 4628       6724    tun2socks.exe   0xad818de82340  0       -       1       True    2023-05-21 22:40:10.000000 UTC  2023-05-21 23:01:24.000000 UTC  \Device\HarddiskVolume3\Program Files (x86)\Outline\resources\app.asar.unpacked\third_party\outline-go-tun2socks\win32\tun2socks.exe -       -
```

---
<p style="color: blue;">5. ¿Cuál es la dirección IP del atacante?</p>

Para esto podemos usar el siguiente comando para obtener las conexiones en el volcado de memoria. 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ vol -f MemoryDump.mem windows.netscan > netscan
```

Ya conocemos el nombre del proceso malicioso.

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ grep "oneetx.exe" netscan                                                                            
0xad818de4aa20  TCPv4   10.0.85.2       55462   77.91.124.20    80      CLOSED  5896    oneetx.exe      2023-05-21 23:01:22.000000 UTC
0xad818e4a6900  UDPv4   0.0.0.0 0       *       0               5480    oneetx.exe      2023-05-21 22:39:47.000000 UTC
0xad818e4a6900  UDPv6   ::      0       *       0               5480    oneetx.exe      2023-05-21 22:39:47.000000 UTC
0xad818e4a9650  UDPv4   0.0.0.0 0       *       0               5480    oneetx.exe      2023-05-21 22:39:47.000000 UTC
```

---
<p style="color: blue;">6. ¿Cuál es la URL completa del archivo PHP que visitó el atacante? </p>


```bash
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ strings MemoryDump.mem > strings
```

Y podemos aplicar un grep para buscar patrones parecidos a una URL: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ grep -iE "http(|s):\/\/77.91.124.20\/" strings
http://77.91.124.20/ E
http://77.91.124.20/store/gamel
http://77.91.124.20/ E
http://77.91.124.20/DSC01491/
http://77.91.124.20/DSC01491/
http://77.91.124.20/store/games/index.php
http://77.91.124.20/store/games/index.php
http://77.91.124.20/store/games/index.php
```

----
<p style="color: blue;">7. ¿Cuál es la ruta completa del ejecutable malicioso?</p>



Esto se puede ver desde el `pstree` que habíamos obtenido ya, aplicamos un filtro por el nombre del fichero malicioso: 

```bash 
┌──(venv)─(kali㉿kali)-[~/blue-labs/redline]
└─$ grep -i "oneetx.exe" pstree 
*** 5480        448     oneetx.exe      0xad818d3d6080  6       -       1       True    2023-05-21 23:03:00.000000 UTC  N/A     \Device\HarddiskVolume3\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe        -       -
5896    8844    oneetx.exe      0xad8189b41080  5       -       1       True    2023-05-21 22:30:56.000000 UTC  N/A     \Device\HarddiskVolume3\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe        -       -
```

Buena observación. La razón por la que la ruta aparece como:

```
\Device\HarddiskVolume3\Users\Tammam\AppData\Local\Temp\c3912af0\oneetx.exe
```

en lugar de `C:\Users\Tammam\...` es porque **Windows internamente usa rutas del espacio de nombres del kernel (NT Object Manager)** para representar los discos y dispositivos.

Windows representa los discos montados de forma abstracta bajo el espacio `\Device\HarddiskVolumeX`. Luego, en modo usuario, el sistema operativo asigna **letras de unidad (como `C:`)** a esos volúmenes usando el **Mount Manager** y las **DOS device names**, que son sólo alias simbólicos.

Entonces:

| Representación interna (kernel)            | Equivalente en modo usuario                      |
| ------------------------------------------ | ------------------------------------------------ |
| `\Device\HarddiskVolume3`                  | `C:\` (en la mayoría de los casos)               |
| `\Device\HarddiskVolume2\Windows\System32` | `D:\Windows\System32` (si estuviera montado así) |

> No siempre `HarddiskVolume3` será `C:\` — eso depende del sistema, la partición activa y el orden de montaje. Pero en la mayoría de PCs domésticos, `HarddiskVolume3` **sí corresponde a `C:\`**.


Podemos usar el plugin `filescan`.

