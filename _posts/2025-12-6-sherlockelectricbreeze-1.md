---
layout: single
title: Sherlock - ElectricBreeze-1
excerpt: Ejercicio de inteligencia de amenazas relacionado con un grupo de hackers chinos. 
date: 2025-6-12
classes: wide
header:
   teaser: ../assets/images/forwa
   teaser_home_page: true
   icon: ../assets/images/hackthebox.webp
categories:
   - sherlock
   - threat intelligence
   - mittre att&ck
tags:
   - hack the boxx
   - mittre att&ck
   - threat intelligence
---

Estaremos resolviendo un ejercicio de Threat Inteligence apoyándonos del framework MITRE ATT&CK, un recurso bastante importante para operaciones de securización de systemas. 
Estaremos investigando el APT volt-typhoon, así que pasamos rápido a las preguntas: 


<h3 style="color: #9FEF00;"> Task 1. Based on MITRE's sources, since when has Volt Typhoon been active? </h3>

Esto podemos encontrarlo directamente en el [reporte de MITRE ATT&CK](https://attack.mitre.org/groups/G1017/)

Parece que el grupo está activo desde el año 2021. 

--------

<h3 style="color: #9FEF00;"> Task 2. MITRE identifies two OS credential dumping techniques used by Volt Typhoon. One is LSASS Memory access (T1003.001). What is the Attack ID for the other technique? </h3>

Buscando en la misma página de MITRE, podemos ver que la táctica que nos piden es la T1003.003, que corresponde al ataque NTDS.dit dumping attack: 

- Consiste en crear una copia del NTDS.dit, normalmente usando una Shadow Copy.

- Se extrae también el archivo SYSTEM del registro (C:\Windows\System32\config\SYSTEM) para obtener la clave de cifrado de los hashes.

-------

<h3 style="color: #9FEF00;"> Task 3. Which database is targeted by the credential dumping technique mentioned earlier? </h3>

Esta pregunta puede ser engañosa, uno pensaría que se trata de la base de datos `NTDS.dit` mencionada en la pregunta anterior, y aunque si hacen referencia a esta base de datos, en realidad nos preguntan a qué servicio de Microsoft pertenece la DB, que en este caso es `Active Directory`. 

- Active Directory (AD) es un servicio de directorio desarrollado por Microsoft. Se utiliza en entornos Windows corporativos para gestionar y autenticar recursos dentro de una red. Permite centralizar la administración de usuarios, grupos, equipos, políticas de seguridad y otros objetos.

NTDS.dit es la base de datos principal de Active Directory.

- Su nombre viene de NT Directory Services - Data Information Tree.
- Ubicación típica: C:\Windows\NTDS\NTDS.dit (en un Domain Controller, no en cualquier equipo).

El contenido de AD: 

| Contenido del NTDS.dit                | Descripción                                                            |
| ------------------------------------- | ---------------------------------------------------------------------- |
| Objetos del directorio                | Usuarios, grupos, equipos, unidades organizativas (OUs)                |
| Atributos de objetos                  | Nombre de usuario, dirección de correo, permisos, etc.                 |
| **Hashes de contraseñas** de usuarios | Usados para autenticar credenciales sin almacenar contraseñas en claro |
| Información de replicación            | Datos para sincronizar con otros Domain Controllers                    |


----

<h3 style="color: #9FEF00;"> Task 4. Which registry hive is required by the threat actor to decrypt the targeted database? </h3>

El hive del registro requerido por el atacante es: `SYSTEM`

Cuando un atacante realiza un volcado de credenciales de la base de datos NTDS.dit (la base de datos principal de Active Directory), los hashes de las contraseñas almacenados allí están cifrados utilizando una clave derivada de la clave de arranque (boot key) del sistema operativo Windows.

Esta boot key no se encuentra dentro del propio archivo NTDS.dit, sino que se almacena en el registro del sistema, específicamente en el hive llamado:

> `SYSTEM (usualmente ubicado en C:\Windows\System32\config\SYSTEM)`

Este hive contiene la información necesaria para derivar la clave maestra usada por LSASS para cifrar los hashes de contraseñas dentro del archivo NTDS.dit. Sin este hive, no es posible descifrar correctamente los hashes extraídos, lo que hace que su obtención sea un paso crucial en la técnica de volcado de credenciales (MITRE ATT&CK T1003.003).

--------

<h3 style="color: #9FEF00;"> Task 5. During the June 2024 campaign, an adversary was observed using a Zero-Day Exploitation targeting Versa Director. What is the name of the Software/Malware that was used? </h3>

Bien, en el reporte de MITRE que hemos estado siguiendo mencionan un [Versa Director Zero Day Exploitation](https://attack.mitre.org/campaigns/C0039/)

Así que expliquemos un poco de lo que mencionan.

Versa Director es un componente central de la solución de SD-WAN (Software Defined Wide Area Network) de la empresa Versa Networks. Actúa como el panel de control centralizado que gestiona la conectividad, seguridad, y configuraciones de redes distribuidas en grandes organizaciones, proveedores de servicios (ISPs y MSPs), etc.

Hablan de  CVE-2024-39717, que es una vulnerabilidad de día cero (zero-day) explotada por el grupo de amenaza Volt Typhoon entre junio y agosto de 2024.

 - Permite acceso no autorizado a servidores Versa Director vulnerables.

 - Su objetivo principal fue: captura de credenciales desde servidores comprometidos pertenecientes a MSPs (Managed Service Providers) e ISPs (Internet Service Providers).

 - Esto les permitió acceder indirectamente a los clientes de esos proveedores → un vector de ataque en cadena.

`VersaMem`es el nombre dado a una web shell utilizada por los atacantes después de comprometer el sistema Versa Director. Es precisamente esto lo que nos piden. 

¿Qué hace VersaMem?
 - Robo de credenciales
 - Ejecución de código (comandos, cargas maliciosas, etc.)
 - Posiblemente diseñada para ser sigilosa en memoria (de ahí el nombre "Mem", por memory), dificultando su detección con herramientas tradicionales.

----

<h3 style="color: #9FEF00;"> Task 6. According to the Server Software Component, what type of malware was observed? </h3>

En el reporte presentado en la pregunta anterior mencionan que se trata de una `web shell`. 
Una web shell es un script malicioso (por ejemplo, en PHP, JSP o ASPX) que un atacante carga en un servidor web para ejecutar comandos remotamente, extraer información, o incluso mantener persistencia en el sistema.

-----

<h3 style="color: #9FEF00;"> Task 7. Where did the malware store captured credentials? </h3>

Siguiendo el enlace para la [información sobre VersaMem](https://attack.mitre.org/software/S1154/) ya podemos ver que se trata de un web shell escrito en Java y desplegada como un Java Archive(JAR). 

En este reporte podemos encontrar que las credenciales capturadas se almacenan en `/tmp/.temp.data`

-----

<h3 style="color: #9FEF00;"> Task 8. According to MITRE’s reference, a Lumen/Black Lotus Labs article(Taking The Crossroads: The Versa Director Zero-Day Exploitaiton.), what was the filename of the first malware version scanned on VirusTotal? </h3>

En el [reporte mencionado](https://blog.lumen.com/uncovering-the-versa-director-zero-day-exploitation/) podemos encontrar que la web shell, nombrada como `VersaTest.png`, se subió a virus total por primera vez el Junio 7 del 2024. 

------

<h3 style="color: #9FEF00;"> Task 9. What is the SHA256 hash of the file? </h3>

El hash de este fichero es `4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37`

----

<h3 style="color: #9FEF00;"> Task 10. According to VirusTotal, what is the file type of the malware? </h3>

Esto lo podemos ver también en el reporte de `Lumen`, se trata de un JAR, que ya habíamos determinado esto en una pregunta anterior. 

-----

<h3 style="color: #9FEF00;"> Task 11. What is the 'Created by' value in the file's Manifest according to VirusTotal? </h3>

Tomamos el hash, lo subimos a virus total y buscamos el Created-By. 

![](../assets/images/sherlock-electric/1.png)

Este es un archivo de metadatos incluido en archivos Java JAR. Contiene información sobre cómo debe comportarse el archivo, quién lo construyó, qué clase principal ejecuta, y otros detalles que ayudan tanto al entorno de ejecución Java como a los desarrolladores o analistas a entender cómo se creó el archivo.

------

<h3 style="color: #9FEF00;"> Task 12. What is the CVE identifier associated with this malware and vulnerability? </h3>

Esto también se puede ver en el reporte: 

![](../assets/images/sherlock-electric/1.png)

**CVE‑2024‑39717** 

- Tipo: CWE‑434 (Subida sin restricciones de ficheros de tipos peligrosos)
- Vector de ataque: Un usuario autenticado con privilegios Provider-Data-Center-Admin o Provider-Data-Center-System-Admin puede abusar de la funcionalidad “Change Favicon” en la GUI de Versa Director para subir un fichero con extensión .png que en realidad contenga código malicioso 
nvd.nist.gov
incibe.es
.
- Descripción: Versa Director ofrece una opción para personalizar la apariencia (favicon) de la interfaz. Al no validar correctamente el contenido más allá de la extensión, es posible cargar un payload malicioso que luego puede activarse en el servidor.

------

<h3 style="color: #9FEF00;"> Task 13. According to the CISA document(https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf) referenced by MITRE, what is the primary strategy Volt Typhoon uses for defense evasion? </h3>

Yendo a este reporte, en la sección de `Defense Evation`, mencionan que el grupo usa LOTL como principar técnica, que es el acrónimo de Living Off The Land, que en el contexto de ciberseguridad significa:

“Vivir de la tierra”

> Utilizar exclusivamente herramientas, utilidades y procesos nativos del sistema operativo o de la red, en lugar de introducir malware o binarios externos, para llevar a cabo acciones maliciosas y así evadir detección

Al usar comandos y utilidades ya presentes en el sistema (por ejemplo: wmic, netsh, certutil, PowerShell, ntdsutil), no se generan alertas de instalación de software extraño ni firmas de archivos maliciosos.


-----

<h3 style="color: #9FEF00;"> Task 14. In the CISA document, which file name is associated with the command potentially used to analyze logon patterns by Volt Typhoon? </h3>

El archivo es: `C:\users\public\documents\user.dat`

Y explican lo siguiente: 

1. **Origen del nombre y ubicación**

   * El archivo se crea mediante un comando de PowerShell que extrae las entradas de logon exitoso (`` Get-EventLog security -instanceid 4624 - after [year-month-date] | fl * | Out-File 'C:\users\public\documents\user.dat'.).
   * Ubicarlo en `C:\Users\Public\Documents` permite que cualquier usuario—incluido el propio atacante—tenga permisos de lectura/escritura sin levantar alerta por rutas inusuales.

2. **Propósito del fichero**

   * Almacena de forma estructurada los eventos de seguridad relacionados con inicios de sesión exitosos.
   * Facilita el **análisis posterior**, ya sea manual o mediante scripts, para identificar patrones de autenticación, picos inusuales de inicio de sesión, cuentas objetivo o comportamiento atípico de usuarios privilegiados.

3. **Evasión de detección y persistencia**

   * Al usar un fichero con extensión genérica `.dat`, se reduce la probabilidad de que soluciones EDR/AV lo identifiquen como herramienta maliciosa.
   * El actor puede revisar o exfiltrar selectivamente `user.dat` para extraer solo la información de interés, dejando el resto de registros intactos para no alterar el funcionamiento normal del servidor.

4. **Mapeo a MITRE ATT\&CK**

   * Esta actividad se corresponde con **T1654: Log Enumeration**, donde Volt Typhoon aprovecha **Living Off The Land** (LOTL) para recolectar datos sin introducir binarios externos.

