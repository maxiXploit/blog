---
layout: single
title: Sherlock - UFO-1
excerpt: Ejercicio de inteligencia de amenaza sobre el APT llamado SandWorm
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

En este ejercicio de Threat Intelligence estaremos investigando las técnicas del grupo conocido como `Sandworm Team`, nos estaremos apoyando del framekor MITRE ATT&CK para desarrollar nuestra investigación. Así que pasamos directamente a las preguntas. 


----

<h3 style="color: #9FEF00;"> Task 1. According to the sources cited by Mitre, in what year did the Sandworm Team begin operations? </h3>

Referenciando directamente al [análisis de MITRE ATT&CK](https://attack.mitre.org/campaigns/C0025/)

Podemos observar que este grupo, relacionado con el gobierno y ejército Ruso, tiene actividades registradas desde el año 2009. 

-----

<h3 style="color: #9FEF00;"> Task 2. Mitre notes two credential access techniques used by the BlackEnergy group to access several hosts in the compromised network during a 2016 campaign against the Ukrainian electric power grid. One is LSASS Memory access (T1003.001). What is the Attack ID for the other? </h3>

Bien, revisando el reporte de MITRE nos encontramos con una técnica bastante conocida; los ataques de fuerza bruta, que también sirven para obtener acceso a credenciales. 

------

<h3 style="color: #9FEF00;"> Task 3. During the 2016 campaign, the adversary was observed using a VBS script during their operations. What is the name of the VBS file? </h3>

Se mencionan varios ficheros `.vbs`, pero el que nos piden es el `ufn.vbs`, usado para el movimiento lateral de herramientas. 

------

<h3 style="color: #9FEF00;"> Task 4. The APT conducted a major campaign in 2022. The server application was abused to maintain persistence. What is the Mitre Att&ck ID for the persistence technique was used by the group to allow them remote access? </h3>

En la seccion de [ATT&CK Navigator Layers](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fcampaigns%2FC0034%2FC0034-enterprise-layer.json), en la parte de `Persistence` se mencionan tres técnicas usadas por los atacantes, la relacionada con una aplicación de servidor es una `web shell`

-----

<h3 style="color: #9FEF00;"> Task 5. What is the name of the malware / tool used in question 4? </h3>

En la nota dejada en la técnica marcada de la pregunta anterior podemos ver que se señala el despliegue de una web shell llamada `Neo-REGEORGNeo-REGEORG`.

-----

<h3 style="color: #9FEF00;"> Task 6. Which SCADA application binary was abused by the group to achieve code execution on SCADA Systems in the same campaign in 2022? </h3>



SCADA ser refiere a `Supervisory Control and Data Acquisition`: 

Es un sistema utilizado para supervisar y controlar procesos industriales a distancia. Es común en sectores como:

 - Energía (eléctrica, petróleo, gas)
 - Agua y tratamiento de aguas residuales
 - Manufactura
 - Transporte
 - Plantas químicas

`scilc.exe` es un binario legítimo perteneciente a MicroSCADA, una plataforma SCADA desarrollada por ABB (Asea Brown Boveri).

 - MicroSCADA es ampliamente utilizada en sistemas eléctricos, especialmente en subestaciones para controlar y supervisar redes eléctricas.

 - scilc.exe es un componente que interpreta o ejecuta comandos escritos en SCIL (Supervisory Control Implementation Language), un lenguaje de scripting propietario usado en MicroSCADA para automatizar tareas y control de procesos.

- Por lo que los atacantes abusaron del binario scilc.exe para ejecutar comandos maliciosos usando el lenguaje SCIL.

--------

<h3 style="color: #9FEF00;"> Task 7. Identify the full command line associated with the execution of the tool from question 6 to perform actions against substations in the SCADA environment. </h3>

En el reporte mencionan que se usó el comando `C:\sc\prog\exec\scilc.exe -do pack\scil\s1.txt`, y que en el fichero `s1.txt` había una serie de instrucciones SCADA predefinidas para enviar comandos no autorizados a otras subestaciones de la infraestructura eléctrica. 

-----

<h3 style="color: #9FEF00;"> Task 8. What malware/tool was used to carry out data destruction in a compromised environment during the same campaign? </h3>

En el reporte podemos ver que en la sección de software se menciona a `CaddyWiper`. 

Un wiper es una clase de malware diseñado no para robar información, sino para destruirla o hacerla irrecuperable, corrompiendo archivos, borrando el MBR/MBR o eliminando contenido de discos.

**Características técnicas de CaddyWiper:** 

 - Desarrollado con el propósito de borrar datos del disco duro, especialmente en equipos Windows.
 - Borra archivos del sistema y datos del usuario, y sobrescribe el MBR (Master Boot Record), lo que impide que el sistema arranque.
 - No guarda persistencia: se ejecuta una vez y destruye el sistema sin dejar rastro.
 - No tiene similitudes de código directas con otros wipers conocidos como HermeticWiper o WhisperGate, lo que indica que es una herramienta distinta.

-----

<h3 style="color: #9FEF00;"> Task 9. The malware/tool identified in question 8 also had additional capabilities. What is the Mitre Att&ck ID of the specific technique it could perform in Execution tactic? </h3>

Visitando el [reporte de CanddyWiper](https://attack.mitre.org/software/S0693/), en la sección de [Navigator Layer](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0693%2FS0693-enterprise-layer.json) en la parte de `Execution` podemos ver la técnica usada, Native API en este caso. 

------

<h3 style="color: #9FEF00;"> Task 10. The Sandworm Team is known to use different tools in their campaigns. They are associated with an auto-spreading malware that acted as a ransomware while having worm-like features .What is the name of this malware? </h3>

En la página principal del grupo podemos ver todas las herramientas que usaron, entre éstas nos encontramos a `NotPetya`, que además de las características ya mencionadas, otra cosa interesantes es que se esparce a través de exploitis como EternalBlue en SMB1.

-----

<h3 style="color: #9FEF00;"> Task 11. What was the Microsoft security bulletin ID for the vulnerability that the malware from question 10 used to spread around the world? </h3>

En el contexto de Microsoft, un Security Bulletin es un documento técnico que publica la empresa para informar oficialmente sobre vulnerabilidades de seguridad descubiertas en sus productos, junto con:

 - Descripción de la vulnerabilidad
 - Productos afectados (Windows, Office, Exchange, etc.)
 - Impacto (ej. ejecución remota de código, elevación de privilegios)
 - Parche de seguridad disponible
 - ID único del boletín (por ejemplo: MS17-010)

En el reporte de NotPetya, se menciona que el malware se esparció mediante la vulnerabilidad marcada como MS17-010, que pertenece al conocido como EternalBlue. 

------

<h3 style="color: #9FEF00;"> Task 12. What is the name of the malware/tool used by the group to target modems? </h3>

Filtrando por la palabra `modem` en el reporte del SandWorm, nos encontramos con el [siguiente reporte](https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/).

Aquí se menciona a `acidrain`: 

AcidRain es un malware tipo wiper diseñado específicamente para atacar dispositivos de red Linux embebidos, como:

 - Módems satelitales

 - Routers

 - Otros equipos IoT industriales

Su función principal es borrar el contenido del sistema de archivos y del firmware, volviendo los dispositivos inservibles (soft-bricked o hard-bricked).

-----

<h3 style="color: #9FEF00;"> Task 13. Threat Actors also use non-standard ports across their infrastructure for Operational-Security purposes. On which port did the Sandworm team reportedly establish their SSH server for listening? </h3>

El reporte menciona que el grupo usó una técnica de `Non-Standard Port`, en este caso, haciendo uso del puerto 6789 para sus comunicaciones por ssh. 

-----

<h3 style="color: #9FEF00;"> Task 14. The Sandworm Team has been assisted by another APT group on various operations. Which specific group is known to have collaborated with them? </h3>

Muchos reportes señalan que el grupo Sandworm fue asistido en muchas de sus campañas por el grupo denominado `GRU Unit 26165`, también conocido como APT28. 

