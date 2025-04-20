---
layout: single
title: Dream Job1 - Sherlock Hack The Box
excerpt: Una reporte bastante resumido sobre la Operación Dream Job dirigida por el Lazarus Group y que se llevó a cabo a través de la plataforma de Linkedin. Una campaña de phishing altamente diriga con la finalidad de espiar y exfiltrar datos de sectores como la tecnología y la aviación. 
date: 2025-4-19
classes: wide
header: 
   teaser: /assets/images/htb-sherlock-dreamjob1/dreamjob1.webp
   teaser_home_page: true 
categories: 
   - cyberdefenders
   - threat intelligence
tags: 
   - mittre att&ck
   - virus total 
--- 

# **Sherlock Dream Job-1 - Hack The Box**

Operation Dream Job es el nombre atribuido a una campaña de ciberespionaje identificada por múltiples firmas de ciberseguridad, en la que actores maliciosos emplean tácticas de spear-phishing altamente dirigidas, simulando ofertas laborales en compañías reconocidas como forma de atraer a profesionales del sector tecnológico, especialmente en áreas sensibles como defensa y el sector aeroespacial. 
Contactaban a las víctimas con supuestas ofertas laborales atractivas y les enviaban archivos maliciosos disfrazados de documentos relacionados con el proceso de selección. Al abrir estos archivos, se instalaba malware que permitía a los atacantes acceder a información confidencial y, en algunos casos, realizar movimientos laterales dentro de las redes comprometidas.

---
## **Antecedentes:**

### Lazarus Group

**Lazarus Group**, también conocido como Hidden Cobra, es una entidad atribuida a la República Popular Democrática de Corea (Corea del Norte) y es ampliamente reconocida por su participación en campañas de ciberespionaje, sabotaje y operaciones cibernéticas con fines financieros. Su actividad ha sido monitoreada desde al menos 2009, aunque se sospecha que sus orígenes podrían remontarse a años anteriores bajo diferentes nombres y estructuras.

Este grupo ha estado detrás de varios de los ciberataques más notorios de la última década. Entre sus operaciones más destacadas se encuentran:

- **Ataque a Sony Pictures Entertainment (2014):** Un ciberataque destructivo que involucró la exfiltración y publicación de grandes volúmenes de datos confidenciales, como represalia por la película *The Interview*, considerada ofensiva por el régimen norcoreano.
- **Campaña WannaCry (2017):** Un ataque global de ransomware que afectó a más de 200,000 sistemas en 150 países, incluyendo infraestructuras críticas como hospitales del NHS en Reino Unido. Aunque inicialmente se presentó como un ataque extorsivo, muchos analistas lo interpretan como una operación de sabotaje encubierta.
- **Campañas financieras contra bancos (SWIFT Attacks):** Lazarus ha sido vinculado con múltiples intentos de robo a través del sistema SWIFT, como el caso del Banco Central de Bangladesh en 2016, en el que se intentó sustraer casi 1,000 millones de dólares.

En años recientes, el grupo ha diversificado sus tácticas, incorporando ataques contra exchanges de criptomonedas, campañas de *watering hole*, y técnicas avanzadas de *social engineering*, como la que inspira el laboratorio **Dream Job**. En esta última, los atacantes se hacen pasar por reclutadores de empresas tecnológicas reconocidas (como Boeing, Lockheed Martin o Crypto.com) para engañar a sus objetivos y lograr la ejecución de malware, el robo de credenciales o la instalación de puertas traseras persistentes.

La sofisticación técnica, junto con una fuerte motivación estratégica y económica, convierten a Lazarus Group en uno de los actores más relevantes dentro del panorama global de amenazas persistentes avanzadas (APT).

## **Acceso inicial**

A diferencia de otros métodos de ataque conocidos, en los que la mayoría de los esfuerzos se concentran en el contacto inicial, en este escenario de ataque los recursos y esfuerzos se invierten tanto en la creación de la entidad (identidad falsa) como en la comunicación con las víctimas. Incluso si la víctima no está interesada en la posición ofrecida por el atacante, se le persuade para que revise detenidamente los detalles del puesto “exclusivo” antes de tomar una decisión definitiva. La oferta de empleo está personalizada y se presenta de forma discreta, lo que aumenta su credibilidad y reduce la sospecha de que se trata de un ataque dirigido. Esta discreción permite al atacante mantener una negociación prolongada con la víctima, ya que el proceso no pone en riesgo su posición laboral actual. — ClearSky Cyber Security, Dream Job Campaign, 2020.

El ataque, al ser áltamente dirigido, daba más probabilidad de que fuera efectivo, piénsalo, si te muestran una oferta que incluya muchas de tus habilidades, es casi seguro que al menos aceptes revisar la oferta que viene adjunta al correo que recibiste: Salary_Lockheed_Martin_job_opportunities_confidential.doc. ☠️

Conocer la forma en la que lograban el acceso inicial debería hacer saltar las alarmas de todo aquel que haya logrado acceder a este blog. El uso de plataformas para buscar trabajo, y con el creciente uso de de internet, obliga a todo aquel que las use a tomar consciencia sobre las acciones que realiza en la red. 

## **En la mira de Linkedin**

El atacante creaba un perfil falso en esta plataforma, impersonando a un reclutador real o creando un perfil de una persona que no existe, y creando una red de contactos con las personas del sector en el que estaban interesados. 

El atacante se ganaba la confianza del usuario, manteniendo una comunicación contínua lograba convencer a la víctima de al menor revisar la oferta de trabajo, oferta que era envíada a través de un fichero usando servicios de alamcenamiento como OneDrive o DropBox, estudiaban a la víctima, analizando sus rutinas y horarios para que la víctima abra el fichero en su lugar de trabajo, mandándolo a una hora cuidadosamente seleccionada. El fichero contenia el malware que permitía el acceso remoto a los sistemas de la empresa y el atacante trataba de que la persona recibiera el fichero fuera linkedin, trataban de enviarlo por correo electrónico, y evitando mandarlo por el correo empresarial. 

Una vez que la víctima descargó el fichero, el atacante eliminaba el perfil falso.  

---

## **¿Quién llevó a cabo la Operación Dream Job?**

Lazarous Group

---
## **¿Cuándo se observó esta operación por primera vez?**

### Primera Observación

Según la base de datos de MITRE ATT&CK, **Operation Dream Job** fue **observada por primera vez en septiembre de 2019**.

Symantec, por su parte, documentó un subconjunto de esta operación —bajo el nombre **Pompilus**— **por primera vez en agosto de 2020**.

Adicionalmente, ClearSky publicó en agosto de 2020 un informe en el que señalaba que había **revelado evidencia de ataques de Lazarus en 2019**, marcando el inicio de la campaña “Dream Job”, inforde del cual sacamos parte de la información presentada en este informe resumido. 

---
## **Hay 2 campañas asociadas a la Operación Dream Job. Una es la Operación Estrella del Norte, ¿cuál es la otra?**

Basándonos en el informe de [MITRE ATT&CK](https://attack.mitre.org/campaigns/C0022/), la segunda campaña asociada a Operation Dream Job es conocida como Operation Interception (a veces estilizada como Operation In(ter)ception).


---
## **Durante la Operación Dream Job, había dos binarios de sistema utilizados para la ejecución proxy. Uno era Regsvr32, ¿cuál era el otro?**

Esto podemos verlos desde la sección de [ATT&CK Navigator Layers](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fcampaigns%2FC0022%2FC0022-enterprise-layer.json), en la columna de Defense Evasion. 

Regsvr32.exe es una utilidad de línea de comandos de Windows que se utiliza para registrar o desregistrar archivos DLL (Dynamic Link Library) y controles ActiveX en el Registro de Windows. En esencia, ayuda a que Windows sepa cómo encontrar y utilizar estos componentes.

Ademas de Regsvr32.exe, el otro binario empleado fue Rundll32.exe. Ambos son utilidades legítimas de Windows, firmadas por Microsoft, que los atacantes abusan para ejecutar cargas maliciosas sin invocar procesos propios detectables. 

Rundll32.exe es un ejecutable de Windows diseñado para cargar y ejecutar funciones exportadas por DLLs especificadas en línea de comandos; forma parte del sistema y está firmado por Microsoft. 

---
## **¿Qué técnica de movimiento lateral utilizó el adversario?**

En la columna de **Defense Evation** podemos ver la técnica asociada, que es **Internal Spearphishing** y se basa en utilizar el spearphishing interno para obtener acceso a información adicional o poner en peligro a otros usuarios de la misma organización

---
## **¿Cuál es la ID de la técnica para la respuesta anterior?**

Cosultando la página de [MITRE ATT&CK](https://attack.mitre.org/techniques/T1534/) para esta técnica, vemos que el ID es el  T1534. 

---
## **¿Qué troyano de acceso remoto utilizó el Grupo Lazarus en la Operación Dream Job?**

El Lazarus Group utilizó principalmente un troyano de acceso remoto (RAT) conocido como [DRATzarus](https://attack.mitre.org/software/S0694/)

---
## **¿Qué técnica utilizó el malware para su ejecución?**
Cuando un malware utiliza la Native API para ejecución, en lugar de llamar a funciones estándar como CreateProcessA o WinExec, usa funciones internas como:
- NtCreateSection
- NtMapViewOfSection
- NtCreateThreadEx
- NtWriteVirtualMemory
- Estas permiten, por ejemplo:
- Crear una sección de memoria compartida (con NtCreateSection).
- Mapear código malicioso en la memoria de otro proceso (NtMapViewOfSection).
- Escribir payloads directamente en memoria (NtWriteVirtualMemory).
- Ejecutar un hilo remoto (NtCreateThreadEx o NtResumeThread).

Este tipo de ejecución es característico de técnicas como process injection, hollowing, o reflective DLL injection.


---
## **¿Qué técnica utilizó el malware para evitar ser detectado en un sandbox?**

En la columna de **Defense Evasion** vemos la técnica **Time Based Evasion**, y consiste en que el malware modifica su comportamiento en función del tiempo, con el objetivo de:

- Retrasar su ejecución hasta que haya pasado el período típico de análisis.
- Ejecutar ciertas funciones solo en momentos específicos.
- Detectar si está corriendo en un entorno de análisis automatizado (por ejemplo, que solo ejecuta el binario durante 2 minutos).

¿Cómo se contrarresta esta técnica?
- Instrumentación del API de tiempo: en sandboxes avanzadas se interceptan y modifican llamadas como Sleep, NtDelayExecution, etc., para simular el paso del tiempo.
- Sleep patching: se modifican las instrucciones en tiempo real para que, por ejemplo, un Sleep(60000) se convierta en Sleep(1).
- Análisis dinámico prolongado: extender el tiempo de ejecución en entornos de análisis para que estas técnicas no sean efectivas.
- Análisis estático del binario: identificar llamadas sospechosas a funciones relacionadas con tiempo sin ejecutarlas.

---
## **Para responder a las preguntas restantes, utilice VirusTotal y consulte el archivo IOCs.txt. ¿Cuál es el nombre asociado al primer hash proporcionado en el archivo IOC?**

Para esto copiamos el primer hash que viene en el comprimido que nos proporciona el laboratorio, lo pegamos en virus total y podremos ver que el nombre es **IEXPLORE.exe**

---
## **¿Cuándo se creó por primera vez el archivo asociado el segundo hash del ICO?**

Copiamos y pegamos el segundo hash en virustotal, en la sección de detalles podemos ver la fecha de la creacón de este fichro. 

---
## **¿Cuál es el nombre del archivo de ejecución principal asociado a la segunda almohadilla del COI?**

Seguimos con el análisi del segundo hash proporcionado, en la sección de relations podemos ver la respuesta: BAE_HPC_SE.iso
Que es el fichero que crear el fichero objeto de estudio al ejecutarse en un sandbox. 

---
## **Examina el tercer hash. ¿Cuál es el nombre de archivo probablemente utilizado en la campaña que se ajusta a las tácticas conocidas del adversario?**

En la sección de `Details>Names` podemos ver varios nombres: 
- z0OTN6TzKIO8HWOFvYH12h7mUJOIP2
- malware_sample_003
- lazarus.doc
- 0160375e19e606d06f672be6e43f70fa70093d2a30031affd2929a5c446d07c1.doc
- Salary_Lockheed_Martin_job_opportunities_confidential.doc

El últimos es el que tiene más pinta de haber sido usado en esta campaña. 


---
## **¿Qué URL fue contactada en 2022-08-03 por el tercer hash porpocionado?**

En la sección de `Relations` podemos ver varias URL, pero por la que nos preguntan es la siguiente: `https://markettrendingcenter.com/lk_job_oppor.docx`, que desde luego tiene mucho que ver con lo que se estudia en este laboratorio. 
