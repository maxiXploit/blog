# **Sherlock Dream Job-1 - Hack The Box**

Operation Dream Job es el nombre atribuido a una campaña de ciberespionaje identificada por múltiples firmas de ciberseguridad, en la que actores maliciosos emplean tácticas de spear-phishing altamente dirigidas, simulando ofertas laborales en compañías reconocidas como forma de atraer a profesionales del sector tecnológico, especialmente en áreas sensibles como defensa y el sector aeroespacial. 
Contactaban a las víctimas con supuestas ofertas laborales atractivas y les enviaban archivos maliciosos disfrazados de documentos relacionados con el proceso de selección. Al abrir estos archivos, se instalaba malware que permitía a los atacantes acceder a información confidencial y, en algunos casos, realizar movimientos laterales dentro de las redes comprometidas.

---
## **¿Quién llevó a cabo la Operación Dream Job?**

### Lazarus Group

**Lazarus Group**, también conocido como Hidden Cobra, es una entidad atribuida a la República Popular Democrática de Corea (Corea del Norte) y es ampliamente reconocida por su participación en campañas de ciberespionaje, sabotaje y operaciones cibernéticas con fines financieros. Su actividad ha sido monitoreada desde al menos 2009, aunque se sospecha que sus orígenes podrían remontarse a años anteriores bajo diferentes nombres y estructuras.

Este grupo ha estado detrás de varios de los ciberataques más notorios de la última década. Entre sus operaciones más destacadas se encuentran:

- **Ataque a Sony Pictures Entertainment (2014):** Un ciberataque destructivo que involucró la exfiltración y publicación de grandes volúmenes de datos confidenciales, como represalia por la película *The Interview*, considerada ofensiva por el régimen norcoreano.
- **Campaña WannaCry (2017):** Un ataque global de ransomware que afectó a más de 200,000 sistemas en 150 países, incluyendo infraestructuras críticas como hospitales del NHS en Reino Unido. Aunque inicialmente se presentó como un ataque extorsivo, muchos analistas lo interpretan como una operación de sabotaje encubierta.
- **Campañas financieras contra bancos (SWIFT Attacks):** Lazarus ha sido vinculado con múltiples intentos de robo a través del sistema SWIFT, como el caso del Banco Central de Bangladesh en 2016, en el que se intentó sustraer casi 1,000 millones de dólares.

En años recientes, el grupo ha diversificado sus tácticas, incorporando ataques contra exchanges de criptomonedas, campañas de *watering hole*, y técnicas avanzadas de *social engineering*, como la que inspira el laboratorio **Dream Job**. En esta última, los atacantes se hacen pasar por reclutadores de empresas tecnológicas reconocidas (como Boeing, Lockheed Martin o Crypto.com) para engañar a sus objetivos y lograr la ejecución de malware, el robo de credenciales o la instalación de puertas traseras persistentes.

La sofisticación técnica, junto con una fuerte motivación estratégica y económica, convierten a Lazarus Group en uno de los actores más relevantes dentro del panorama global de amenazas persistentes avanzadas (APT).

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


