---
layout: single
title: Cyberdefenders - Lespion
excerpt: Ejercicio de inteligencia de amenazas en el que simulan un entorno bastate realista.
date: 2025-05-25
classes: wide
header:
  teaser: ../assets/images/sherlock-bumbleebe/
  teaser_home_page: true
  icon: ../assets/images/logo-icon.svg
categories:
   - cyberdefenders
   - threat intelligence
tags:
   - osint
   - git hub history
   - social media
   - threat intel

---

Para este laboratorio se nos proporciona lo siguiente: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/lespio]
└─$ tree temp_extract_dir
temp_extract_dir
├── Github.txt
├── office.jpg
└── WebCam.png

1 directory, 3 files
```

Así que podemo pasar brevemente a las preguntas:

----

<h3 style="color: #0d6efd;">Q1. File -> Github.txt: What API key did the insider add to his GitHub repositories? </h3>

Leyendo el fichero Github.txt obtenemos el enlace a un perfil, nos preguntan por un repositorio así que suponemos que se trata del primero, que es públicó.

![](../assets/images/cyber-lespion/1.png)

Explorando el repositorio encontramos que efectivamente en el fichero Login Page.js hay una APIkey en el historial de cambios: 

![](../assets/images/cyber-lespion/2.png)

Cuando se sube un repositorio a un servicio público (como GitHub), todo el mundo—incluidos atacantes automatizados—puede descargar el código y extraer la clave. Con ella, podrían realizar llamadas a la API haciéndose pasar por la aplicación, lo que puede derivar en cargos económicos, pérdida de datos o abuso de tus recursos.

Supongamos que esta API Key da acceso a un servicio de almacenamiento en la nube:

```bash
curl -H "Authorization: Bearer aJFRaLHjMXvYZgLPwiJkroYLGRkNBW" \
     https://api.cloudstorage.com/v1/buckets/mi-bucket
```
Cualquiera, con la clave, podría:

- Leer, borrar o modificar archivos sensibles.
- Generar facturas millonarias de almacenamiento.
- Emprender ataques de denegación de servicio sobre la cuenta de la API.

----

<h3 style="color: #0d6efd;">Q2. File -> Github.txt: What plaintext password did the insider add to his GitHub repositories? </h3>

Explorando este Login Page.txt, podemos ver una contraseña en base64:

![](../assets/images/cyber-lespion/3.png)

```bash 
┌──(kali㉿kali)-[~/blue-labs/lespio]
└─$ echo "UGljYXNzb0JhZ3VldHRlOTk=" | base64 -d
PicassoBaguette99 
```

-------

<h3 style="color: #0d6efd;">Q3. File -> Github.txt: What cryptocurrency mining tool did the insider use? </h3>

Explorando el perfil podemos ver lo siguiente: 

![](../assets/images/cyber-lespion/4.png)

XMRig es un software de minería de código abierto y alto rendimiento diseñado principalmente para la criptomoneda Monero (XMR).

Modalidades de uso:
    - CPU Mining: utiliza el procesador para calcular hashes.
    - GPU Mining (opcional con forks): usa tarjetas gráficas para acelerar el proceso.

Características técnicas:
    - Implementa el algoritmo CryptoNight (y sus variantes) optimizado en C/C++.
    - Soporta múltiples sistemas operativos (Windows, Linux, macOS).
    - Permite conectarse a pools de minería o minar en solitario.
    - Contiene opciones de configuración muy flexibles (threads, afinidad, intensidad, URLs de los pools, etc.).

-----

<h3 style="color: #0d6efd;">Q4. On which gaming website did the insider have an account? </h3>

Aquí simplemente realicé google dorking: 

![](../assets/images/cyber-lespion/5.png)

----

<h3 style="color: #0d6efd;">Q5. What is the link to the insider Instagram profile?</h3>

Con la misma búsqueda de la pregunta anterior encontramos un perfil de instagram: 

![](../assets/images/cyber-lespion/6.png)

------

<h3 style="color: #0d6efd;">Q6. Which country did the insider visit on her holiday? </h3>

En el perfil nos encontramos la siguiente imagen: 

![](../assets/images/cyber-lespion/7.png)

En los comentario encontramos el pais, pero igual podemos buscarlo con google lens: 

-----

<h3 style="color: #0d6efd;">Q7. Which city does the insider family live in? </h3>

En el perfil nos encontramos la siguiente publicación, donde menciona que visia a su familia, la publicación consta de 2 fotos, la que se muestra es la que nos interesa: 

![](../assets/images/cyber-lespion/8.png)

Buscando en google parece que vive en una famosa ciudad en los Emiratos Árabes: 

![](../assets/images/cyber-lespion/9.png)

----

<h3 style="color: #0d6efd;">Q8. File -> office.jpg: You have been provided with a picture of the building in which the company has an office. Which city is the company located in? </h3>

Si subimos la imagen a google lens encontramos facilmente que se trata de la estacíón New Street, Birmingham, Inglaterra. 

![](../assets/images/cyber-lespion/10.png)

-----

<h3 style="color: #0d6efd;">Q9. File -> Webcam.png: With the intel, you have provided, our ground surveillance unit is now overlooking the person of interest suspected address. They saw them leaving their apartment and followed them to the airport. Their plane took off and landed in another country. Our intelligence team spotted the target with this IP camera. Which state is this camera in? </h3>

Subiendo esta imagen a google lens encontramos que se trata de la Universidad de Notre Dame, en el estado de Indiana, USA. 

