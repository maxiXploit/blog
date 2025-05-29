---
layout: single
title: Cyberdefenders - Eli
excerpt: Investigación forense enfocada en artefactos de usuario como datos de navegación, descargas y otros datos de navegación de internet. 
date: 2025-05-24
classes: wide
header:
  teaser: ../assets/images/sherlock-bumbleebe/
  teaser_home_page: true
  icon: ../assets/images/logo-icon.svg
categories:
   - cyberdefenders
   - DFIR
   - endping forensics
   - linux
tags:
   - sqlite3 
   - grep 
---

Para este laboratorio se nos proporcionan gran cantidad de ficheros, relacionados con la huella digital de un usuario, como historial de búsquedas, emails, ficheros de sistema, etc. Nuestro objetivo es analizar el comportamiento del usuario mientas repondemos las preguntas. 

<h3 style="color: #0d6efd;">Q1. The folder to store all your data in - How many files are in Eli's downloads directory? </h3>

Esto lo podemos encotrar en la siguiente ruta: `/temp_extract_dir/decrypted/mount/user/downloads`

Chrome OS(un sistema operativo moderno)para proteger los datos de cada usuario mientras el dispositivo está apagado o bloqueado, usa eCryptfs (Encrypted Cryptographic Filesystem), que es un sistema de archivos “apilado” (stacked filesystem) que se monta sobre otro sistema de ficheros existente (por ejemplo, ext4). Cada archivo y directorio queda cifrado individualmente antes de escribirlo en el disco. El sistema añade metadatos (cabecera) al propio archivo para almacenar la información necesaria para descifrarlo (sin necesidad de guardar estas claves en texto claro).

- Al iniciar sesión, el usuario introduce su contraseña.
- Chrome OS la usa para desbloquear la clave maestra de eCryptfs.
- Entonces, el sistema monta (de forma transparente) la carpeta del usuario sobre la versión cifrada. Esto permite que el usuario lea y escriba ficheros como si estuvieran en texto claro; el cifrado/descifrado ocurre “al vuelo”.
- Al cerrar sesión o suspender, ese montaje se desmonta y los datos vuelven a quedar únicamente en su forma cifrada en disco.

Contamos 6 ficheros en el directorio `Downloads`: 

```bash 
┌──(kali㉿kali)-[~/…/temp_extract_dir/decrypted/mount/user]
└─$ ls Downloads
 network_diagnostics_2021-03-08.19-04-05.txt   third_party_1613945285717.jpg
'Screenshot 2021-03-04 at 3.16.31 AM.png'      tux.png
'Screenshot 2021-03-04 at 3.17.06 AM.png'      Wickr-Customer-Security-Promises-November-2020.pdf
```

---

<h3 style="color: #0d6efd;">Q2. Smile for the camera - What is the MD5 hash of the user's profile photo? </h3>

En ChromeOS, las imágenes del perfil se almacenan en `Accounts/Avatar Images/`, navegando a esta ruta encontramos lo siguiente: 

```bash 
┌──(kali㉿kali)-[~/…/temp_extract_dir/decrypted/mount/user]
└─$ file Accounts/Avatar\ Images/eflatt610@gmail.com
Accounts/Avatar Images/eflatt610@gmail.com: PNG image data, 64 x 64, 8-bit/color RGB, non-interlaced

┌──(kali㉿kali)-[~/…/temp_extract_dir/decrypted/mount/user]
└─$ md5sum Accounts/Avatar\ Images/eflatt610@gmail.com
5ddd4fe0041839deb0a4b0252002127b  Accounts/Avatar Images/eflatt610@gmail.com
```

----

<h3 style="color: #0d6efd;">Q3. Road Trip! - What city was Eli's destination in? </h3>

Para esto, podemos visitar la siguiente ruta: 

```bash 
┌──(kali㉿kali)-[~/…/temp_extract_dir/Takeout/My Activity/Maps]
└─$ ls
MyActivity.html
```

Abriendo en el navegador podemos ver lo siguiente:

![](../assets/images/cyber-chros/1.png)

Esto ayuda a correlacionar actividad del usuario que ayuda para la investigación. 

---

<h3 style="color: #0d6efd;">Q4. Promise Me - How many promises does Wickr make?</h3>

Wickr es una empresa de software estadounidense conocida por su aplicación de mensajería instantánea del mismo nombre, que permite a los usuarios intercambiar mensajes cifrados de extremo a extremo y con contenido que se autodestruye.

En las promesas de Wickr se revelan detalles sobre las promesas de seguridad de Wickr, que describen las medidas adoptadas para garantizar la integridad, autenticación y cifrado de los datos.

Encotramos el documento de las promesas en la carpeta de descargas del usuario: 

```bash 
┌──(kali㉿kali)-[~/…/decrypted/mount/user/Downloads]
└─$ ls
 network_diagnostics_2021-03-08.19-04-05.txt   third_party_1613945285717.jpg
'Screenshot 2021-03-04 at 3.16.31 AM.png'      tux.png
'Screenshot 2021-03-04 at 3.17.06 AM.png'      Wickr-Customer-Security-Promises-November-2020.pdf
```

![}(../assets/images/cyber-chros/2.png)

Podemos ver 9 promesas en el documento. 

---

<h3 style="color: #0d6efd;">Q5. Key-ty Cat - What are the last five characters of the key for the Tabby Cat extension? </h3>

La extensión Tabby Cat es una extensión de Chrome que muestra un nuevo animal en cada nueva pestaña, con la intención de alegrar el día al usuario con mascotas interactivas como gatos, perros, pingüinos, conejos y cerdos. Estas mascotas pueden parpadear, dormir e incluso dejarse acariciar, de forma similar a los animales de verdad.

En el contexto de las extensiones de navegador (por ejemplo Chrome o Chromium), la propiedad key que a veces ves en el fichero manifest.json cumple dos funciones principales:

1. Estabilizar el ID de la extensión

- Cada extensión en Chrome tiene un identificador único (un string de 32 caracteres hexadecimal, ej. abcdefghijklmnopqrstuvwx12345678).
- Por defecto, ese ID se genera de forma determinística a partir de la clave pública de la extensión en el momento del empaquetado (.crx).
- Si tú incluyes manualmente en el manifiesto la propiedad "key", le estás indicando a Chrome: “usa esta clave pública para calcular mi ID, así no cambiará aunque reapaque el .crx”.
- De este modo, tanto si instalas la extensión localmente como si la distribuyes desde la Web Store, conservará siempre el mismo ID.

2. Formato de la clave
- La propiedad "key" es en realidad la clave pública codificada en Base64 (normalmente un blob PKCS#8 DER).
- Chrome extrae de ese Base64 la clave pública, la transforma a binario, y luego aplica un hash SHA-256 para derivar tu ID.

Podemos ir a la siguiente ruta: 

```bash 
┌──(kali㉿kali)-[~/…/user/Extensions/mefhakmgclhhfbdadeojlkbllmecialg/2.0.0_0]
└─$ cat manifest.json
{
   "author": "Leslie Zacharkow",
   "chrome_url_overrides": {
      "newtab": "public/index.html"
   },
   "description": "A new friend in every tab.",
   "icons": {
      "128": "icon128.png"
   },
   "key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjA9ElNuqHGIuDyrztUxn0nV1CLRgjSHEKw1zfhzE/6OdWd3teRV9wq4EukIX8UKf96fhS2WsLVnTuRmF7mQuqeAIxOkSvFm4Set3YRQ5994NA8Y9un1ZGhPtjFnpoLo1pEA5PPly5/BX2y3Ci2Rb0C3wp8NdeXud4r6BKEzhPdWmkwIS+YbTWhOBR1IbP/sF6+l8EdG/Ks881p8LO0J3qepmhNDA/LjVWzJq5ARmIYeT3TnvR/qRGTY9UXfUvg3gcUWV2LBBpeil8t6Np0PVYvG44zOBhKUnYSVE6gAcXENLTJJABgRgKT1K1kDYl1N8LJZf/S/9Ix1P+wItoEinTwIDAQAB",
   "manifest_version": 2,
   "name": "Tabby Cat",
   "offline_enabled": true,
   "permissions": [ "storage" ],
   "update_url": "https://clients2.google.com/service/update2/crx",
   "version": "2.0.0"
}
```

----

<h3 style="color: #0d6efd;">Q6. Time to jam out - How many songs does Eli have downloaded? </h3>

Podemos verlo en la siguiente ruta: 

```bash 
┌──(kali㉿kali)-[~/…/mount/user/MyFiles/Music]
└─$ ls
'alt-J (∆) Breezeblocks.mp3'  'Leave - Post Malone.mp3'
```

Más data que podemos coorrelacionar con el usuario. 

----

<h3 style="color: #0d6efd;">Q7. Autofill, roll out - Which word was Autofilled the most? </h3>

El autofill es la característica que permite al navegador rellenar formularios basado en datos que el usurio puso en otros formularis previamente. Así que analizamos el fichero `Web Data` que se encuentra en el directorio del usuario, 

```bash 
┌──(kali㉿kali)-[~/…/temp_extract_dir/decrypted/mount/user]
└─$ sqlite3 Web\ Data
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
autofill                   masked_credit_cards
autofill_model_type_state  meta
autofill_profile_emails    payment_method_manifest
autofill_profile_names     payments_customer_data
autofill_profile_phones    server_address_metadata
autofill_profiles          server_addresses
autofill_profiles_trash    server_card_metadata
autofill_sync_metadata     token_service
credit_cards               unmasked_credit_cards
keywords                   web_app_manifest_section
sqlite> .headers on
sqlite> .mode columns
sqlite> SELECT * FROM autofill;
name    value                      value_lower                date_created  date_last_used  count
------  -------------------------  -------------------------  ------------  --------------  -----
guests  1 Guest                    1 guest                    1612397725    1612397725      1
email   e.flatt610@gmail.com       e.flatt610@gmail.com       1613524166    1614846543      3
email   e.flatt610@protonmail.com  e.flatt610@protonmail.com  1614846564    1614846564      1
sqlite>
```

Vemos que el valor `e.flatt610@gmail.com` es el que más se repite, pudiendo indicar que es la cuenta de correo principal del usuario. 

---

<h3 style="color: #0d6efd;">Q8. Dress for success - What is this bird's image's logical size in bytes? </h3>

Buscando esto, parece que se refieren a Tux, la mascota de linux, que es un pingüino precisamente. 

En la siguiente ruta podemos ver la info: 

```bash 
┌──(kali㉿kali)-[~/…/temp_extract_dir/decrypted/mount/user]
└─$ ls -ls Downloads/tux.png
48 -rw-r--r-- 1 kali kali 46791 Apr  5  2021 Downloads/tux.png
```

- El primer valor, 48, corresponde al número de bloques de disco ocupados por el fichero (normalmente de 1 KiB cada uno, según la configuración de tu sistema).
- El valor 46791 es el tamaño real del fichero en bytes.

----

<h3 style="color: #0d6efd;">Q9. Repeat customer - What was Eli's top-visited site? </h3>

Lo vemos en la siguiente ruta: `/temp_extract_dir/Takeout/My Activity/Chrome/MyActivity.html`

![](../assets/images/cyber-chros/3.png)

Vemos bastante actividad sobre proton mail. 
---

<h3 style="color: #0d6efd;"Q10 Vroom Vroom, What is the name of the car-related theme? </h3>

Chrome almacena las extensiones y los temas instalados en un formato estructurado dentro de este directorio, donde cada extensión se identifica con un nombre de carpeta alfanumérico único. Dentro de cada carpeta de extensión, un archivo manifest.json proporciona metadatos sobre la extensión o el tema, incluido su nombre, permisos y otros atributos relevantes.

Finalmente, podemos encontrar la respuesta a esta pregunta en la siguiente ruta: `/temp_extract_dir/decrypted/mount/user/Extensions/dkkklbgbfaeockpgbkleblklmcjdbnbj/1_0/manifest.json`

```bash 
{
   "description": "Lambroghini Cherry",
   "key": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkqKU3UqdDvEEbE02cxMeXkdPqTU3FaA48eDRGht3vrH2gI2XoDaFYKgEfBIMlvJkWfCZwMigyg1mmPg6Tkx9G4R0abm4HBd9FxOsfB6dYI4yEQYWLQIqvxLifK9Pb7zyQpghp4ovjuPQzKai8tljnKBUyqE2MSNGem4ldf3CbUwIDAQAB",
   "manifest_version": 2,
   "name": "Lamborghini Cherry ",
   "theme": {
      "colors": {
         "bookmark_text": [ 255, 255, 255 ],
         "button_background": [ 157, 0, 0, 1 ],
         "frame": [ 172, 162, 179 ],
         "ntp_background": [ 255, 255, 255 ],
         "ntp_text": [ 239, 0, 0 ],
         "tab_background_text": [ 0, 0, 0 ],
         "tab_text": [ 0, 0, 0 ],
         "toolbar": [ 175, 0, 0 ]
      },
```

----

<h3 style="color: #0d6efd;">Q11. You got mail - How many emails were received from notification@service.tiktok.com? </h3>

Para responder a esto tenemos que analizar el archivo MBOX ubicado en los datos de la siguiente ruta: `/chrome/temp_extract_dir/Takeout/Mail/'All mail Including Spam and Trash.mbox'` 

Este archivo contiene todos los correos electrónicos de Eli, incluidos los de las carpetas Bandeja de entrada, Spam y Papelera. Para extraer los mensajes de correo electrónico relevantes

Los archivos MBOX son un formato estándar para almacenar mensajes de correo electrónico, en el que todos los correos electrónicos se concatenan en un único archivo. Estos archivos pueden examinarse utilizando herramientas especializadas como Mozilla Thunderbird, MBox Viewer, o incluso editores de texto como Notepad++ para la inspección manual. 

Usando grep: 

```bash 
┌──(kali㉿kali)-[~/…/chrome/temp_extract_dir/Takeout/Mail]
└─$ grep "notification\@service\.tiktok\.com" All\ mail\ Including\ Spam\ and\ Trash.mbox
Message-ID: <d63f8acd-b291-4d70-88f9-9caa7a5e2f5d.notification@service.tiktok.com>
From: "TikTok" <notification@service.tiktok.com>
Reply-To: notification@service.tiktok.com
Reply-To: notification@service.tiktok.com
From: "TikTok" <notification@service.tiktok.com>
Message-ID: <89693bf6-6612-45dc-8fa7-54fd431d0c2c.notification@service.tiktok.com>
Reply-To: notification@service.tiktok.com
From: "TikTok" <notification@service.tiktok.com>
Message-ID: <f74c25a4-91f5-4f28-b521-2803b21be559.notification@service.tiktok.com>
Message-ID: <4fae99bd-e0fd-4d14-a553-1a29b6f7466e.notification@service.tiktok.com>
From: "TikTok" <notification@service.tiktok.com>
Reply-To: notification@service.tiktok.com
From: "TikTok" <notification@service.tiktok.com>
Message-ID: <8c570c87-f8bf-43eb-a8e9-3e8d5ba736df.notification@service.tiktok.com>
Reply-To: notification@service.tiktok.com
Message-ID: <f1f16fc7-ea51-4dd1-9d86-8617cddbfd0e.notification@service.tiktok.com>
Reply-To: notification@service.tiktok.com
From: "TikTok" <notification@service.tiktok.com>

┌──(kali㉿kali)-[~/…/chrome/temp_extract_dir/Takeout/Mail]
└─$ grep 'From: "TikTok"' All\ mail\ Including\ Spam\ and\ Trash.mbox
From: "TikTok" <notification@service.tiktok.com>
From: "TikTok" <notification@service.tiktok.com>
From: "TikTok" <notification@service.tiktok.com>
From: "TikTok" <notification@service.tiktok.com>
From: "TikTok" <notification@service.tiktok.com>
From: "TikTok" <notification@service.tiktok.com>
```

----

<h3 style="color: #0d6efd;">Q12. Hungry for directions - Where did the user request directions to on Mar 4, 2021, at 4:15:18 AM EDT</h3>

Para esto vamos al siguiente directorio: `/temp_extract_dir/Takeout/My Activity/Maps/MyActivity.html`

Aquí es donde encontramos información de búsqueda del usuarios: 

![](../assets/images/cyber-chros/5.png)

Podría indicar que planeaba viajar a dicho lugar. 




-----

<h3 style="color: #0d6efd;">Q13. Who defines essential? - What was searched on Mar 4, 2021, at 4:09:35 AM EDT</h3>

Vamos a la siguiente ruta: `/temp_extract_dir/Takeout/My Activity/Search/MyActivity.html`

![](../assets/images/cyber-chros/4.png)

Parece que planeaba ir por comida. 

----

<h3 style="color: #0d6efd;">Q </h3>

Vamos a la siguiente ruta: 

```bash 
┌──(kali㉿kali)-[~/…/temp_extract_dir/Takeout/YouTube and YouTube Music/subscriptions]
└─$ ls
subscriptions.json

┌──(kali㉿kali)-[~/…/temp_extract_dir/Takeout/YouTube and YouTube Music/subscriptions]
└─$ cat subscriptions.json
[ ]                        
```

Parece que Eli no tenía fans

----

<h3 style="color: #0d6efd;">Q15. Time flies when you're watching YT - What date was the first YouTube video the user watched uploaded? </h3>

Vamos a la siguiente ruta: `/temp_extract_dir/Takeout/YouTube and YouTube Music/history/watch-history.html`

![](../assets/images/cyber-chros/7.png)

Si entramos al video, vemos que se subió el 27 de enero del 2021
