


---

**Scenario: An ex-employee, who appears to hold a grudge against their former boss, is displaying suspicious behavior. We seek assistance in uncovering their intentions or plans.**

Para este laboratorio se nos da un solo fichero:

Tenemos que montarlo en nuestro sistema.

`hackerman.img` es una imagen raw de disco completo (no de una sola partición) — por eso el file/lsblk nos dice que tiene un MBR con tabla de particiones extendida. El kernel no puede montar directamente una imagen así porque no sabe dónde empieza cada partición dentro del archivo.

`kpartx` lee la tabla de particiones de la imagen y crea device mapper nodes (/dev/mapper/loop0pX) para cada partición que encuentra, calculando automáticamente los offsets. Las flags:

-a → add (crea los mappings)
-v → verbose (para que veas qué particiones detectó)

Lo que vemos en lsblk -f
- `loop0p1` → sin FSTYPE, probablemente la partición de boot/MBR reservada o algo no reconocido por blkid
- `loop0p2` → FAT32, típicamente EFI System Partition
- `loop0p3` → ext4, esta es la que te interesa — el filesystem raíz de Linux con el contenido real del sistema

Por eso hay que montar `loop0p3`: ahí está el sistema de archivos con la evidencia.

Y montamos con `mount -o ro,noload /dev/mapper/loop0p3 /mnt/hackerman`.

--------

What is the MD5 hash of the image?

********************************

Submit Task
Task 2

Hint
What is the SHA256 hash of the file in the "hackerman" desktop?

****************************************************************

Submit Task
Task 3

Hint
What command did the user use to install Google Chrome?

**** **** -* ******-******-******_*******_*****.***

Submit Task
Task 4

Hint
When was the Gimp app installed?

YYYY-MM-DD hh:mm:ss

Submit Task
Task 5

Hint
What is the hidden secret that the attacker believes they have successfully concealed in a secret file?

*_****_**_****_**_****

Submit Task
Task 6

Hint
What was the UUID of the main root volume?

********-****-****-****-************

Submit Task
Task 7

Hint
How many privileged commands did the user run?

**

Submit Task
Task 8

Hint
What is the last thing the user searches for in the installed browser?

*** ** ***** * ****** ** ********* ******* ** ** ****

Submit Task
Task 9

Hint
From Q8 we know that the user tried to write a script, what is the script name that the user wrote?

******************.**

Submit Task
Task 10

Hint
What is the URL that the user uses to download the malware?

*****://****.**/************

Submit Task
Task 11

Hint
What is the name of the malware that the user tried to download?

*****

Submit Task
Task 12

Hint
What is the IP address associated with the domain that the user pinged?

***.***.***.***

Submit Task
Task 13

Hint
What is the password hash of the "hackerman" user?

