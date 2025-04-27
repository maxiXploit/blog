

# **Sherlock - Campfire1**

Para este laboratorio estaremos trabajando con un par de ficheros .evtx y un monton de ficheros .pf que son archivos de Prefetch de Windows.

Estaremos investigando lo que parece ser un Kerberoasting attack: 

La carpeta que tienes (`prefetch`) contiene **archivos .pf** que son archivos de **Prefetch** de Windows.  
Estos archivos los crea automáticamente Windows para **acelerar el arranque de programas**. Básicamente, cuando ejecutas un programa, Windows guarda un `.pf` para registrar **qué archivos usa ese programa y cuánto tarda**. Luego, en futuras ejecuciones, Windows puede cargar todo eso más rápido.

Ahora, en **forense**. los Prefetch son muy útiles porque:  
- **Confirman que un programa fue ejecutado** (por ejemplo, si ves `mimikatz.exe.pf`, alguien corrió Mimikatz).
- **Muestran la fecha y hora de última ejecución**.
- **A veces registran varios timestamps de ejecución** (en sistemas más nuevos).
- **Indican la ruta original del ejecutable** y **qué archivos cargó**.

Para parsear estos ficheros usaremos la herramienta de Eric Zimmerman, PECmd, que nos permite parsear ficheros .pf a un csv, podemos hacerlo con el siguiente comando

![](../assets/images/sherlock-campfire1/imagen1.pg)

Una vez parseado el contenido correctamente, podemos usar el Timeline Explorer para tener una visualización más cómoda del cvs y pasar a responder las preguntas. 

---
**task 1**

Analizando los registros de seguridad del controlador de dominio, ¿puede confirmar la fecha y hora en que se produjo la actividad de kerberoasting?
