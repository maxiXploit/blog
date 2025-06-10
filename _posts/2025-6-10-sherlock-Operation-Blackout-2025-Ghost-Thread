---
layout: single
title: Sherlock - Operation Blackout 2025-Phantom Check
excerpt: 
date: 2025-6-7
classes: wide
header:
   teaser: ../assets/images/forwa
   teaser_home_page: true
   icon: ../assets/images/splunk-logo.jpg
categories:
   - splunk
   - windows
   - hack the box
   - sherlock
   - active directory
   - DFIR
tags:
   - .evtx
   - evtxecmd
   - virtualization
---


Para esto vamos a usar `IDA Freeware`, un desensamblador/depurador estático, y [API monitor](http://www.rohitab.com/apimonitor). 

----

<h3 style="color: #9FEF00;">Task 1. What process injection technique did the attacker use? </h3>

Primeramente vamos a explicar unas cosas: 

1. **Detección de callbacks especiales**

   * En un ejecutable de Windows, no solo hay funciones exportadas para uso externo: también se pueden registrar *callbacks* internos que el sistema invoca en momentos muy tempranos de la carga del programa.
   * Uno de estos mecanismos son los **TLS callbacks** (más abajo explico qué son). IDA, al parsear el *PE header*, sitúa estos callbacks bajo “Exports” con nombres como `TlsCallback_0`, `TlsCallback_1`, etc.
2. **Ejecución antes de `main()`**

   * Un TLS callback se ejecuta **antes** de que se llegue al punto de entrada habitual (`main` o `WinMain`). Por eso, el atacante lo utiliza para inyectar o desplegar su código justo al inicio, sin tener que modificar el flujo normal de ejecución.

## ¿Qué es el mecanismo TLS en Windows?

* **TLS = Thread Local Storage**
  Es un área de memoria reservada por el sistema para cada hilo (*thread*) que crea un proceso. Permite a cada hilo mantener sus propias variables globales sin interferir con otros hilos.

* **¿Para qué sirve originalmente?**
  Imaginemos que tenemos una variable global `int counter;` que cada hilo incrementa. Si la declaramos en TLS, cada hilo tendrá su propio `counter` independiente.

* **¿Y los callbacks?**
  Dentro de la sección **IMAGE\_DIRECTORY\_ENTRY\_TLS** del encabezado PE (Portable Executable), además de apuntar a la región de datos TLS, podemos especificar una **tabla de direcciones** de funciones (callbacks). El sistema:

  1. Reserva la región TLS para cada hilo.
  2. Recorre esa tabla de callbacks, llamando a cada función **antes** de que cualquier otro código de tu programa corra (incluso antes de `main`).
  3. Ejecuta el hilo principal y posteriores hilos, llamando de nuevo a esos callbacks cada vez que se crea un nuevo hilo.


## Esta ténica de poner funciones en los callbacks se conoce como *Thread Local Storage (TLS) injection.*

1. **Concepto**

   * El atacante inserta su propio código como uno de esos **TLS callbacks**, de modo que se ejecutará automáticamente y muy temprano, **sin tocar** el flujo normal (ni parchear el `main`, ni usar import hijacking).
2. **Ventajas para el atacante**

   * **Sigilo inicial**: el código malicioso corre antes de que la mayoría de los mecanismos de protección (antivirus, hooks de API) estén totalmente cargados.
   * **Simplicidad**: basta con añadir la función al array de callbacks TLS; no hay necesidad de modificar la tabla de imports ni el entry point.

Así que vamos a la pestaña de `Exports`, vemos un callback llamado `TlsCallback_0,`, si le damos doble click podemos ver efectivamente contiene una inyección de código: 

![](../assets/images/sherlock-ghost/1.png)

----

<h3 style="color: #9FEF00;">Task 2. Which Win32 API was used to take snapshots of all processes and threads on the system? </h3>

Para esto tenemos que subir el fichero `Ghost-Thread.apmx64` en apimonitor.

![](../assets/images/sherlock-ghost/2.png)

La llamada a la API CreateToolhelp32Snapshot con la bandera TH32CS_SNAPPROCESS es el mecanismo que Windows pone a tu disposición para capturar, en un instante dado, un “volcado” (snapshot) de todos los procesos —y, si se combinan con otras banderas, también de los hilos, módulos, etc.— que están activos en el sistema. A continuación te explico en detalle:

En el flujo que vimos en API Monitor:

- MessageBoxW → el binario muestra un mensaje (quizá distractor o comprobación).
- CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) → captura la lista de procesos.

Con esa lista el atacante puede, por ejemplo:
- Buscar procesos concretos (por nombre o PID) donde inyectar su payload.
- Enumerar hilos de un proceso objetivo para inyección (si incluyera TH32CS_SNAPTHREAD).
- Recopilar información de proceso (PID, nombre, estado), útil para escalada o movimientos laterales.

----

<h3 style="color: #9FEF00;">Task 3. Which process is the attacker's binary attempting to locate for payload injection? </h3>

Podemos ver en el análisis de `injecto.exe`

![](../asssets/images/sherlock-ghost/3.png)


- Toma un snapshot de todos los procesos.
- Itera con Process32First/Process32Next.
- Compara cada pe.szExeFile con "notepad.exe" mediante una comparación case‑insensitive. Se usa típicamente _wcsicmp (o lstrcmpiW). 
- Cuando encuentra el proceso llamado notepad.exe, extrae su PID y procede a inyectar el payload utilizando las llamadas Win32 habituales (OpenProcess, VirtualAllocEx, etc.).

-----

<h3 style="color: #9FEF00;">Task </h3>

Al final de las iteraciones podemos ver que encontró el proceso, obteniendo la información de éste posteriormente: 

![](../assets/images/sherlock-ghost/4.png)

----

<h3 style="color: #9FEF00;">Task 5. What is the size of the shellcode? </h3>

![](../assets/images/sherlock-ghost/5.png)


En la imagen podemos ver que se usa VirtualAllocEx, que es una función de la API de Win32 que permite a un proceso reservar o asignar memoria dentro del espacio de direcciones de otro proceso (o del propio proceso si se pasa su propio manejador). Se utiliza frecuentemente en escenarios de inyección de código, depuración remota o manipulación de procesos.


| Parámetro          | Descripción                                                                                                                      |                           |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `hProcess`         | Manejador con permisos para asignar memoria en el proceso objetivo. Usualmente obtenido con \`OpenProcess(PROCESS\_VM\_OPERATION | PROCESS\_VM\_WRITE, …)\`. |
| `lpAddress`        | Dirección de inicio donde reservar. Si es `NULL`, el sistema elegirá automáticamente un bloque libre adecuado.                   |                           |
| `dwSize`           | Número de bytes que quieres reservar. En inyección de código, corresponde al tamaño del shellcode o DLL a escribir.              |                           |
| `flAllocationType` | Máscara que indica el tipo de asignación:                                                                                        |                           |

------

<h3 style="color: #9FEF00;">Task 6. Which Win32 API was used to execute the injected payload in the identified process? </h3>

![](../assets/images/sherloc-ghost/6.png)

La función clave para ejecutar el payload inyectado en el proceso remoto es CreateRemoteThread. 

CreateRemoteThread arranca un nuevo hilo que comienza la ejecución en la dirección donde residía el shellcode, efectivamente lanzando el payload.

Este último paso es el que “dispara” la ejecución del código inyectado dentro del proceso víctima.

------

<h3 style="color: #9FEF00;">Task 7. The injection method used by the attacker executes before the main() function is called. Which Win32 API is responsible for terminating the program before main() runs? </h3>

![](../assets/images/sherlock-ghost/7.png)

La función ExitProcess es la llamada de la API de Win32 que termina un proceso de manera ordenada, cerrando todos sus hilos y liberando sus recursos antes de salir. Cuando el atacante inserta su payload en un TLS callback, quiere asegurarse de que, una vez ejecutado ese código malicioso, el programa legitimo no continúe hacia su punto de entrada normal (main o WinMain). Para ello, invoca ExitProcess, que cierra el proceso inmediatamente.

Diferencia con otras APIs de terminación:

- TerminateProcess
    Termina de forma forzada el proceso indicado (puede ser otro proceso), sin ejecutar atexit handlers ni notificar DLLs.
    Es más “brusca” y puede dejar recursos sin liberar adecuadamente.

- ExitThread
    Finaliza únicamente el hilo que la llamó, sin detener el resto del proceso.

- return desde main()
    Equivale en la práctica a llamar internamente a ExitProcess con ese valor de retorno, pero sucede después de ejecutar todo el código legítimo de la aplicación.

Por lo tanto la API ExitProcess es la responsable de finalizar el proceso de forma ordenada y temprana, justo después de que el atacante haya ejecutado su código malicioso en el TLS callback, y antes de que la aplicación legítima llegue a main().
