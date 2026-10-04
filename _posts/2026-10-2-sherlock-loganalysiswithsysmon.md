
Para este lab se nos dan los siguientes ficheros:

```bash
```

El `.evtx` lo voy a parsear con `chainsaw` para analizar los logs con `jq`:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/sysmon]
└─$ /opt/chainsaw/target/release/chainsaw dump --jsonl *.evtx > events_sysmon.jsonl

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Sysmon.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (1.1 MiB)
[+] Done
```

Con esto pasamos rápido a las preguntas.

---------------

Primero veamos los eventos que tenemos para este lab, asì nos daremos una guia visual de qué es lo que tenemos:

```bash
┌──(kali㉿kali)-[~/Documents/nueva_era_sherlocks/sysmon]
└─$ jq '.Event | .System.EventID' events_sysmon.jsonl | sort | uniq -c | sort -rn
    259 1
    248 11
    175 13
     40 22
     20 3
      6 5
      6 12
      3 8
```

**1\. Which file gave access to the attacker?**

Para empezar la investigación 
Submit Task
Task 1

Hint
What did the attacker use to bypass UAC? Mention the EXE.

*********.***

Submit Task
Task 2

Hint
What registry path and value was used by the above EXE to gain higher privileges? (path\value)

****:\********\*******\**-********\*****\****\*******\********

Submit Task
Task 3

Hint
The attacker dropped a file. What is the file location?

*:\*****\****\*********\********.***

Submit Task
Task 4

Hint
What are the technique name and ID used by the dropped EXE?

********** *******: *****

Submit Task
Task 5

Hint
What is the name of the attack?

**** *** ****

Submit Task
Task 6

Hint
What EXE did the attacker run using elevated privileges from the above attack?

**********.***

Submit Task
Task 7

Hint
The attacker downloaded and ran a file. What is the filename?

