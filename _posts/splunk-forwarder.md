---
layout: single
title: Instalación Splunk Forwarder
excerpt: Explicamos como instalamos el forwarder de splunk en un ubuntu server. 
date: 2025-6-5
classes: wide
header:
   teaser: ../assets/images/forwarder.png
   teaser_home_page: true
   icon: ../assets/images/splunk-logo.jpg
categories:
   - splunk
   - linux
tags:
   - auth.log
   - ubuntu server
---

Splunk es una plataforma de software diseñada para buscar, analizar y visualizar grandes volúmenes de datos generados por máquinas (machine data), tales como logs de sistemas operativos, aplicaciones, dispositivos de red o endpoints. En un entorno de Centro de Operaciones de Seguridad (SOC), Splunk se emplea principalmente para: 

1. Recopilar (ingest) logs y eventos provenientes de múltiples fuentes (firewalls, IPS/IDS, endpoints, servidores, etc.).

2. Indexar estos datos para que sean fácilmente consultables a través de su lenguaje Splunk Processing Language (SPL).

3. Correlacionar eventos y patrones que puedan indicar actividad maliciosa o anomalías.

4. Generar alertas (basadas en búsquedas programadas) cuando se detecten condiciones predefinidas (por ejemplo, múltiples intentos de login fallidos, tráfico inusual, etc.).

5. Visualizar series de tiempo y estadísticas en dashboards e informes, facilitando la investigación y el monitoreo continuo.


<h3> Componentes básicos de Splunk </h3>

1. Forwarders (Universal o Heavy):

 - Agentes que envían logs desde servidores o dispositivos hacia Splunk.

 - No se ven en la interfaz de búsqueda, pero es importante saber que los datos que se buscan provienen de ellos.

2. Indexers:

 - Reciben los datos, los procesan (parsean y extraen campos básicos) y los almacenan en índices.

 - Cada índice es una especie de base lógica para agrupar eventos. Ejemplos: main, security, network, etc.

3. Search Head:

 - Es la interfaz (Search & Reporting App) donde escribes consultas SPL, generas dashboards y alertas.

 - Cuando se envía una query, el Search Head lo distribuye a los indexers para recuperar los eventos que coinciden.

<h2 style="color: #5abe5a" > En este artículo breve se explica cómo se instala un forwarder en un Ubuntu server. </h2>

Para esto ya debemos de tener una cuenta en Splunk, podemos visitar el siguiente enlace para [obtener el forwarder]. 

Los comandos pueden ser como los siguiente: 

<pre style="background-color: #1e1e1e; color: #dcdcdc; padding: 15px; border-radius: 5px; overflow-x: auto;">
<code>
wget -O splunkforwarder.deb 'URL_DEL_ENLACE_COPIADO'

sudo tar -xvzf splunkforwarder.tgz -C /opt/

cd /opt/splunkforwarder

sudo ./bin/splunk start --accept-license
</code>
</pre>

Ahora tenemos que crear el usuario `splunk`, un usuario de sistema sin acceso a shell (por seguridad):

`sudo useradd -r -m -d /opt/splunkforwarder -s /bin/bash splunk`

> con -s /bin/bash le damos acceso a una shell, en caso de querer ejecutar comandos como el usuario splunk, pero no se recomienda por seguridad. 

Ahora cambiamos la propiedad de los ficheros de Splunk para que sean del usuario `splunk`

`sudo chown -R splunk:splunk /opt/splunkforwarder`

Habilitamos el servicio para que se inicie al momento de iniciarse el sistema: 

`sudo ./bin/splunk enable boot-start -user splunk`

Si todo salió bien, iniciamos splunk con el usuario splunk:

`sudo su - splunk -c "/opt/splunkforwarder/bin/splunk start"`

Luego, recargamos systemd y habilitamos el servicio:

<pre style="background-color: #1e1e1e; color: #dcdcdc; padding: 15px; border-radius: 5px; overflow-x: auto;">
<code>
sudo systemctl daemon-reload
sudo systemctl enable SplunkForwarder
sudo systemctl start SplunkForwarder
</code>
</pre>

Y verificamos: 

`sudo systemctl status SplunkForwarder`

Ahora activamos el forwarder para que empiece a mandar los logs:

<pre style="background-color: #1e1e1e; color: #dcdcdc; padding: 15px; border-radius: 5px; overflow-x: auto;">
<code>
sudo ./bin/splunk add forward-server 192.168.0.16:9997 -auth adminubuntu:Contraseniaubuntu

sudo ./bin/splunk status

sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log

sudo /opt/splunkforwarder/bin/splunk restart

sudo ./bin/splunk list forward-server
</code>
</pre>

Para esto, tenemos que abrir el firewall del indexer, en este caso el puerto 9997. 

Podemos confirmar los logs que está envíando: 

`tail -f /opt/splunkforwarder/var/log/splunk/splunkd.log`

<p style="color: #5abe5a "> Ahora que ya tenemos todo, si queremos que los logs vayan a un índice en específico para tenerlo más organizado, creamos el índice en el servidor de splunk, y en el forwarder añadimos lo siguiente: </h3>

    sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf

```plaintext
[default]
host = MiservidorUbuntu

[monitor:///var/log/syslog]
index = debian_logs
sourcetype = syslog
disabled = false

[monitor:///var/log/auth.log]
index = debian_logs
sourcetype = syslog
disabled = false
```

`sudo /opt/splunkforwarder/bin/splunk restart`  






