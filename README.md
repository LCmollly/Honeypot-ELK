# Honeypot-ELK
Archivos de configuración para la implementación de un honeypot IoT y el monitoreo de eventos con ELK
## Despliegue del Honeypot
En esta sección se detallará el proceso de instalación y configuración del software elegido para implementar el honeypot IoT, "Cowrie".
### Instalación de dependencias
Antes de instalar cualquier software, siempre es una buena práctica actualizar la lista de paquetes del sistema. Para lo cual se utilizaron los comandos:
  
    sudo apt update

    sudo apt upgrade

Luego se instalaron las dependencias previo a la instalación de cowrie.

    sudo apt-get install git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv python3-venv
 
Es recomendado utilizar un usuario no root para la instalación, para lo cual se realizó la creación del usuario cowrie.

    sudo adduser --disabled-password cowrie
 
Este usuario no tendrá asignada una contraseña, solo se podrá acceder mediante el comando: 

    sudo su – cowrie
 
### Instalación de Cowrie
Descargamos el código de cowrie desde el repositorio git:

    git clone http://github.com/cowrie/cowrie
    cd cowrie
 
Creamos un entorno virtual con python3 para ejecutar cowrie dentro del repositorio descargado e instalamos algunos requerimientos:

    python3 -m venv cowrie-env
    source cowrie-env/bin/activate
    (cowrie-env) $ python -m pip install --upgrade pip
    (cowrie-env) $ python -m pip install --upgrade -r requirements.txt
 
### Configuraicón de Cowrie
La configuración de Cowrie se almacena en el archivo cowrie.cfg.dist ubicado en la ruta /home/cowrie/cowrie/etc. Copiamos la configuración al archivo cowrie.cfg para realizar las modificaciones que necesitamos, debido a que este archivo tiene mayor precedencia se leerá primero.

    cd /home/cowrie/cowrie/etc
    cp cowrie.cfg.dist cowrie.cfg
 
En el archivo de configuración cowrie.cfg se modificaron parámetros como:
-	Hostname: Nombre que observarán los atacantes al conectarse al honeypot
-	Kernel_version, kernel_build_string, hardware_platform, operating: Información del sistema operativo que observará el atacante al conectarse al honeypot
-	SSH options: Se activó el servicio SSH que simulará el honeypot y definió el puerto 2222 que usa cowrie para recibir las peticiones del servicio.
-	Telnet option: Se activó el servicio Telnet que simulará el honeypot y definió el puerto 2223 que usa cowrie para recibir las peticiones del servicio.

También observamos las rutas donde se almacenarán los logs de la actividad que se genere en el honeypot. 

### Configuración de conexiones
Mapeamos las conexiones que recibirá la VM

Debido a que los atacantes intentarán acceder al honeypot por el puerto 22 (ssh) y 23 (telnet) de la VM, se modificó el puerto de escucha del servicio SSH al 22000 para no perder la administración de la máquina real, esto se realizó modificando el archivo ssh_config.

    sudo vi /etc/ssh/sshd_config

Reiniciamos el servicio y validamos que el servicio SSH se encuentra activo por el puerto 22000.

    sudo systemctl restart sshd
    sudo ss -tulpn | grep ssh

Las conexiones recibidas por los puertos 22 y 23 deben redirigirse a los puertos configurados para la simulación de los servicios en cowrie, para lo cual se utilizó iptables para redirigir las conexiones entrantes.

    sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
    sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
 
### Configuración de usuarios y contraseñas válidas
Configuramos la lista de usuarios y password válidos que serán usados por los atacantes para la autenticación exitosa en el honeypot, se duplicó el archivo de configuración userdb.example y se guardaron los cambios en el archivo userdb.txt.

    cd /home/cowrie/cowrie/etc
    cp userdb.example userdb.txt

### Iniciamos Cowrie
Para iniciar los servicios de cowrie ejecutamos los comandos:

    sudo su - cowrie
    cd /home/cowrie/cowrie/bin
    ./cowrie start

### Configuración de usuario 'Phil'
Al consultar los archivos /etc/passwd, /etc/group y /etc/shadow se observó la presencia del usuario Phil, el cual es un usuario por defecto de Cowrie. Para evitar que los atacantes descubran que nuestro dispositivo es un honeypot por la presencia de este usuario, se modificaron los archivos para reemplazar el usuario ‘Phil’ por el usuario ‘admin’ [10].
Ingresamos a la ruta Cowrie y se utilizó el editor fs.pickle para cambiar el home del usuario

    cd  /home/cowrie/cowrie
    python3 bin/fsctl share/cowrie/fs.pickle
    fs.pickle:/$ mv /home/phil /home/admin

Se editó el archivo /etc/passwd con los datos del usuario admin

    vi /home/cowrie/cowrie/honeyfs/etc/passwd

Se editó el archivo /etc/group con los datos del usuario admin

    vi /home/cowrie/cowrie/honeyfs/etc/group

Se editó el archivo /etc/shadow con los datos del usuario admin

    vi /home/cowrie/cowrie/honeyfs/etc/shadow

Se reiniciaron los servicios de Cowrie para validar los cambios:

    /home/cowrie/cowrie/bin/cowrie restart

Se confirman los cambios ejecutados
 
Figura 4.2.7.6 Archivo /etc/passwd antes del cambio
 
Figura 4.2.7.7 Archivo /etc/passwd después del cambio
4.2.8	VERIFICANDO SERVICIOS ACTIVOS
Utilizamos la herramienta nmap y verificamos que los servicios ssh y telnet se encuentran activos, ejecutamos algunos intentos de acceso para el registro en los logs.
 
nmap -Pn -p 22,23 -sV 20.172.206.246
  
Figura 4.2.7.1 Escaneo de puertos en del honeypot en funcionamiento
Ejecutamos pruebas de acceso por ssh al honeypot utilizando credenciales fallidas y válidas, así como ejecución del comando “cat /etc/passwd”.
 
Figura 4.2.7.2 Pruebas de acceso al honeypot por SSH
También ejecutamos pruebas de acceso por telnet al honeypot utilizando credenciales fallidas y válidas, así como la ejecución del comando “hostname”.
 
 Figura 4.2.7.3 Pruebas de acceso al honeypot por telnet
4.2.9	VALIDANDO EL REGISTRO DE ACTIVIDADES
Validamos la actividad realizada en el honeypot en el archivo de log ubicado en la ruta /home/cowrie/cowrie/var/log/cowrie/cowrie.log, también contamos con el log en formato .json en el archivo cowrie.json en la misma ruta.
cat /home/cowrie/cowrie/var/log/cowrie/cowrie.log
 
Figura 4.2.8.1 Registro de actividad realizada en la Figura 4.2.7.2
 
Figura 4.2.8.2 Registro de actividad realizada en la Figura 4.2.7.3
4.3	DESPLIEGUE DE ELK
En esta sección se detallará el proceso de instalación y configuración de la plataforma conocida como ELK (Elasticsearch, Logstash y Kibana) + Filebeat, elegida para la visualización y tratamiento de los logs generados en el honeypot IoT basado en Cowrie [11] y [12].
La interacción de los componentes se describe en la figura [Figura 4.3.1]. Filebeat es el elemento inicial y será el encargado de recopilar los logs para el envío a Logstash. Logstash  recibirá los eventos en formato .json y realizará el procesamiento de los logs, definición de campos, parseo y modificación antes de enviarlos a Elasticsearch. Finalmente, Elasticsearch se encarga de indexar los logs formateados para su envío a la plataforma de visualización Kibana donde se analizarán los eventos y generarán los dashboards.
Debido a que ELK se configura en localhost se instaló el proxy reverso Ngnix para el acceso desde internet mediante la ip pública de la VM. 
 
Figura 4.3.1 Arquitectura ELK + Filebeat + Nginx
4.3.1	INSTALACIÓN DE PAQUETES Y DEPENDENCIAS
Inicialmente, se descargó la clave GPG pública de ElasticSearch y se añadió al sistema para que los paquetes firmados con esa clave sean considerados confiables durante el proceso de instalación y actualización.
Se indica al sistema dónde encontrar los paquetes de ElasticSearch y por último se actualiza la lista de paquetes disponibles en los repositorios configurados en el sistema con los comandos: 
 
$wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
$echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
$sudo apt-get update
 
Figura 4.3.1.1 Descarga y actualización de paquetes Elasticsearch
Se realiza la instalación de algunas dependencias de Elasticsearch y Java [Figura 4.3.1.2], los componentes de ELK (Elasticsearch, Logstash y Kibana) [Figura 4.3.1.3] y Filebeat [Figura 4.3.1.4]
$sudo apt -y install apt-transport-https wget default-jre
 
Figura 4.3.1.2 Instalación de dependencias y java
$sudo apt install elasticsearch logstash kibana
 
Figura 4.3.1.3 Instalación de ELK
$sudo apt install filebeat
 
Figura 4.3.1.4 Instalación de Filebeat
Se instala NGINX junto a algunos componentes de apache necesarios para el funcionamiento. [Figura 4.3.1.5] 
$sudo apt install nginx apache2-utils
 
Figura 4.3.1.5 Instalación de NGNIX y Apache
Finalmente se iniciaron los servicios de los componentes instalados:
$sudo systemctl enable elasticsearch logstash kibana filebeat nginx
$sudo systemctl start elasticsearch logstash kibana filebeat nginx
Para la configuración de los componentes se descargaron los archivos de configuración de cowrie y ELK ubicados en la VM del honeypot en el directorio de instalación de cowrie /home/cowrie/cowrie/docs/elk/ para copiarlos en la VM donde se instaló ELK.
 
Figura 4.3.1.6 Archivos de configuración de cowrie y ELK
4.3.2	CONFIGURACIÓN DE FILEBEAT
Para la configuración de Filebeat copiamos el archivo de configuración filebeat-cowrie.conf en nuestra VM Lillalogs con el nombre /etc/filebeat/filebeat.yml.
En el archivo, se modificaron los parámetros:
-	filebeat.inputs: Aquí se indica la ruta donde se ubican los logs de cowrie /home/azureuser/cowrielogs/cowrie.json* [Figura 4.3.2.1]
-	output.elasticsearch: Se configura como false debido a que Filebeat enviará los logs a Logstash, no directamente a ElasticSearch [Figura 4.3.2.2]
-	output.logstash: Se configura como True para el envío de logs a Logstash. El puerto por defecto para Logstash es 5044 [Figura 4.3.2.3]
 
Figura 4.3.2.1 Modificación del parámetro filebeat.inputs
 
Figura 4.3.2.2 Modificación del parámetro output.elasticsearch
 
 Figura 4.3.2.3 Modificación del parámetro output.logstash
Finalmente iniciamos el servicio de filebeat con el comando:
$sudo systemctl start filebeat
4.3.3	CONFIGURACIÓN DE LOGSTASH
Debido a que recibimos conexiones desde ips de diferentes partes del mundo y necesitamos ubicar e identificar el origen según ip utilizamos el archivo GeoLite2-City.mmdb que es parte de la base de datos GeoIP de MaxMind disponible de forma gratuita. Esta base contiene información como países, regiones, ciudades, coordenadas, etc. y permite asociar la ips con una ubicación geográfica.
Para descargar el archivo GeoLite2-City.mdb primero nos registrarnos gratuitamente en la web www.maxmind.com y procedemos con la descarga del archivo GZIP.
 
Figura 4.3.3.1 Web de descarga del archive GeoLite2-City.mmdb
Creamos el directorio /opt/logstash/vendor/geoip, descomprimimos el archivo .GZIP y copiamos la base GeoLite2-City.mmdb.
 
$sudo mkdir -p /opt/logstash/vendor/geoip/
$sudo mv GeoLite2-City.mmdb /opt/logstash/vendor/geoip
 
Figura 4.3.3.2 Copia de archivo GeoLite2-City.mmdb en ruta logstash
Para la configuración de Logstash copiamos el archivo de configuración logstash-cowrie.conf en nuestra VM Lillalogs con el nombre /etc/logstash/conf.d/logstash-cowrie.conf. En el archivo, se modificaron los parámetros:
-	input: Se configura el puerto 5400 de filebeat y el tipo de log cowrie [Figura 4.3.3.3]
-	filter: Se almacena la información del campo message con el prefijo h para evitar la sobreescritura de campos. Se formateó el campo timestamp utilizando el formato ISO8601. Adicionalmente, se creó el campo src_host resultado de la resolución dns del campo src_ip. [Figura 4.3.3.4]
-	geoip: Se creó el campo geoip resultado búsqueda del campo src_ip en la base de datos GeoLite2-City.mmdb previamente descargada. [Figura 4.3.3.5]
-	output: Se configura el envío de logs modificados hacia elasticsearch por el puerto 9200 bajo el alias cowrie-logstash. [Figura 4.3.3.6]
 
Figura 4.3.3.3 Modificación del parámetro input
 
Figura 4.3.3.4 Modificación del parámetro filter
 
Figura 4.3.3.3 Modificación del parámetro geoip
 
Figura 4.3.3.3 Modificación del parámetro output
Finalmente iniciamos el servicio de filebeat con el comando:
$sudo systemctl start logstash
4.3.4	CONFIGURACIÓN DE ELASTICSEARCH
Para la configuración de ElasticSearch ubicamos el archivo /etc/elasticsearch/elasticsearch.yml. En el archivo, se observaron los parámetros:
-	http.port: Se mantiene el puerto 9200 de elasticsearch 
-	discovery.type: Se configura single-node debido a que solo contamos con un nodo.
 
Figura 4.3.4.1 Archivo de configuración elasticsearch.yml
Probamos elasticsearch con el comando curl http://localhost:9200, obteniendo una respuesta en JSON.
 
Figura 4.3.4.2 Respuesta al test de Elasticsearch
4.3.5	CONFIGURACIÓN DE KIBANA
Para la configuración de Kibana modificamos el archivo de configuración /etc/kibana/kibana.yml en nuestra VM Lillalogs. Se modificaron los parámetros:
-	server.host: Se configura localhost debido a que usaremos Nginx. [Figura 4.3.5.1]
-	server.name: Configuramos el nombre de nuestro servidor Kibana. [Figura 4.3.5.2]
-	elasticsearch.hosts: Indicamos la url y puerto de elasticsearch. [Figura 4.3.5.3]
-	logging.dest: Configuramos el archivo de almacenamiento de logs de Kibana, debemos asegurarnos previamente de que la ruta existe y el owner es kibana. [Figura 4.3.5.4]
 
Figura 4.3.5.1 Modificación del parámetro server.host
 
Figura 4.3.5.2 Modificación del parámetro server.name
 
Figura 4.3.5.3 Modificación del parámetro elasticsearch.hosts
 
Figura 4.3.5.4 Modificación del parámetro logging.dest
4.3.6	CONFIGURACIÓN DE NGINX
Debido a que ELK corre en localhost, para acceder remotamente se configuró un proxy reverso hacia Kibana que corre en el puerto 5601 por defecto.
Se procede a crear un usuario y password para el acceso seguro a Kibana desde internet:
$sudo htpasswd -c /etc/nginx/htpasswd.users admin_kibana
$passwd: <password>
 Figura 4.3.6.1 Configuración de usuario y password para el acceso a Kibana desde internet
Para configurar Nginx se modificaron en el archivo /etc/nginx/sites-available/default los siguientes parámetros [Figura 4.3.6.2]:
-	Listen 8082: Puerto configurado para publicar Kibana, este puerto debe ser abierto en el network security group de la VM. 
-	server.name: ip pública de la VM.
-	auth_basic y auth_basic_user_file: archivo de configuración donde se configuró el usuario y contraseña de acceso previamente.
-	proxy_pass: Dirección que se publicará, url de Kibana 
  Figura 4.3.6.2 Archivo de configuración de Nginx
Verificamos si la configuración contiene algún error de sintaxis [Figura 4.3.6.3]:
$sudo nginx -t
  Figura 4.3.6.3 Validación de la sintaxis de configuración
Iniciamos el servicio de Nginx y validamos el puerto 8082 en escucha [Figura 4.3.6.4]:
$sudo systemctl start nginx
$sudo ss -tulpn | grep 8082
  Figura 4.3.6.4 Servicio y puerto de Nginx activo
Ingresamos por navegador a la url http://20.124.130.77:8082 con las credenciales configuradas y validamos el acceso a Kibana.
 
Figura 4.3.6.5 Validación de acceso a Kibana desde internet
4.3.7	CONFIGURACIÓN DE ANSIBLE
Para el envío de logs desde la VM Lilubu hacia la VM Lillalogs se realizó la instalación y configuración de ansible siguiendo los siguientes pasos [13]:
Instalación de ansible para el envío automático de logs de una vm a otra
$sudo apt-get update
$sudo apt-get install ansible
 
Figura 4.3.7.1 Instalación del paquete Ansible
Se configuró el archivo send_logs.yml donde se describen los parámetros como:
-	ip pública de servidor destino: 20.124.138.77
-	usuario remoto para la conexión: azureuser
-	la llave pública para la conexión remota: /home/azureuser/Lillalog_key.pem
-	ruta local de logs: /home/cowrie/var/log/cowrie
-	ruta remota de logs: /home/azureuser/cowrielogs
Adicionalmente se aplicaron filtros y patrones para solo enviar los logs en formato json
 
Figura 4.3.7.2 Configuración del archivo send_logs.yml
Validación de la sintaxis del archivo de configuración send_logs.yml
 
Figura 4.3.7.3 Validación de la sintaxis de configuración
Configuración en crontab para la ejecución periódica de ansible
 
Figura 4.3.7.4 Configuración de crontab
Prueba de ejecución ansible
$ansible-playbook send_logs.yml
  
Figura 4.3.7.5 Validación de la sintaxis de configuración
Respuesta satisfactoria
 
Figura 4.3.7.6 Validación de la sintaxis de configuración
4.4	VISUALIZACIÓN DE LOGS Y CREACIÓN DE DASHBOARDS EN KIBANA
Listamos los archivos indexados utilizando el comando:
$curl 'http://localhost:9200/_cat/indices?v'
 
Figura 4.4.1 Archivos indexados
Configuramos el archivo indexado cowrie-logstash-<Fecha>:
$curl -XPUT 'localhost:9200/cowrie-logstash-2023.08.07-000001/_settings' -H "Content-Type:application/json" -d '{ "index" : {"number_of_replicas" : 0 } }'
Validamos la respuesta sin error con la salida {“acknowledged”:true}
 
Figura 4.4.2 Validación de acceso a Kibana desde internet
En el menú Index Patterns, creamos el patrón indexado cowrie-logstash-* [14]
 
Figura 4.4.3 Patrón indexado cowrie-logstash-*
Validamos en el menú Discover [Figura 4.4.4] los eventos recibidos, aquí podemos aplicar filtros por campos, por tiempo, etc. facilitando el análisis de logs.
 
Figura 4.4.4 Eventos desde la vista del menú Discover
 
Figura 4.4.5 Eventos desde la vista del menú Discover filtrando la palabra “login”
Se recopilaron eventos durante 15 días lo cual permitió contar con información valiosa para el análisis, la cual fue disponibilizada en el dashboard Honeypot IoT [Figura 4.4.6], donde se resumieron los aspectos más importantes en una sola vista. 
       Figura 4.4.6 Dashboard Honeypot IoT 
![image](https://github.com/LCmollly/Honeypot-ELK/assets/103143023/d95799b5-843e-4e0d-9e42-18a8062dd052)
