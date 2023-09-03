# Honeypot-ELK
Archivos de configuración para la implementación de un honeypot IoT y el monitoreo de eventos con ELK
## Despliegue del Honeypot
En esta sección se detallará el proceso de instalación y configuración del software elegido para implementar el honeypot IoT, "Cowrie".

<img width="1200" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/d8a52d66-7882-4092-8ddb-bf418c85b306">

### Instalación de dependencias
Antes de instalar cualquier software, siempre es una buena práctica actualizar la lista de paquetes del sistema. Para lo cual se utilizaron los comandos:
  
    sudo apt update

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/2b1e8c12-8653-4371-8c16-e3f46a45197c">

    sudo apt upgrade

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/1a0809d1-7b85-4d6d-9a79-9e58de6e3dbb">

Luego se instalaron las dependencias previo a la instalación de cowrie.

    sudo apt-get install git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv python3-venv

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/86d4827e-7ca2-4635-9dfa-35fb303706cd">
 
Es recomendado utilizar un usuario no root para la instalación, para lo cual se realizó la creación del usuario cowrie.

    sudo adduser --disabled-password cowrie

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/b1fa3478-0362-4bf4-a414-5b06f0324623">
 
Este usuario no tendrá asignada una contraseña, solo se podrá acceder mediante el comando: 

    sudo su – cowrie

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/44ada5c7-aa3f-4671-bd14-51e35b6163ce">
 
### Instalación de Cowrie
Descargamos el código de cowrie desde el repositorio git:

    git clone http://github.com/cowrie/cowrie
    cd cowrie

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/495255d4-d52f-421c-93f4-45834df1fd22">

Creamos un entorno virtual con python3 para ejecutar cowrie dentro del repositorio descargado e instalamos algunos requerimientos:

    python3 -m venv cowrie-env
    source cowrie-env/bin/activate
    (cowrie-env) $ python -m pip install --upgrade pip
    (cowrie-env) $ python -m pip install --upgrade -r requirements.txt
    
<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/d4b55024-95a0-42ba-aa47-82c6cb3407e3">

### Configuración de Cowrie
La configuración de Cowrie se almacena en el archivo cowrie.cfg.dist ubicado en la ruta /home/cowrie/cowrie/etc. Copiamos la configuración al archivo cowrie.cfg para realizar las modificaciones que necesitamos, debido a que este archivo tiene mayor precedencia se leerá primero.

    cd /home/cowrie/cowrie/etc
    cp cowrie.cfg.dist cowrie.cfg

<img width="454" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/52be91d2-de4d-4caa-b002-c947f0c73285">
 
En el archivo de configuración cowrie.cfg se modificaron parámetros como:

- Hostname: Nombre que observarán los atacantes al conectarse al honeypot

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/f174e081-c670-4877-8a93-641cb053c690">

- Kernel_version, kernel_build_string, hardware_platform, operating: Información del sistema operativo que observará el atacante al conectarse al honeypot

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/c1fb356e-c1ac-40c3-a5be-79f83c8befe9">

-	SSH options: Se activó el servicio SSH que simulará el honeypot y definió el puerto 2222 que usa cowrie para recibir las peticiones del servicio.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/7493e772-a36d-466b-b865-335fd6971ce1">
<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/45b44112-c077-414f-9bab-708faa6e9300">

-	Telnet option: Se activó el servicio Telnet que simulará el honeypot y definió el puerto 2223 que usa cowrie para recibir las peticiones del servicio.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/96b78485-de52-4a07-9fcf-42ff44446d62">

También observamos las rutas donde se almacenarán los logs de la actividad que se genere en el honeypot. 

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/38cf3620-27a1-4ca7-8e16-907c1627b420">
<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/f9071d7d-c26c-4624-a33a-a14ba7763202">

### Configuración de conexiones
Mapeamos las conexiones que recibirá la VM

<img width="1200" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/08e540ce-4a2f-4f17-abb6-1c29987c7dec">

Debido a que los atacantes intentarán acceder al honeypot por el puerto 22 (ssh) y 23 (telnet) de la VM, se modificó el puerto de escucha del servicio SSH al 22000 para no perder la administración de la máquina real, esto se realizó modificando el archivo ssh_config.

    sudo vi /etc/ssh/sshd_config

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/2768c68d-e3e9-4dd0-86d8-a68be8ef3456">

Reiniciamos el servicio y validamos que el servicio SSH se encuentra activo por el puerto 22000.

    sudo systemctl restart sshd
    sudo ss -tulpn | grep ssh

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/276f7b5a-031b-4288-8783-35fec8c1c5d1">

Las conexiones recibidas por los puertos 22 y 23 deben redirigirse a los puertos configurados para la simulación de los servicios en cowrie, para lo cual se utilizó iptables para redirigir las conexiones entrantes.

    sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
    sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/105451a8-42b4-4667-8071-e5806376dece">

### Configuración de usuarios y contraseñas válidas
Configuramos la lista de usuarios y password válidos que serán usados por los atacantes para la autenticación exitosa en el honeypot, se duplicó el archivo de configuración userdb.example y se guardaron los cambios en el archivo userdb.txt.

    cd /home/cowrie/cowrie/etc
    cp userdb.example userdb.txt

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/60c83361-11bf-4c78-96e0-ee2a4f71d1d3">

### Iniciamos Cowrie
Para iniciar los servicios de cowrie ejecutamos los comandos:

    sudo su - cowrie
    cd /home/cowrie/cowrie/bin
    ./cowrie start

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/7b8ff29a-0880-44f0-aa21-e0ec70e99a96">

### Configuración de usuario 'Phil'
Al consultar los archivos /etc/passwd, /etc/group y /etc/shadow se observó la presencia del usuario Phil, el cual es un usuario por defecto de Cowrie. Para evitar que los atacantes descubran que nuestro dispositivo es un honeypot por la presencia de este usuario, se modificaron los archivos para reemplazar el usuario ‘Phil’ por el usuario ‘admin’ [10].
Ingresamos a la ruta Cowrie y se utilizó el editor fs.pickle para cambiar el home del usuario

    cd  /home/cowrie/cowrie
    python3 bin/fsctl share/cowrie/fs.pickle
    fs.pickle:/$ mv /home/phil /home/admin

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/6f091f24-ae66-4950-b990-4d2826c7e4ad">

Se editó el archivo /etc/passwd con los datos del usuario admin

    vi /home/cowrie/cowrie/honeyfs/etc/passwd

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/ae6f146d-42f2-4b81-a112-c6fef5912725">

Se editó el archivo /etc/group con los datos del usuario admin

    vi /home/cowrie/cowrie/honeyfs/etc/group

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/02be6dfc-39c5-4a18-a2fd-edd075353893">

Se editó el archivo /etc/shadow con los datos del usuario admin

    vi /home/cowrie/cowrie/honeyfs/etc/shadow

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/fd996dbd-9920-431c-b946-3617181095c7">

Se reiniciaron los servicios de Cowrie para validar los cambios:

    /home/cowrie/cowrie/bin/cowrie restart

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/2fb12a30-9951-499c-ab30-fda8f55ff684">

Se confirman los cambios ejecutados

## DESPLIEGUE DE ELK
En esta sección se detallará el proceso de instalación y configuración de la plataforma conocida como ELK (Elasticsearch, Logstash y Kibana) + Filebeat.
Debido a que ELK se configura en localhost se instaló el proxy reverso Ngnix para el acceso desde internet mediante la ip pública de la VM. 

###	Instalación de paquetes y dependencias
Inicialmente, se descargó la clave GPG pública de ElasticSearch y se añadió al sistema para que los paquetes firmados con esa clave sean considerados confiables durante el proceso de instalación y actualización.
Se indica al sistema dónde encontrar los paquetes de ElasticSearch y por último se actualiza la lista de paquetes disponibles en los repositorios configurados en el sistema con los comandos: 

    wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
    sudo apt-get update

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/1f976706-c32a-46ce-a791-5f2bd6c73a21">

Se realiza la instalación de algunas dependencias de Elasticsearch y Java, los componentes de ELK (Elasticsearch, Logstash y Kibana) y Filebeat

    sudo apt -y install apt-transport-https wget default-jre

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/76d2fe14-990d-4917-810a-5fc81e531ccf">
    
    sudo apt install elasticsearch logstash kibana

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/0236ee26-0518-4593-aa3d-dc1ca212f2f0">

    sudo apt install filebeat

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/d95fc6d1-0f7b-4969-9fbe-c204e5514ed8">

Se instala NGINX junto a algunos componentes de apache necesarios para el funcionamiento.

    sudo apt install nginx apache2-utils

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/92698d69-8726-41f1-b173-4dc358a1d249">

Finalmente se iniciaron los servicios de los componentes instalados:

    sudo systemctl enable elasticsearch logstash kibana filebeat nginx
    sudo systemctl start elasticsearch logstash kibana filebeat nginx

Para la configuración de los componentes se descargaron los archivos de configuración de cowrie y ELK ubicados en la VM del honeypot en el directorio de instalación de cowrie /home/cowrie/cowrie/docs/elk/ para copiarlos en la VM donde se instaló ELK.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/281ccd95-bcf8-4c87-b013-df90d8750911">


### Configuración de Filebeat
Para la configuración de Filebeat copiamos el archivo de configuración filebeat-cowrie.conf en nuestra VM Lillalogs con el nombre /etc/filebeat/filebeat.yml.
En el archivo, se modificaron los parámetros:

-	filebeat.inputs: Aquí se indica la ruta donde se ubican los logs de cowrie /home/azureuser/cowrielogs/cowrie.json*

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/9df3b407-4680-4759-be65-e55bdd8575ee">

-	output.elasticsearch: Se configura como false debido a que Filebeat enviará los logs a Logstash, no directamente a ElasticSearch

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/673c5e09-e2c8-404f-b3ea-bcd0a175a75f">

-	output.logstash: Se configura como True para el envío de logs a Logstash. El puerto por defecto para Logstash es 5044

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/3b8e6add-8226-46e1-a1c7-98211bf29af7">

Finalmente iniciamos el servicio de filebeat con el comando:
    
    sudo systemctl start filebeat
    
### Configuración de Logstash
Para la configuración de Logstash copiamos el archivo de configuración logstash-cowrie.conf en nuestra VM Lillalogs con el nombre /etc/logstash/conf.d/logstash-cowrie.conf. En el archivo, se modificaron los parámetros:

-	input: Se configura el puerto 5400 de filebeat y el tipo de log cowrie

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/03fa2109-8a42-4075-bffd-f889f2eda5c5">

-	filter: Se almacena la información del campo message con el prefijo h para evitar la sobreescritura de campos. Se formateó el campo timestamp utilizando el formato ISO8601. Adicionalmente, se creó el campo src_host resultado de la resolución dns del campo src_ip.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/61143c87-c955-4e61-962d-45b1d03cb67e">

-	geoip: Se creó el campo geoip resultado búsqueda del campo src_ip en la base de datos GeoLite2-City.mmdb previamente descargada.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/90735ff3-bca3-489d-8ca9-60403e3d23c6">

-	output: Se configura el envío de logs modificados hacia elasticsearch por el puerto 9200 bajo el alias cowrie-logstash.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/ce99d515-2baa-4b7f-8a6e-a868d4a2597d">

Finalmente iniciamos el servicio de filebeat con el comando:

    sudo systemctl start logstash
    
### Configuración de Elastisearch
Para la configuración de ElasticSearch ubicamos el archivo /etc/elasticsearch/elasticsearch.yml. En el archivo, se observaron los parámetros:

-	http.port: Se mantiene el puerto 9200 de elasticsearch 
-	discovery.type: Se configura single-node debido a que solo contamos con un nodo.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/73918b19-8151-4435-a89e-3cdb4322e517">

Probamos elasticsearch con el comando curl http://localhost:9200, obteniendo una respuesta en JSON.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/1746d7f8-919b-490b-be9c-7f2bef83698b">

### Configuración de Kibana
Para la configuración de Kibana modificamos el archivo de configuración /etc/kibana/kibana.yml en nuestra VM Lillalogs. Se modificaron los parámetros:

-	server.host: Se configura localhost debido a que usaremos Nginx.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/311265b5-064e-4fae-a7b9-5d308c25ec78">

-	server.name: Configuramos el nombre de nuestro servidor Kibana.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/81014a03-348b-4c82-81c2-8819f96d35ae">

-	elasticsearch.hosts: Indicamos la url y puerto de elasticsearch.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/2a0ecd41-3987-48cf-8b3a-7bc6fdba88d1">

-	logging.dest: Configuramos el archivo de almacenamiento de logs de Kibana, debemos asegurarnos previamente de que la ruta existe y el owner es kibana.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/ba9f08ff-5e9f-4911-940e-3614bc085677">

### Configuración de Nginx
Debido a que ELK corre en localhost, para acceder remotamente se configuró un proxy reverso hacia Kibana que corre en el puerto 5601 por defecto.
Se procede a crear un usuario y password para el acceso seguro a Kibana desde internet:

    sudo htpasswd -c /etc/nginx/htpasswd.users admin_kibana

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/68c7a77f-f3ab-4c40-9214-c93322d3918f">

Para configurar Nginx se modificaron en el archivo /etc/nginx/sites-available/default los siguientes parámetros:

-	Listen 8082: Puerto configurado para publicar Kibana, este puerto debe ser abierto en el network security group de la VM. 
-	server.name: ip pública de la VM.
-	auth_basic y auth_basic_user_file: archivo de configuración donde se configuró el usuario y contraseña de acceso previamente.
-	proxy_pass: Dirección que se publicará, url de Kibana 

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/cc437b08-484b-4956-bb94-bd4877137808">


Verificamos si la configuración contiene algún error de sintaxis:

    sudo nginx -t

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/79a001fb-5a07-4a55-ab7b-a51f705b439d">

Iniciamos el servicio de Nginx y validamos el puerto 8082 en escucha:

    sudo systemctl start nginx
    sudo ss -tulpn | grep 8082

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/294d3c4d-95d6-47a9-b8c0-82f8995c0e71">

Ingresamos por navegador a la url http://20.124.130.77:8082 con las credenciales configuradas y validamos el acceso a Kibana.

<img width="1200" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/403e55c5-3bd6-45d6-a437-1ce6c537f8bd">

### Configuración de Ansible
Para el envío de logs desde la VM Lilubu hacia la VM Lillalogs se realizó la instalación y configuración de ansible siguiendo los siguientes pasos:
Instalación de ansible para el envío automático de logs de una vm a otra

    sudo apt-get update
    sudo apt-get install ansible

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/42e4a122-53cb-48c7-bbd5-e934b7840b5e">

Se configuró el archivo send_logs.yml donde se describen los parámetros como:

-	ip pública de servidor destino: 20.124.138.77
-	usuario remoto para la conexión: azureuser
-	la llave pública para la conexión remota: /home/azureuser/Lillalog_key.pem
-	ruta local de logs: /home/cowrie/var/log/cowrie
-	ruta remota de logs: /home/azureuser/cowrielogs

Adicionalmente se aplicaron filtros y patrones para solo enviar los logs en formato json

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/a0ff5ad2-0942-42aa-a364-c10171e8766f">

Validación de la sintaxis del archivo de configuración send_logs.yml

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/236307ef-4ec5-4c3d-baa6-44bcad305519">

Configuración en crontab para la ejecución periódica de ansible

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/1d41d4ec-6b63-4989-b6f2-59a3bf6ab93a">

Prueba de ejecución ansible

    ansible-playbook send_logs.yml

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/81608a29-d3d7-4bc6-977f-c5d9ad2ea435">

Respuesta satisfactoria

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/56dd8186-fa05-41fc-be05-0dea6215cf9b">

##	Visualización de logs y creación de dashboards
Listamos los archivos indexados utilizando el comando:
    
    curl 'http://localhost:9200/_cat/indices?v'

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/4e27add5-e29f-4e30-a9c8-7094a84a0e77">

Configuramos el archivo indexado cowrie-logstash-<Fecha>:

    curl -XPUT 'localhost:9200/cowrie-logstash-2023.08.07-000001/_settings' -H "Content-Type:application/json" -d '{ "index" : {"number_of_replicas" : 0 } }'

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/e16e35c4-4658-4fad-ad43-3fa0fee29c3d">

Validamos la respuesta sin error con la salida {“acknowledged”:true}

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/6e895c2a-bc97-4ceb-9a89-fda5f5b00928">

En el menú Index Patterns, creamos el patrón indexado cowrie-logstash-*

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/8910c1ad-36b4-48fd-a1f2-ce9a02177d2f">

Validamos en el menú Discover los eventos recibidos, aquí podemos aplicar filtros por campos, por tiempo, etc. facilitando el análisis de logs.

<img width="700" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/538bbdd2-9dd2-4798-b386-388bf71e4574">

Se recopilaron eventos durante 15 días lo cual permitió contar con información valiosa para el análisis, la cual fue disponibilizada en el dashboard Honeypot IoT, donde se resumieron los aspectos más importantes en una sola vista. 

<img width="1200" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/ceb132c4-862e-4164-8d21-ee7544ac1837">
<img width="1200" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/b50d9c2b-f69e-4d1a-b61b-36b2af239332">
<img width="1200" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/1bf4c103-241e-4cb6-892a-aefda8f5b5ab">
<img width="1200" alt="image" src="https://github.com/LCmollly/Honeypot-ELK/assets/103143023/0997b506-f434-4016-94b9-b2fa5f97146e">
