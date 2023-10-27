graylogVersion=5.1.6
syslogInPort=5140
nginxExternalHttpsPort=10000
nginxExternalHttpPort=10001
domain=internal.local
rootFolder=/opt/docker/graylog2
dockerHostIP=$(hostname -i | cut -f2 -d' ')

mkdir -p $rootFolder/compiler
mkdir -p $rootFolder/plugin
mkdir -p $rootFolder/ssl
mkdir -p $rootFolder/target
mkdir -p $rootFolder/nginx/conf $rootFolder/nginx/keys
cd $rootFolder

# define graylog credentials
read -p "Enter password secret: " pwdsecret
str1=`echo $pwdsecret | tr -d '\n' | sha256sum | cut -d " " -f1`
read -p "Enter admin password: " pwdweb
str2=`echo $pwdweb | tr -d '\n' | sha256sum | cut -d " " -f1`
echo GRAYLOG_PASSWORD_SECRET="$str1" > .env
echo GRAYLOG_ROOT_PASSWORD_SHA2="$str2" >> .env
echo syslogInPort=$syslogInPort >> .env
echo nginxExternalHttpsPort=$nginxExternalHttpsPort >> .env
echo nginxExternalHttpPort=$nginxExternalHttpPort >> .env
echo dockerHostIP=$dockerHostIP >> .env

#define nginx graylog credentials for user admin in this case
#htpasswd -n admin > $rootFolder/nginx/keys/nginx.htpasswd

cat << 'EOT' > $rootFolder/docker-compose.yml
version: "3.8"

services:
  mongodb:
    container_name: "graylog-db"
    hostname: "graylogdb"
    image: "mongo:5.0"
    volumes:
      - "mongodb_data:/data/db"
    restart: "on-failure"

  opensearch:
    container_name: "graylog-elastic"
    hostname: "graylogelastic"
    image: "opensearchproject/opensearch:2.4.0"
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
      - "bootstrap.memory_lock=true"
      - "discovery.type=single-node"
      - "action.auto_create_index=false"
      - "plugins.security.ssl.http.enabled=false"
      - "plugins.security.disabled=true"
    ulimits:
      memlock:
        hard: -1
        soft: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - "os_data:/usr/share/opensearch/data"
    restart: "on-failure"

  graylog:
    cap_add:
      - NET_ADMIN #Allow low ports
    container_name: "graylog-server"
    hostname: "graylog"
    image: "${GRAYLOG_IMAGE:-graylog/graylog:5.1}"
    depends_on:
      opensearch:
        condition: "service_started"
      mongodb:
        condition: "service_started"
      nginx:
        condition: "service_started"
    entrypoint: "/usr/bin/tini -- wait-for-it opensearch:9200 --  /docker-entrypoint.sh"
    environment:
      GRAYLOG_NODE_ID_FILE: "/usr/share/graylog/data/config/node-id"
      GRAYLOG_PASSWORD_SECRET: "${GRAYLOG_PASSWORD_SECRET:?Please configure GRAYLOG_PASSWORD_SECRET in the .env file}"
      GRAYLOG_ROOT_PASSWORD_SHA2: "${GRAYLOG_ROOT_PASSWORD_SHA2:?Please configure GRAYLOG_ROOT_PASSWORD_SHA2 in the .env file}"
      GRAYLOG_REST_LISTEN_URI: "http://0.0.0.0:9000/api/"
      GRAYLOG_WEB_LISTEN_URI: "http://0.0.0.0:9000/"
      GRAYLOG_HTTP_BIND_ADDRESS: "0.0.0.0:9000"
      GRAYLOG_HTTP_EXTERNAL_URI: "http://$dockerHostIP:$nginxExternalHttpPort/"
      GRAYLOG_ELASTICSEARCH_HOSTS: "http://opensearch:9200"
      GRAYLOG_MONGODB_URI: "mongodb://mongodb:27017/graylog"
    ports:
    - "5044:5044/tcp"   # Beats
    - "$syslogInPort:$syslogInPort/udp"   # Syslog
    - "$syslogInPort:$syslogInPort/tcp"   # Syslog
    - "5555:5555/tcp"   # RAW TCP
    - "5555:5555/udp"   # RAW TCP
    - "12201:12201/tcp" # GELF TCP
    - "12201:12201/udp" # GELF UDP
    - "13301:13301/tcp" # Forwarder data
    - "13302:13302/tcp" # Forwarder config
    volumes:
      - "graylog_data:/usr/share/graylog/data/data"
      - "graylog_journal:/usr/share/graylog/data/journal"
      - ${PWD}/plugin:/usr/share/graylog/plugin:rw
      - ${PWD}/ssl/:/usr/share/graylog/data/config/ssl/
    restart: "on-failure"

  compiler:
    container_name: "graylog-compiler"
    hostname: "graylogdev"
    build:
      args:
        - BASE_IMAGE=jessie-slim
        - APP_VERSION=5.1.6
      context: ./compiler
    volumes:
      - ${PWD}/ssl:/opt/ssl/tmpssl
      - ${PWD}/target:/opt/git/graylog2-output-syslog/tmptarget
    restart: "no"	

  nginx:
    image: nginx
    hostname: "graylognginx"
    container_name: "graylog-nginx"
    depends_on:
      compiler:
        condition: "service_started"
    volumes:
      - ${PWD}/nginx/conf/nginx.conf:/etc/nginx/nginx.conf
      - ${PWD}/nginx/conf/graylog.conf:/etc/nginx/conf.d/graylog.conf
      - ${PWD}/nginx/keys:/keys
    ports:
      - "$nginxExternalHttpPort:$nginxExternalHttpPort/tcp" # HTTP interface
      - "$nginxExternalHttpsPort:$nginxExternalHttpsPort/tcp" # HTTPS interface
    restart: unless-stopped

volumes:
  mongodb_data:
  os_data:
  graylog_data:
  graylog_journal:
EOT

cat << EOT > $rootFolder/compiler/Dockerfile
FROM debian:latest
ARG graylogVersion=$graylogVersion
ARG domain=$domain
ARG dockerhostname=graylog
ARG keyname=graylog-sslkey
ARG baseVolumesDir=/opt
EOT

cat << 'EOT' >> $rootFolder/compiler/Dockerfile
RUN apt update
RUN apt install procps git mlocate net-tools vim python3-pip pkg-config openjdk-17-jdk maven cron -y
WORKDIR /opt
RUN mkdir -p $baseVolumesDir/ssl/tmpssl
RUN openssl req -x509 -newkey rsa:4096 -keyout $baseVolumesDir/ssl/$keyname.key -out $baseVolumesDir/ssl/$keyname.crt -sha256 -days 3650 -nodes -subj "/CN=$dockerhostname.$domain" -addext "subjectAltName = DNS:$dockerhostname.$domain" 
RUN chmod 666 $baseVolumesDir/ssl/$keyname.crt
RUN chmod 666 $baseVolumesDir/ssl/$keyname.key
WORKDIR /opt
RUN mkdir -p /opt/git/
WORKDIR /opt/git
RUN git clone https://github.com/wizecore/graylog2-output-syslog
RUN mkdir -p /opt/git/graylog2-output-syslog/tmptarget
WORKDIR /opt/git/graylog2-output-syslog
RUN sed -i.bak "s/4\.2\.6/$graylogVersion/g" pom.xml
RUN mvn package
ENTRYPOINT ["cron", "-f"]
EOT

cat << 'EOT' > $rootFolder/nginx/conf/nginx.conf
worker_processes  4;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;
}
EOT

cat << EOT > $rootFolder/nginx/conf/graylog.conf
server
{
    listen $nginxExternalHttpsPort ssl http2;
    server_name graylog.internal.local;
    ssl_certificate					/keys/graylog-sslkey.crt;
    ssl_certificate_key				/keys/graylog-sslkey.key;
    proxy_ssl_certificate			/keys/graylog-sslkey.crt;
    proxy_ssl_trusted_certificate	/keys/graylog-sslkey.key;
	ssl_session_cache				shared:SSL:10m;
	ssl_session_timeout     		5m;
	ssl_protocols					TLSv1.2;
	ssl_ciphers						ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS;

    location /graylog/
    {
EOT

cat << 'EOT' >> $rootFolder/nginx/conf/graylog.conf
      proxy_set_header Host $http_host;
      proxy_set_header X-Forwarded-Host $host;
      proxy_set_header X-Forwarded-Server $host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Graylog-Server-URL http://$server_name/graylog/;
      rewrite          ^/graylog/(.*)$  /$1  break;
      proxy_pass       http://graylog:9000;
    }
}
EOT

docker compose up -d

#copy files to volumes folders
docker exec graylog-compiler bash -c "cp /opt/git/graylog2-output-syslog/target/graylog-output-syslog-$graylogVersion.jar /opt/git/graylog2-output-syslog/tmptarget/"
docker exec graylog-compiler bash -c 'cp /opt/ssl/graylog-sslkey* /opt/ssl/tmpssl/'
#Place files on the correct place
cp $rootFolder/ssl/* $rootFolder/nginx/keys/
cp $rootFolder/target/* $rootFolder/plugin/
#restart services
docker restart graylog-nginx
docker restart graylog-server
