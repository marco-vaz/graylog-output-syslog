#!/bin/sh
# example: sh script nginxHttpsExternalPort domain.name /path/to/folder
# sh script.sh 10000 internal.local /opt/docker/graylog2
#
# Define variables
#nginxExternalHttpsPort=10000
nginxExternalHttpPort=10001
#domain=internal.local
#rootFolder=/opt/docker/graylog2
#nginxExternalHttpsPort=$1
#domain=$2
#rootFolder=$3

# Main 

# Function to validate a domain name
is_valid_domain() {
	vdomain="$1"
  if echo "$vdomain" | grep -E -q "^[a-zA-Z0-9.-]+$"; then
    return 0
  else
    return 1
  fi
}

# Function to display usage information
usage() {
  echo "Usage: $0 -p|--port <port> -d|--domain <domain_name> -f|--rootFolder <folder_path>"
  echo "\n"
  echo "  -p, --port <port>                 Specify the HTTPS port for Nginx (0-65535)."
  echo "  -d, --domain <domain_name>        Specify the domain name for the service."
  echo "  -f, --rootFolder <folder_path>    Specify the root folder path for the service."
  echo "  --help                            Display this help message."
  echo "\n"
  echo "Graylog needs ports for input to ingest events from systems."
  echo "A file 'graylogports.conf' is used to allow for more flexibility for every environment"
  echo "If not present then will be created using default values, namely:"
  echo "\t 5140:SYSLOG"
  echo "\t 5044:BEATS"
  echo "\t 5555:RAW"
  echo "\t 12201:GELF"
  echo "\t 13301:Forwarder Data"
  echo "\t 13302:Forwarder Config"
  echo "\n"
  echo "Please note that all this ports are both TCP and UDP"
  exit 1
}

# Parse command line arguments using getopts
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|--port)
      nginxExternalHttpsPort="$2"
	  # Check nginxExternalHttpsPort as a number
	  if ! [ "$nginxExternalHttpsPort" -ge 0 ] 2>/dev/null || ! [ "$nginxExternalHttpsPort" -le 65535 ] 2>/dev/null; then
	    echo "Flag nginxExternalHttpsPort must be a number between 0 and 65535. Aborting."
		usage
	    exit 1
	  fi
      shift 2
      ;;
    -d|--domain)
      domain="$2"
	  # Check domain as a valid domain name
	  if ! is_valid_domain "$domain"; then
	    echo "Flag domain must be a valid domain name. Aborting."
		usage
	    exit 1
	  fi
      shift 2
      ;;
    -f|--rootFolder)
      rootFolder="$2"
	  # Check rootFolder as a valid directory path
	  if ! [ -d "$rootFolder" ]; then
	    echo "Flag rootFolder must be a valid directory path. Aborting."
		usage
	    exit 1
	  fi
      shift 2
      ;;
    --help)
      usage
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      ;;
  esac
done

if ss -tln | grep -q $nginxExternalHttpsPort; then
	echo "Port $nginxExternalHttpsPort is in use. Aborting."
	usage
else
    echo "Chosen port is not in use"
fi

if ss -tln | grep -q $nginxExternalHttpPort; then
	echo "Port $nginxExternalHttpPort is in use. Aborting."
	usage
else
    echo "Chosen port is not in use"
fi

# Check if any of the flags are empty, and if so, exit the script
if [ -z "$nginxExternalHttpsPort" ] || [ -z "$domain" ] || [ -z "$rootFolder" ]; then
  echo "One or more of the flags are empty. Aborting."
  usage
fi

# create folder structure
mkdir -p $rootFolder/compiler
mkdir -p $rootFolder/plugin
mkdir -p $rootFolder/ssl
mkdir -p $rootFolder/target
mkdir -p $rootFolder/nginx/conf $rootFolder/nginx/keys
cd $rootFolder

cat <<EOT > "./splash"
#############################################
#     ____                 _                #
#    / ___|_ __ __ _ _   _| | ___   __ _    #
#   | |  _| '__/ _\` | | | | |/ _ \ / _\` |   #
#   | |_| | | | (_| | |_| | | (_) | (_| |   #
#    \____|_|  \__,_|\__, |_|\___/ \__, |   #
#                    |___/         |___/    #
#     ____              ___                 #
#    |  _ \  _____   __/ _ \ _ __  ___      #
#    | | | |/ _ \ \ / / | | | '_ \/ __|     #
#    | |_| |  __/\ V /| |_| | |_) \__ \     #
#    |____/ \___| \_/  \___/| .__/|___/     #
#                           |_|             #
#                                           #
#   Brought to you by Marco Vaz (aka MTV)   #
#                                           #
#                                           #
#############################################
EOT

cat "./splash"
echo \

# the following is used to get graylog version
# Please install skopeo and jq. 
# Function to check if a command is available
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

skopeo_installed=$(command_exists "skopeo" && echo "yes" || echo "no")
jq_installed=$(command_exists "jq" && echo "yes" || echo "no")

# Ask the user for the Graylog version
if [ "$skopeo_installed" = "no" ] || [ "$jq_installed" = "no" ]; then
  read -p "Enter the Graylog version (default: 5.1.7): " graylogVersion
  graylogVersion=${graylogVersion:-"5.1.7"}  # Set default value to "5.1.7" if user presses Enter
  logging $green "Graylog version set to: $graylogVersion"
else
	image_name="graylog/graylog"; tags=$(skopeo list-tags docker://docker.io/$image_name | jq -r '.Tags[]' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$'); latest_stable_version=$(printf "%s\n" $tags | sort -V | tail -n 1); graylogVersion=$latest_stable_version
fi
#graylogVersion=5.1.7
echo $graylogVersion
# Define ANSI escape codes for colors
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
RESET='\033[0m'

#logging variables
log_level="info"
log_file="lastrun.log"

# Logging function
logging() {
    local color="$1"
    local log_message="$2"
    local single_line_event=$(echo "$log_message" | tr -d '\t' | tr -d '\n')
    # Log to a file
    echo "$(date +"%Y-%m-%d %H:%M:%S") [$log_level] [graylog_docker] - $single_line_event" >> "$log_file"
    # Log to syslog
    #logger -t "DockerComposeScript" -p "user.$log_level" "$single_line_event"
    # Execute additional actions with the specified color
    echo "${color}$log_message${RESET}"
}

# Function to wait for the container to be up and running
wait_for_container() {
    local container_name="$1"
    local max_attempts="$2"
    local sleep_seconds="$3"
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if docker ps -q --filter "name=$container_name" | grep -q .; then
            return 0  # Container is running
        fi

        sleep "$sleep_seconds"
        attempt=$((attempt + 1))
    done

    return 1  # Container did not start within the specified time
}

#echo "#####################################################################################" > "$log_file"
logging $green "Starting GRAYLOG docker compose builder"
logging $green "This script configures graylog docker${RESET}"
logging $green "and adds a SYSLOG Output plugin${RESET}"
logging $green "Nginx is configured for graylog web interface${RESET}"
logging $green "Graylog ports input file is $rootFolder/graylogports.conf${RESET}"

# Define ports (UDP/TCP)
# check if file exists
file_path=$rootFolder/graylogports.conf
if [ -e "$file_path" ]; then
    logging $green "$file_path exists. Proceeding..."
else
	logging $yellow "$file_path not present will be created automatically with:${RESET}"
	logging $green "\t 5140:SYSLOG \n\t 5044:BEATS \n\t 5555:RAW \n\t 12201:GELF \n\t 13301:Forwarder Data \n\t 13302:Forwarder Config${RESET}"
	# write some ports
	cat <<EOT > "$rootFolder/graylogports.conf"
5140:SYSLOG
5044:BEATS
5555:RAW
12201:GELF
13301:Forwarder Data
13302:Forwarder Config
EOT
fi

# check if file has correct syntax
logging $yellow "checking graylogports.conf syntax"
while IFS= read -r line; do
    # Remove leading and trailing whitespace
    line=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
    # Check if the line is empty or starts with a comment
    if [ -z "$line" ] || [ "$(echo "$line" | cut -c 1)" = "#" ]; then
        continue  # Skip empty lines and lines starting with a comment
    fi
    # Split the line into parts using ":" as the delimiter
    port=$(echo "$line" | cut -d':' -f1)
    rest=$(echo "$line" | cut -d':' -f2-)
    # Check if the port is a valid number between 1 and 65535
    if [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && [ "$port" -eq "$port" ] 2>/dev/null; then
        logging $green "\t Valid line: $port:$rest"
    else
        logging $green "\t Invalid line: $line"
    fi
done < "$file_path"


#set variables
dockerHostIP=$(hostname -i | cut -f2 -d' ')

logging $yellow "Please define graylog credentials and secret ${RESET}"
# define graylog credentials
read -p "Enter admin password: " pwdweb
str1=`echo $pwdweb | tr -d '\n' | sha256sum | cut -d " " -f1`
read -p "Enter password secret: " pwdsecret
str2=`echo $pwdsecret | tr -d '\n' | sha256sum | cut -d " " -f1`
echo GRAYLOG_ROOT_PASSWORD_SHA2="$str1" > .env
echo GRAYLOG_PASSWORD_SECRET="$str2" >> .env
echo syslogInPort=$syslogInPort >> .env
echo nginxExternalHttpsPort=$nginxExternalHttpsPort >> .env
echo nginxExternalHttpPort=$nginxExternalHttpPort >> .env
echo dockerHostIP=$dockerHostIP >> .env
echo GRAYLOG_IMAGE=graylog/graylog:$graylogVersion >> .env

#define nginx graylog credentials for user admin in this case
#htpasswd -n admin > $rootFolder/nginx/keys/nginx.htpasswd

logging $yellow "Writing docker-compose.yml"
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
EOT

# Loop through each line in graylogports.conf and append port mappings to the Docker Compose file
docker_compose_file="$rootFolder/docker-compose.yml"
while IFS=: read -r port description; do
logging $green "\t Adding $description port $port TCP and UDP"
cat <<EOT >> "$docker_compose_file"
      - "$port:$port/tcp"  # $description TCP"
      - "$port:$port/udp"  # $description UDP"
EOT
done < "$rootFolder/graylogports.conf"

cat << 'EOT' >> $rootFolder/docker-compose.yml
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

logging $yellow "Writing ./compiler/Dockerfile"
logging $green "\t This container is used only once"
logging $green "\t Purpose: \n\t\t create SSL certificates \n\t\t compile the graylog plugin"

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
EOT

if echo "$graylogVersion" | grep -qE '^[0-9]+\.[0-9]+$'; then
    graylogVersion="${graylogVersion}.0"
fi

major=$(echo $graylogVersion | awk -F '.' '{print $1}')
minor=$(echo $graylogVersion | awk -F '.' '{print $2}')

if [ $major -eq 4 ] && [ $minor -ge 1 ] || [ $major -eq 5 ] && [ $minor -le 1 ]; then
    echo RUN sed -i.bak \"s/4\.2\.6/$graylogVersion/g\" pom.xml >> $rootFolder/compiler/Dockerfile
elif [ $major -eq 5 ] && [ $minor -ge 2 ]; then
    echo RUN sed -i.bak \"s/4\.2\.6/$graylogVersion/g\" pom.xml >> $rootFolder/compiler/Dockerfile
	echo RUN sed -i.bak.v2 "'/<dependencies>/a\<dependency>\\\n        <groupId>com.fasterxml.jackson.core<\/groupId>\\\n        <artifactId>jackson-databind<\/artifactId>\\\n        <version>2.12.5<\/version>\\\n    <\/dependency>\\\n    <dependency>\\\n        <groupId>com.fasterxml.jackson.core<\/groupId>\\\n        <artifactId>jackson-core<\/artifactId>\\\n        <version>2.15.3<\/version>\\\n    <\/dependency>\\\n    <dependency>\\\n        <groupId>io.dropwizard.metrics<\/groupId>\\\n        <artifactId>metrics-core<\/artifactId>\\\n        <version>4.2.21<\/version>\\\n    <\/dependency>\\\n    <dependency>\\\n        <groupId>org.glassfish.corba<\/groupId>\\\n        <artifactId>glassfish-corba-omgapi<\/artifactId>\\\n        <version>4.2.1<\/version>\\\n    <\/dependency>\\\n    <dependency>\\\n        <groupId>com.eaio.uuid<\/groupId>\\\n        <artifactId>uuid<\/artifactId>\\\n        <version>3.2<\/version>\\\n    <\/dependency>\\\n    <dependency>\\\n        <groupId>javax<\/groupId>\\\n        <artifactId>javaee-api<\/artifactId>\\\n        <version>8.0<\/version>\\\n        <scope>provided<\/scope>\\\n    <\/dependency>\\\n    <dependency>\\\n        <groupId>com.google.inject.extensions<\/groupId>\\\n        <artifactId>guice-assistedinject<\/artifactId>\\\n        <version>7.0.0<\/version>\\\n    <\/dependency>\\\n    <dependency>\\\n        <groupId>com.google.inject<\/groupId>\\\n        <artifactId>guice<\/artifactId>\\\n        <version>7.0.0<\/version>\\\n    <\/dependency>\\\n    <dependency>\\\n        <groupId>com.google.guava<\/groupId>\\\n        <artifactId>guava<\/artifactId>\\\n\\\n        <version>32.1.3-jre<\/version>\\\n    <\/dependency>\\\n    <dependency>\\\n        <groupId>junit<\/groupId>\\\n        <artifactId>junit<\/artifactId>\\\n        <version>4.12<\/version>\\\n        <scope>test<\/scope>\\\n    <\/dependency>'" pom.xml >> $rootFolder/compiler/Dockerfile
else
    echo "Invalid version number"
fi

cat << 'EOT' >> $rootFolder/compiler/Dockerfile
RUN mvn package
ENTRYPOINT ["cron", "-f"]
EOT

logging $yellow "Writing ./nginx/conf/nginx.conf"
logging $green "\t This file has nginx general config items"

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

logging $yellow "Writing ./nginx/conf/graylog.conf"
logging $green "\t This file has graylog config items"

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

logging $yellow "doing docker compose up -d"
docker compose up -d  2>&1 | while IFS= read -r line; do
    echo "$(date +"%Y-%m-%d %H:%M:%S") [$log_level] [graylog_docker] - docker compose: $line" >> "$log_file"
done
# Check if the command was successful
if [ $? -eq 0 ]; then
	logging $green "\t docker Compose up successful."
else
    logging red "\t docker Compose up failed."
fi

#check container up if not start
max_attempts=30
sleep_seconds=1
logging $yellow "Check if graylog-compiler container is up"
docker start graylog-compiler > /dev/null
wait_for_container "graylog-compiler" "$max_attempts" "$sleep_seconds"
if [ $? -eq 0 ]; then
    logging $green "\t Container $container_name is up and running."
else
    logging $red "\tcontainer $container_name did not start within the specified time."
    # Handle the failure as needed
    # For example, you can stop the container: docker stop "$container_name"
fi

#copy files to volumes folders
logging $yellow "Copying files"
logging $green "\t copying plugin to graylog volume"
docker_command="docker exec graylog-compiler bash -c \"cp /opt/git/graylog2-output-syslog/target/graylog-output-syslog-$graylogVersion.jar /opt/git/graylog2-output-syslog/tmptarget/\""
output=$(eval "$docker_command" 2>&1)
if [ $? -eq 0 ]; then
    logging $green "\t docker exec cp for container graylog-compiler successful."
else
    log_message="$(date +'%Y-%m-%d %H:%M:%S') [$log_level] [graylog_docker] - docker cp: $output"
    echo "$log_message" >> "$log_file"
    logging $red "\t docker exec cp for container graylog-compiler failed."
fi

#beware that there might be other plugins or previous versions
#rm -rf $rootFolder/plugin/graylog-output-syslog*
cp $rootFolder/target/* $rootFolder/plugin/
logging $green "\t copying certificates to nginx volume"
docker_command="docker exec graylog-compiler bash -c 'cp /opt/ssl/graylog-sslkey* /opt/ssl/tmpssl/'"
output=$(eval "$docker_command" 2>&1)
if [ $? -eq 0 ]; then
    logging $green "\t docker exec cp for container graylog-nginx successful."
else
    log_message="$(date +'%Y-%m-%d %H:%M:%S') [$log_level] [graylog_docker] - docker cp: $output"
    echo "$log_message" >> "$log_file"
    logging $red "\t docker exec cp for container graylog-nginx failed."
fi
cp $rootFolder/ssl/* $rootFolder/nginx/keys/
#restart services
logging $yellow "restarting graylog and nginx containers"
docker_command="docker restart graylog-nginx"
output=$(eval "$docker_command" 2>&1)
if [ $? -eq 0 ]; then
    logging $green "\t docker restart for container graylog-nginx successful."
else
    log_message="$(date +'%Y-%m-%d %H:%M:%S') [$log_level] [graylog_docker] - docker restart: $output"
    echo "$log_message" >> "$log_file"
    logging $red "\t docker restart for container graylog-nginx failed."
fi
docker_command="docker restart graylog-server"
output=$(eval "$docker_command" 2>&1)
if [ $? -eq 0 ]; then
    logging $green "\t docker restart for container graylog-server successful."
else
    log_message="$(date +'%Y-%m-%d %H:%M:%S') [$log_level] [graylog_docker] - docker restart: $output"
    echo "$log_message" >> "$log_file"
    logging $red "\t docker restart for container graylog-server failed."
fi
logging $yellow "stoping compiler container"
docker_command="docker stop graylog-compiler"
output=$(eval "$docker_command" 2>&1)
if [ $? -eq 0 ]; then
    logging $green "\t docker stop for container graylog-server successful."
else
    log_message="$(date +'%Y-%m-%d %H:%M:%S') [$log_level] [graylog_docker] - docker stop: $output"
    echo "$log_message" >> "$log_file"
    logging $red "\t docker stop for container graylog-server failed."
fi
logging $green "Run Logs are in $log_file."
logging $green "You can access graylog web interface with: \n\t https://graylog.$domain:$nginxExternalHttpsPort/graylog/ \n\t https://$dockerHostIP:$nginxExternalHttpsPort/graylog/"

#remove everything
#docker compose down --volumes --rmi all --remove-orphans
