#!/bin/bash

ensure_param () {
  local PARAM_NAME=$1
  local PARAM_VALUE=${!PARAM_NAME}

  if [ -z "${PARAM_VALUE}" ]; then
    echo "Missing parameter: ${PARAM_NAME}"
    exit 1
  fi
  echo "${PARAM_NAME}: ${PARAM_VALUE}"  
}

ensure_file () {
  local FILE_PATH=$1
  local FILE_FRIENDLY_NAME=$2

  if [ ! -f "${FILE_PATH}" ]; then
    echo "Missing ${FILE_FRIENDLY_NAME} file: ${FILE_PATH}"
    exit 1
  fi
  echo "Using ${FILE_FRIENDLY_NAME} file: ${FILE_PATH}"
}

generate_container_name () {
  CONTAINER_NAME=${IMAGE_NAME//[\/:]/_}_${CONNECTOR_NAME}
  echo "CONTAINER_NAME: ${CONTAINER_NAME}"
}

SUB_COMMAND=$1

case ${SUB_COMMAND} in

  build-image)
    echo "Build AD/LDAP Connector image:"
    
    IMAGE_NAME=$2
    ensure_param "IMAGE_NAME"

    echo "Removing existing image (if it exists)..."
    docker image rm --force ${IMAGE_NAME}

    echo "Building new image..."
    docker build -t ${IMAGE_NAME} .
    ;;

  run-first-connector)
    echo "Run first Connector container for a given Auth0 AD/LDAP Connection:"
    
    IMAGE_NAME=$2
    ensure_param "IMAGE_NAME"
    CONNECTOR_NAME=$3
    ensure_param "CONNECTOR_NAME"
    generate_container_name

    ensure_file "./config.json" "Config"
    ensure_file "./profileMapper.js" "Profile Mapper"

    echo Creating AD/LDAP Connector container with name "${CONTAINER_NAME}"... 
    docker create --name ${CONTAINER_NAME} ${IMAGE_NAME}

    echo Copying config files to container...
    docker cp ./config.json ${CONTAINER_NAME}:/opt/auth0-adldap/
    docker cp ./profileMapper.js ${CONTAINER_NAME}:/opt/auth0-adldap/lib

    echo Starting container...
    docker start ${CONTAINER_NAME}

    echo Tailing container logs...
    docker logs -f ${CONTAINER_NAME}
    ;;

  export-connector-config)
    echo "Export config files from AD/LDAP Connector container:"

    IMAGE_NAME=$2
    ensure_param "IMAGE_NAME"
    CONNECTOR_NAME=$3
    ensure_param "CONNECTOR_NAME"
    generate_container_name

    echo Creating config archive on container...
    docker exec -it $CONTAINER_NAME tar -czvf config.tar.gz config.json lib/profileMapper.js certs/cert.key certs/cert.pem

    echo Copying config archive from container...
    docker cp $CONTAINER_NAME:/opt/auth0-adldap/config.tar.gz ./

    echo Removing config archive from container...
    docker exec -it $CONTAINER_NAME rm config.tar.gz
    ;;

  run-additional-connector)
    echo "Run additional Connector container for a given Auth0 AD/LDAP Connection:"

    IMAGE_NAME=$2
    ensure_param "IMAGE_NAME"
    CONNECTOR_NAME=$3
    ensure_param "CONNECTOR_NAME"
    generate_container_name

    ensure_file "./config.tar.gz" "Config Archive"

    echo Creating AD/LDAP Connector container with name "${CONTAINER_NAME}"... 
    docker create --name ${CONTAINER_NAME} ${IMAGE_NAME}

    echo Copying config archive to container...
    docker cp ./config.tar.gz ${CONTAINER_NAME}:/opt/auth0-adldap/

    echo Starting container...
    docker start ${CONTAINER_NAME}

    echo Extracting config archive...
    docker exec ${CONTAINER_NAME} tar -xzvf config.tar.gz

    echo Removing config archive from container...
    docker exec -it $CONTAINER_NAME rm config.tar.gz

    echo Restarting container...
    docker restart ${CONTAINER_NAME}

    echo Tailing container logs...
    docker logs -f ${CONTAINER_NAME}
    ;;

  kill-connectors)
    echo "Remove all Connector containers:":

    IMAGE_NAME=$2
    ensure_param "IMAGE_NAME"

    docker rm $(docker stop $(docker ps -a -q --filter ancestor=${IMAGE_NAME} --format="{{.ID}}"))
    ;;

  *)
    echo "Command not supported. See DOCKER.md for usgae."
    exit 1
    ;;

esac
