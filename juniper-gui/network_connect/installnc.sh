#!/bin/bash

# exit this script if anything fails
set -e
#set -x
#exec > /tmp/installnc.out 2>&1

if [ -z "$1" ]
then
    echo "Missing ncLinuxApp.jar"
    exit 1
fi

JAR=$1
JARDIR=$(dirname $1)
SCRIPT=$(readlink -f $0)
SCRIPTDIR=$(dirname "${SCRIPT}")

cd ${JARDIR}
if [ ! -d network_connect ]; then
    mkdir network_connect
fi
cd network_connect
unzip -o ${JAR} ncsvc libncui.so version.txt
chmod 6711 ncsvc ncui_wrapper
cp ${SCRIPTDIR}/ncui_wrapper ${JARDIR}/network_connect

