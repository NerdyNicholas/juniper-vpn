#!/bin/bash

#set -x
set -e

SRC="../juniper-gui"
NAME=jgui
ARCH=x86_64
VERSION=1.0
RELEASE=1
RPM=${NAME}-${VERSION}-${RELEASE}.x86_64.rpm
DEB=${NAME}_${VERSION}-${RELEASE}_amd64.deb
TMPDIR=$(mktemp -d)
INSTALLDIR="opt/juniper-gui"
PKGDIR=${TMPDIR}/${INSTALLDIR}
POST_INSTALL=$(mktemp --tmpdir juniper-gui-post_install.shXXX)

if [ -f $RPM -o -f $DEB ]; then
	read -r -p "${RPM} or ${DEB} already exists; do you want to continue? [y/N] " response
	case ${response} in
		[yY][eE][sS]|[yY])
			;;
		*)
			exit 0
			;;
	esac
fi

mkdir -p ${PKGDIR}
cp -r ${SRC}/lib ${PKGDIR}
rm ${PKGDIR}/lib/*.pyc
cp -r ${SRC}/res ${PKGDIR}
cp ${SRC}/jgui ${PKGDIR}

cp -r ${SRC}/network_connect ${PKGDIR}
#cp ncLinuxApp.jar ${PKGDIR}/network_connect

mkdir -p ${TMPDIR}/usr/local/bin
ln -s /${INSTALLDIR}/jgui ${TMPDIR}/usr/local/bin

pushd ${PKGDIR}/network_connect
gcc -m32 ncui_wrapper.c -ldl -o ncui_wrapper
rm ncui_wrapper.c
#unzip ncLinuxApp.jar ncsvc libncui.so
#chmod +x ncsvc ncui_wrapper
popd

cat > $POST_INSTALL <<POST
chmod 700 /${INSTALLDIR}/network_connect/installnc.sh
chmod 6711 /${INSTALLDIR}/network_connect/ncui_wrapper
POST

rm -f ${RPM}
fpm \
    -t rpm \
    -s dir \
    -n ${NAME} \
    -v ${VERSION} \
    --iteration ${RELEASE} \
    -a $ARCH \
    --after-install $POST_INSTALL \
    --rpm-user root \
    --rpm-group root \
    -C $TMPDIR \
    -d python-qt4 \
    -d python-enum34 \
    -d python-netifaces \
    ./ #${INSTALLDIR}


rm -f ${DEB}
fpm \
	-t deb \
	-s dir \
	-n ${NAME} \
	-v ${VERSION} \
	--iteration ${RELEASE} \
	-a ${ARCH} \
	--after-install $POST_INSTALL \
	--deb-user root \
	--deb-group root \
	-C $TMPDIR \
	-d python-qt4 \
	-d python-enum34 \
	-d python-netifaces \
	./ #${INSTALLDIR}

rm ${POST_INSTALL}
rm -rf ${TMPDIR}
