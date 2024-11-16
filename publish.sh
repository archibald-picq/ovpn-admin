#!/usr/bin/env bash
set -eo pipefail
PATH=$PATH:~/go/bin

PACKAGE_DEPENDENCIES="libc6, openvpn, easy-rsa"
PACKAGE_NAME=ovpn-admin
PACKAGE_MAINTAINER="Archibald Picq <archibald.picq@gmail.com>"
PACKAGE_HOMEPAGE="https://picq.fr"
PACKAGE_DESCRIPTION="A GUI to manage OpenVPN"

ARCHS=
#ARCHS="$ARCHS armhf"
#ARCHS="$ARCHS arm64"
#ARCHS="$ARCHS arm7"
ARCHS="$ARCHS amd64"
#ARCHS="$ARCHS arm"



APP_VERSION=$(grep '"version":' frontend/package.json)
APP_VERSION=${APP_VERSION##*\": \"}
APP_VERSION=${APP_VERSION%%\"*}

BUILD=$(../update-apt.sh get-build ${PACKAGE_NAME}_${APP_VERSION})
BUILD=$((BUILD + 1))
BUILD_DIR="./deb-build"
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
echo "Publish to apt repository (version $APP_VERSION, build $BUILD)"
./build.sh --skip-back
for ARCH in $ARCHS; do
  deb_name=${PACKAGE_NAME}_${APP_VERSION}-${BUILD}_${ARCH}
  echo
  echo " -> building '$deb_name'"

  ## create package dir
  mkdir -p $BUILD_DIR/$deb_name

  ## Add service binary file
  ./build.sh --skip-front --arch $ARCH

  mkdir -p $BUILD_DIR/$deb_name/usr/sbin/
  cp ./rpiadm-$ARCH $BUILD_DIR/$deb_name/usr/sbin/ovpn-admin

  ## Add service startup file
  mkdir -p $BUILD_DIR/$deb_name/lib/systemd/system/
  cp ./setup/ovpn-admin.service $BUILD_DIR/$deb_name/lib/systemd/system/

  ## Create control files
  mkdir -p $BUILD_DIR/$deb_name/DEBIAN/
echo "Package: ${PACKAGE_NAME}
Version: ${APP_VERSION}-${BUILD}
Maintainer: ${PACKAGE_MAINTAINER}
Depends: ${PACKAGE_DEPENDENCIES}
Architecture: ${ARCH}
Homepage: ${PACKAGE_HOMEPAGE}
Description: ${PACKAGE_DESCRIPTION}" \
> $BUILD_DIR/$deb_name/DEBIAN/control

  cp ./setup/conffiles $BUILD_DIR/$deb_name/DEBIAN/conffiles
  cp ./setup/preinst.sh $BUILD_DIR/$deb_name/DEBIAN/preinst
  cp ./setup/postinst.sh $BUILD_DIR/$deb_name/DEBIAN/postinst
  cp ./setup/prerm.sh $BUILD_DIR/$deb_name/DEBIAN/prerm
  cp ./setup/postrm.sh $BUILD_DIR/$deb_name/DEBIAN/postrm

  mkdir -p $BUILD_DIR/$deb_name/etc/default/
  cp ./setup/default.conf $BUILD_DIR/$deb_name/etc/default/ovpn-admin

  dpkg --build $BUILD_DIR/$deb_name
done

for ARCH in $ARCHS; do
  deb_name=${PACKAGE_NAME}_${APP_VERSION}-${BUILD}_${ARCH}
  ../update-apt.sh add-package $BUILD_DIR/$deb_name.deb
#     && \
#      rm -rf $BUILD_DIR
done
