#!/usr/bin/env bash
set -eo pipefail

PATH=$PATH:~/go/bin
ARCHS=
#ARCHS="$ARCHS armhf"
#ARCHS="$ARCHS arm64"
#ARCHS="$ARCHS arm7"
ARCHS="$ARCHS amd64"
#ARCHS="$ARCHS arm"
PACKAGE_DEPENDENCIES="libc6, openvpn, easy-rsa"
PACKAGE=ovpn-admin



APP_VERSION=$(grep '"version":' frontend/package.json)
APP_VERSION=${APP_VERSION##*\": \"}
APP_VERSION=${APP_VERSION%%\"*}

BUILD=$(../update-apt.sh get-build ${PACKAGE}_${APP_VERSION})
BUILD=$((BUILD + 1))
BUILD_DIR="./deb-build"
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
echo "Publish to apt repository (version $APP_VERSION, build $BUILD)"
./build.sh --skip-back
for ARCH in $ARCHS; do
  PACKAGE_NAME=${PACKAGE}_${APP_VERSION}-${BUILD}_${ARCH}
  echo
  echo " -> building '$PACKAGE_NAME'"

  ## create package dir
  mkdir -p $BUILD_DIR/$PACKAGE_NAME

  ## Add service binary file
  ./build.sh --skip-front --arch $ARCH

  mkdir -p $BUILD_DIR/$PACKAGE_NAME/usr/sbin/
  cp ./rpiadm-$ARCH $BUILD_DIR/$PACKAGE_NAME/usr/sbin/ovpn-admin

  ## Add service startup file
  mkdir -p $BUILD_DIR/$PACKAGE_NAME/lib/systemd/system/
  cp ./setup/ovpn-admin.service $BUILD_DIR/$PACKAGE_NAME/lib/systemd/system/

  ## Create control files
  mkdir -p $BUILD_DIR/$PACKAGE_NAME/DEBIAN/
echo "Package: ${PACKAGE}
Version: ${APP_VERSION}-${BUILD}
Maintainer: Archibald Picq <archibald.picq@gmail.com>
Depends: ${PACKAGE_DEPENDENCIES}
Architecture: ${ARCH}
Homepage: https://picq.fr
Description: A GUI to manage OpenVPN" \
> $BUILD_DIR/$PACKAGE_NAME/DEBIAN/control

  cp ./setup/conffiles $BUILD_DIR/$PACKAGE_NAME/DEBIAN/conffiles
  cp ./setup/preinst.sh $BUILD_DIR/$PACKAGE_NAME/DEBIAN/preinst
  cp ./setup/postinst.sh $BUILD_DIR/$PACKAGE_NAME/DEBIAN/postinst
  cp ./setup/prerm.sh $BUILD_DIR/$PACKAGE_NAME/DEBIAN/prerm
  cp ./setup/postrm.sh $BUILD_DIR/$PACKAGE_NAME/DEBIAN/postrm

  mkdir -p $BUILD_DIR/$PACKAGE_NAME/etc/default/
  cp ./setup/default.conf $BUILD_DIR/$PACKAGE_NAME/etc/default/ovpn-admin

  dpkg --build $BUILD_DIR/$PACKAGE_NAME
done

for ARCH in $ARCHS; do
  PACKAGE_NAME=${PACKAGE}_${APP_VERSION}-${BUILD}_${ARCH}
  ../update-apt.sh add-package $BUILD_DIR/$PACKAGE_NAME.deb
#     && \
#      rm -rf $BUILD_DIR
done
