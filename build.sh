#!/usr/bin/env bash

VERSION=1.2.0
PACKAGE=ovpn-admin

PATH=$PATH:~/go/bin

SKIP_FRONT=0
SKIP_BACK=0
SKIP_DEB=0

PACKAGE_DEPENDENCIES="libc6, openvpn, easy-rsa"

while [ $# -ge 1 ]; do
  case $1 in
    --skip-front)
      SKIP_FRONT=1
      ;;
    --skip-back)
      SKIP_BACK=1
      ;;
    --skip-deb)
      SKIP_DEB=1
      ;;
    *)
      echo "Unsupported option: $1"
      exit 1
  esac
  shift
done

if [ $SKIP_FRONT = 0 ]; then
  rsync --progress --times --recursive --delete-after ~/bus-ui/src/content/app/openvpn/ ./frontend/src/content/app/openvpn/
  rsync --progress --times --recursive --delete-after ~/bus-ui/src/content/app/shared/services/ble/ ./frontend/src/content/app/shared/services/ble/
  cd frontend && npm install && npm run build && cd ..
fi

if [ $SKIP_BACK = 0 ]; then
  CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags "-X main.version=$VERSION -linkmode external -extldflags -static -s -w"
fi

if [ $SKIP_DEB = 0 ]; then
  BUILD=$(../update-apt.sh get-build ${PACKAGE}_${VERSION})
  BUILD=$((BUILD + 1))
  PACKAGE_NAME=${PACKAGE}_${VERSION}-${BUILD}_amd64
  BUILD_DIR="deb-build"
  rm -rf $BUILD_DIR

  ## create package dir
  mkdir -p $BUILD_DIR/$PACKAGE_NAME

  ## Add service binary file
  mkdir -p $BUILD_DIR/$PACKAGE_NAME/usr/sbin/
  cp ./rpiadm $BUILD_DIR/$PACKAGE_NAME/usr/sbin/ovpn-admin

  ## Add service startup file
  mkdir -p $BUILD_DIR/$PACKAGE_NAME/lib/systemd/system/
  cp ./setup/ovpn-admin.service $BUILD_DIR/$PACKAGE_NAME/lib/systemd/system/

  ## Create control files
  mkdir -p $BUILD_DIR/$PACKAGE_NAME/DEBIAN/
echo "Package: ${PACKAGE}
Version: ${VERSION}-${BUILD}
Maintainer: Archibald Picq <archibald.picq@gmail.com>
Depends: ${PACKAGE_DEPENDENCIES}
Architecture: amd64
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

  dpkg --build $BUILD_DIR/$PACKAGE_NAME && \
    ../update-apt.sh add-package $BUILD_DIR/$PACKAGE_NAME.deb && \
    rm -rf $BUILD_DIR
fi
