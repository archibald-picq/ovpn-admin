#!/usr/bin/env bash
set -eo pipefail

APP_VERSION=$(grep '"version":' frontend/package.json)
APP_VERSION=${APP_VERSION##*\": \"}
APP_VERSION=${APP_VERSION%%\"*}

case "$APP_VERSION" in
  *.*.*) ;;
  *) echo "Bad version in package.json '$APP_VERSION'"; exit 1;;
esac

PATH=$PATH:~/go/bin
SKIP_FRONT=0
SKIP_BACK=0
BUILD_DEV=0
ARCH=amd64

while [ $# -ge 1 ]; do
  case $1 in
    --dev)
      BUILD_DEV=1
      ;;
    --skip-front)
      SKIP_FRONT=1
      ;;
    --skip-back)
      SKIP_BACK=1
      ;;
    --arch)
      shift
      ARCH=$1
      ;;
    *)
      echo "Unsupported option: $1"
      exit 1
  esac
  shift
done

PACKAGE_BUILD_SCRIPT=build
[ "$BUILD_DEV" = 1 ] && PACKAGE_BUILD_SCRIPT=build-dev

if [ $SKIP_FRONT = 0 ]; then
  rsync --progress --times --recursive --delete-after ~/bus-ui/src/content/app/openvpn/ ./frontend/src/content/app/openvpn/
  rsync --progress --times --recursive --delete-after ~/bus-ui/src/content/app/shared/services/ble/ ./frontend/src/content/app/shared/services/ble/
  export APP_VERSION
  cd frontend && npm install && npm run $PACKAGE_BUILD_SCRIPT && cd .. || (echo "Build front failed"; exit 1)
fi

if [ $SKIP_BACK = 0 ]; then
  echo "Compile Go backend for arch '$ARCH' at version '$APP_VERSION'"
#  CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags "-X main.version=$APP_VERSION -linkmode external -extldflags -static -s -w"

  # apt install gcc-arm-linux-gnueabi
  # apt install gcc-arm-linux-gnueabihf
  # apt install aarch64-linux-gnu-gcc
  rm -f ./rpiadm
  case $ARCH in
    arm)
      CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=7 go build -a -tags netgo -ldflags "-X main.version=$APP_VERSION -linkmode external -extldflags -static -s -w"
      ;;
    armhf)
      CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 go build -a -tags netgo -ldflags "-X main.version=$APP_VERSION -linkmode external -extldflags -static -s -w"
      ;;
    arm64)
      CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -a -tags netgo -ldflags "-X main.version=$APP_VERSION -linkmode external -extldflags -static -s -w"
      ;;
    aarch64)
      CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -a -tags netgo -ldflags "-X main.version=$APP_VERSION -linkmode external -extldflags -static -s -w"
      ;;
    *)
      CGO_ENABLED=1 GOOS=linux GOARCH=${ARCH} go build -a -tags netgo -ldflags "-X main.version=$APP_VERSION -linkmode external -extldflags -static -s -w"
      ;;
  esac

  if [ ! -f ./rpiadm ]; then
    echo "Build failed" 1>&2
    exit 1
  fi
  mv ./rpiadm ./rpiadm-$ARCH
fi
