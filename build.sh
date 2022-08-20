#!/usr/bin/env bash

PATH=$PATH:~/go/bin

SKIP_FRONT=0

while [ $# -ge 1 ]; do
  case $1 in
    --skip-front)
      SKIP_FRONT=1
      ;;
    *)
      echo "Unsupported option: $1"
  esac
  shift
done

if [ $SKIP_FRONT = 0 ]; then
  cd frontend && npm install && npm run build && cd ..
fi

CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags "-linkmode external -extldflags -static -s -w"
