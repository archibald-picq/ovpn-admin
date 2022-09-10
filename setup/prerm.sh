#!/bin/sh
set -e


systemctl stop ovpn-admin.service
systemctl disable ovpn-admin.service

if [ -x "/etc/init.d/ovpn-admin" ] && [ "$1" = remove ]; then
	invoke-rc.d ovpn-admin stop || exit $?
fi

if [ "$1" = "purge" ]; then
  rm /etc/openvpn/admin-config.json
  rm /etc/openvpn/server.conf.test
fi
