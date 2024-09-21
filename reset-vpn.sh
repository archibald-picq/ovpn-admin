#!/usr/bin/env bash

ssh root@vpn.seyes.dev '
systemctl stop ovpn-admin.service
systemctl stop openvpn@server.service

rm -rf /etc/openvpn/server.conf
rm -rf /etc/openvpn/ipp.txt
rm -rf /etc/openvpn/openvpn-status.log
rm -rf /etc/openvpn/ccd

#rm -rf /etc/openvpn/easyrsa

systemctl start ovpn-admin.service
'
