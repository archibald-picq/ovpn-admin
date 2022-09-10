#!/bin/sh

set -e

case "$1" in
	configure)
#		if [ -z "$2" ]; then
#			addgroup --system docker
#		fi
		;;
	abort-*)
		# How'd we get here??
		exit 1
		;;
	*)
		;;
esac

deb-systemd-helper unmask ovpn-admin.service >/dev/null || true

# was-enabled defaults to true, so new installations run enable.
if deb-systemd-helper --quiet was-enabled ovpn-admin.service; then
	# Enables the unit on first installation, creates new
	# symlinks on upgrades if the unit file has changed.
	deb-systemd-helper enable ovpn-admin.service >/dev/null || true
else
	# Update the statefile to add new symlinks (if any), which need to be
	# cleaned up on purge. Also remove old symlinks.
	deb-systemd-helper update-state ovpn-admin.service >/dev/null || true
fi

systemctl enable ovpn-admin.service
systemctl start ovpn-admin.service
