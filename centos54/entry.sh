#!/bin/sh
set -e
mkdir -p /tmp/sessions
chmod 777 /tmp/sessions
exec /usr/sbin/httpd -DFOREGROUND
