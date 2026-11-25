#!/bin/sh
set -eu

address=${SENTINELLOGS_NGINX_BIND_ADDRESS:-}
if ! printf '%s\n' "$address" | awk -F. '
  NF != 4 { exit 1 }
  {
    for (i = 1; i <= 4; i++) {
      if ($i !~ /^[0-9]+$/ || $i > 255 || ($i ~ /^0[0-9]+$/)) exit 1
    }
    if ($1 == 0 && $2 == 0 && $3 == 0 && $4 == 0) exit 1
  }
'; then
  printf '%s\n' "Nginx requires an explicit IPv4 bind address assigned to its container." >&2
  exit 1
fi

sed "s/@SENTINELLOGS_NGINX_BIND_ADDRESS@/$address/g" \
  /etc/nginx/nginx.conf.template > /tmp/sentinellogs-nginx.conf
exec nginx -c /tmp/sentinellogs-nginx.conf -g 'daemon off;'
