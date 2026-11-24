#!/bin/bash
# Prints what the operator needs after an install: address, setup code, fingerprint.
set -euo pipefail
port_suffix=""
[ "${BUS_PORT:-443}" = "443" ] || port_suffix=":${BUS_PORT}"
echo "Console address : https://${BUS_HOSTNAME}${port_suffix}"
if [ -s /data/bus/operator/setup-code ]; then
  echo "Setup code      : $(cat /data/bus/operator/setup-code)"
  echo "                  (one use; a new code is issued each time the container restarts until a password is set)"
else
  echo "Setup code      : none - the operator password is already set"
fi
if [ -s /data/ca-root.crt ]; then
  echo "Certificate root: /data/ca-root.crt (copy it out with: docker compose cp bus:/data/ca-root.crt .)"
  /opt/strugglebus/bin/python -c "
import hashlib, ssl, sys
digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[1]).read())).hexdigest().upper()
print('SHA-256 print   : ' + ':'.join(digest[i:i + 2] for i in range(0, 64, 2)))
" /data/ca-root.crt
fi
