#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
: "${ADMIN_PASSWORD:?ADMIN_PASSWORD_muss_in_Dockhand_gesetzt_sein}"
: "${SIP_HOST:?SIP_HOST_muss_den_oeffentlichen_SIP_FQDN_enthalten}"
if [[ ${#ADMIN_PASSWORD} -lt 20 ]]; then echo 'ADMIN_PASSWORD muss mindestens 20 Zeichen haben' >&2; exit 1; fi
if ! [[ "$SIP_HOST" =~ ^[a-zA-Z0-9.-]+$ ]] || [[ "$SIP_HOST" == *..* ]] || [[ "$SIP_HOST" == .* ]]; then
  echo 'SIP_HOST muss ein DNS-Name (ohne Schema/Port) sein' >&2; exit 1
fi
SIP_PORT=${SIP_PORT:-5062}
API_PORT=${API_PORT:-8787}
API_BIND_IP=${API_BIND_IP:-127.0.0.1}
for name in SIP_PORT API_PORT; do
  value=${!name}
  if ! [[ $value =~ ^[0-9]+$ ]] || ((10#$value < 1024 || 10#$value > 65535)); then echo "Ungültiger Port: $name" >&2; exit 1; fi
done
python3 - "$API_BIND_IP" "${SIP_PUBLIC_IP:-}" "${SIP_LOCAL_NET:-}" <<'PY'
import ipaddress, sys
bind, external, local = sys.argv[1:]
b = ipaddress.IPv4Address(bind)
if not any(b in ipaddress.IPv4Network(n) for n in ('127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
    raise SystemExit('API_BIND_IP muss eine private/Loopback-IPv4 sein')
if external: ipaddress.IPv4Address(external)
if local: ipaddress.IPv4Network(local, strict=False)
PY
if [[ -n ${SIP_PASSWORD:-} ]]; then
  [[ ${#SIP_PASSWORD} -ge 20 && ${SIP_PASSWORD} =~ ^[a-zA-Z0-9._~-]+$ ]] || { echo 'Altes SIP_PASSWORD ist ungültig' >&2; exit 1; }
fi
# Vorhandene SIP/API Test-Credentials werden nur beim erstmaligen Erstellen der DB importiert.
mkdir -p /var/lib/asterisk/blf /run/asterisk
chown -R asterisk:asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /run/asterisk
# Initialisierung unter asterisk, DB/Configs nur fuer diesen Account lesbar.
gosu asterisk python3 /opt/blf/app.py --init
ln -sfn /var/lib/asterisk/blf/pjsip.conf /etc/asterisk/pjsip.conf
ln -sfn /var/lib/asterisk/blf/extensions.conf /etc/asterisk/extensions.conf
asterisk_pid=''; api_pid=''
cleanup() {
  trap - TERM INT
  [[ -z $api_pid ]] || kill "$api_pid" 2>/dev/null || true
  [[ -z $asterisk_pid ]] || kill "$asterisk_pid" 2>/dev/null || true
  [[ -z $api_pid ]] || wait "$api_pid" 2>/dev/null || true
  [[ -z $asterisk_pid ]] || wait "$asterisk_pid" 2>/dev/null || true
}
trap 'cleanup; exit 143' TERM
trap 'cleanup; exit 130' INT
printf 'Starte Asterisk UDP %s und Verwaltungs-API %s:%s\n' "$SIP_PORT" "$API_BIND_IP" "$API_PORT"
gosu asterisk /usr/sbin/asterisk -f & asterisk_pid=$!
gosu asterisk /usr/bin/python3 -u /opt/blf/app.py & api_pid=$!
set +e
wait -n "$asterisk_pid" "$api_pid"
exit_code=$?
set -e
cleanup
if [[ $exit_code -eq 0 ]]; then exit 1; fi
exit "$exit_code"
