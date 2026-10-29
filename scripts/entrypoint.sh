#!/bin/sh
set -eu

# Das Kennwort wird nur beim Start erzeugter Asterisk-Konfiguration uebergeben.
# Zugelassen sind bewusst nur Zeichen, die in pjsip.conf nicht escaped werden muessen.
: "${SIP_PASSWORD:?SIP_PASSWORD muss in Dockhand als Secret gesetzt sein}"
case "$SIP_PASSWORD" in
  *[!a-zA-Z0-9._~-]*|'')
    echo 'FEHLER: SIP_PASSWORD darf nur Buchstaben, Zahlen sowie . _ ~ - enthalten.' >&2
    exit 1
    ;;
esac
if [ "${#SIP_PASSWORD}" -lt 20 ]; then
  echo 'FEHLER: SIP_PASSWORD muss mindestens 20 Zeichen lang sein.' >&2
  exit 1
fi

SIP_PORT=${SIP_PORT:-5062}
case "$SIP_PORT" in
  *[!0-9]*|'') echo 'FEHLER: SIP_PORT muss eine Zahl sein.' >&2; exit 1 ;;
esac
if [ "$SIP_PORT" -lt 1024 ] || [ "$SIP_PORT" -gt 65535 ]; then
  echo 'FEHLER: SIP_PORT muss im Bereich 1024..65535 liegen.' >&2
  exit 1
fi

# Optional fuer Server hinter NAT. Leere Werte werden nicht geschrieben.
if [ -n "${SIP_PUBLIC_IP:-}" ]; then
  case "$SIP_PUBLIC_IP" in
    *[!0-9.]*|'') echo 'FEHLER: SIP_PUBLIC_IP muss eine IPv4-Adresse sein.' >&2; exit 1 ;;
  esac
fi
if [ -n "${SIP_LOCAL_NET:-}" ]; then
  case "$SIP_LOCAL_NET" in
    *[!0-9./]*|'') echo 'FEHLER: SIP_LOCAL_NET muss IPv4/CIDR sein.' >&2; exit 1 ;;
  esac
fi

umask 077
cat > /etc/asterisk/pjsip.conf <<EOF_PJSIP
; Automatisch erzeugt. Nicht manuell innerhalb des Containers bearbeiten.
[global]
type=global
user_agent=Yealink-BLF-Lab

[transport-blf]
type=transport
protocol=udp
bind=0.0.0.0:${SIP_PORT}
EOF_PJSIP

if [ -n "${SIP_PUBLIC_IP:-}" ]; then
  printf 'external_signaling_address=%s\nexternal_signaling_port=%s\n' \
    "$SIP_PUBLIC_IP" "$SIP_PORT" >> /etc/asterisk/pjsip.conf
fi
if [ -n "${SIP_LOCAL_NET:-}" ]; then
  printf 'local_net=%s\n' "$SIP_LOCAL_NET" >> /etc/asterisk/pjsip.conf
fi

cat >> /etc/asterisk/pjsip.conf <<EOF_PJSIP

; Ein Testtelefon: SIP-Account 2 am Yealink.
[status01]
type=endpoint
transport=transport-blf
context=presence-test
disallow=all
allow=alaw,ulaw
auth=auth-status01
aors=status01
allow_subscribe=yes
rewrite_contact=yes
force_rport=yes
rtp_symmetric=yes
direct_media=no

[auth-status01]
type=auth
auth_type=userpass
username=status01
password=${SIP_PASSWORD}

[status01]
type=aor
max_contacts=1
remove_existing=yes
qualify_frequency=30
EOF_PJSIP

chown asterisk:asterisk /etc/asterisk/pjsip.conf
install -d -o asterisk -g asterisk /run/asterisk
# Das Named Volume wird beim ersten Start ggf. als root erstellt.
chown -R asterisk:asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk

echo 'Starte Asterisk (PJSIP/BLF-Test) ...'
exec /usr/sbin/asterisk -f -U asterisk -G asterisk -vvv
