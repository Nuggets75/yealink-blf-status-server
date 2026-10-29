# Yealink BLF-Statusserver: Asterisk + Dockhand (Proof of Concept)

Ein Git-faehiger Docker-Testaufbau fuer **ein Yealink T46S/T54W** mit bereits vorhandenem **3CX-STUN-Account**. Asterisk stellt eine eigene SIP-Registrierung (`status01`, Account 2 am Telefon) und einen BLF-Hint (`9001`) bereit. Die vorhandene 3CX-Telefonie auf Account 1 wird nicht bewusst umkonfiguriert.

**Status:** Testvorlage nach Dokumentation; nicht auf einer konkreten Yealink-Firmware / in deinem Dockhand getestet. Keine produktionsreife zentrale Multi-Mandanten-Plattform, keine CFD-API und kein SIP/TLS. Erst die erfolgreiche Registrierung und BLF-Funktion nachweisen.

## Dateien

```text
.
├── docker-compose.yml
├── Dockerfile
├── config/
│   ├── extensions.conf
│   └── modules.conf
├── scripts/
│   └── entrypoint.sh
├── .env.example
├── .gitignore
└── .dockerignore
```

Die `pjsip.conf` wird **erst beim Containerstart** aus den Dockhand-Umgebungsvariablen erzeugt. So gelangt kein echtes SIP-Passwort ins Git-Repository. Die Konfigurationen werden ins Docker-Image kopiert: Es gibt keine relativen Bind-Mounts, die beim Dockhand-Git-Deployment Probleme bereiten koennten.

## Voraussetzungen

- Linux-Docker-Host (fuer `network_mode: host`), auf dem UDP **5062** frei ist.
- Eine von aussen erreichbare IPv4 oder eine funktionierende Portweiterleitung UDP 5062 an den Docker-Host (kein CGNAT ohne Vermittlung).
- Dockhand mit eingerichtetem Git-Repository (GitHub), Berechtigung zum Build lokaler Images.
- Ein Testtelefon, fuer das du die zweite SIP-Registrierung manuell konfigurieren kannst.
- Externe Erreichbarkeit **nur fuer die oeffentliche WAN-IP des Teststandorts** auf UDP 5062 erlauben, soweit moeglich.

**Achtung:** Das hier ist ein SIP-Testdienst, kein Reverse-Proxy-faeiger HTTP-Dienst. Docker-Host-Networking bedeutet: `ports:` nicht angeben; die Host-Firewall ist fuer den Schutz des Dienstes verantwortlich.

## GitHub und Dockhand

1. Neues GitHub-Repository anlegen, zum Beispiel `yealink-blf-asterisk-lab` (bevorzugt privat).
2. Den **Inhalt dieses Ordners** in das Wurzelverzeichnis des Repositories hochladen, mit den Unterordnern `config/` und `scripts/`. Keine echten Passwoerter committen.
3. In Dockhand unter **Settings -> Git** das Repository einrichten.
4. **Git-Stack** erstellen: Repository und Branch auswaehlen, Compose-Datei **`docker-compose.yml`** (im Repository-Root).
5. **Build images on deploy aktivieren**. Das ist notwendig, weil die Compose-Datei eine `build:`-Anweisung fuer unser eigenes Dockerfile enthaelt. Ohne diese Option kann das lokale Image auf einem neuen Host fehlen.
6. In Dockhand die Variable **`SIP_PASSWORD` als Secret** eintragen (mindestens 20 Zeichen, nur Buchstaben, Zahlen, `.`, `_`, `~`, `-`). Zum Generieren z. B.: `openssl rand -hex 24`.
7. Optional normale Stack-Variablen setzen: `SIP_PORT=5062`, `SIP_PUBLIC_IP=...` und `SIP_LOCAL_NET=...` (siehe unten).
8. Git-Stack deployen und die Logs des Containers `blf-asterisk` pruefen.

Dockhand-Doku: https://dockhand.pro/manual/ (Abschnitte "Git integration", "Build images on deploy", "Secrets").

### Host direkt mit oeffentlicher IPv4

- `SIP_PORT=5062`
- `SIP_PUBLIC_IP` **leer** lassen.
- `SIP_LOCAL_NET` **leer** lassen.
- UDP 5062 in der Host-Firewall fuer den Teststandort freischalten.

### Host hinter Router/NAT

- Router: UDP **5062** an die lokale IP des Docker-Hosts weiterleiten.
- `SIP_PUBLIC_IP` auf die **oeffentliche IPv4 des Routers** setzen.
- `SIP_LOCAL_NET` bei Bedarf auf das lokale Server-Netz setzen, z. B. `192.168.178.0/24`.
- Externer Port und interner Port sollten fuer diesen Test beide 5062 sein.
- Bei CGNAT ohne eingehende IPv4-Portweiterleitung funktioniert dieser direkte Aufbau nicht.

Hinweis: Das ist eine erste NAT-Variante. Bei speziellen NAT-/Firewall-Setups kann SIP-Feintuning erforderlich sein.

## Yealink einrichten (zuerst manuell, nicht im 3CX-Template)

1. Die bestehende 3CX-Registrierung auf **Account 1** nicht anfassen.
2. Im Webinterface unter **Account -> Register** den **Account 2** aktivieren:

| Feld | Wert |
| --- | --- |
| Line Active | Enabled |
| Label | BLF Test |
| Register Name / User Name | `status01` |
| Password | Das `SIP_PASSWORD` aus Dockhand |
| SIP Server | Oeffentliche IPv4 oder DNS-Name des Docker-Hosts |
| SIP Port | `5062` (oder `SIP_PORT`) |
| Transport | UDP |

3. Unter **DSSKey / Line Key** eine freie Taste konfigurieren (z. B. Taste 5):

| Feld | Wert |
| --- | --- |
| Type | BLF |
| Account / Line | **2** |
| Value | `9001` |
| Label | `Spontanschaltung` |

Die entsprechende Yealink-Provisionierungslogik waere grundsaetzlich:

```ini
linekey.5.type = 16
linekey.5.line = 2
linekey.5.value = 9001
linekey.5.label = Spontanschaltung
```

**Wichtig:** Je nach Firmware/3CX-Provisionierung kann ein Reprovisioning die manuellen Einstellungen wieder ueberschreiben. Deshalb zuerst bewusst manuell testen, erst danach das 3CX-Template anpassen. Auf einem Routerphone ist ein eigener Test erforderlich.

## Funktionstest

Auf dem **Docker-Host** mit Zugriff auf den Docker-Daemon:

```bash
docker logs -f blf-asterisk
```

```bash
# Registrierung (erwartet: ein Kontakt fuer status01)
docker exec blf-asterisk asterisk -rx 'pjsip show contacts'

# Vorhandenen Hint und Watcher anzeigen
docker exec blf-asterisk asterisk -rx 'core show hints'

# Pruefen, ob die benoetigten Presence-Module geladen sind
docker exec blf-asterisk asterisk -rx 'module show like res_pjsip_pubsub'
docker exec blf-asterisk asterisk -rx 'module show like res_pjsip_exten_state'

# Normal: frei, erwartete Anzeige gruen (modellabhaengig)
docker exec blf-asterisk asterisk -rx 'devstate change Custom:spontan NOT_INUSE'

# Spontanschaltung: besetzt, erwartete Anzeige rot (modellabhaengig)
docker exec blf-asterisk asterisk -rx 'devstate change Custom:spontan BUSY'

# Wieder Normalbetrieb
docker exec blf-asterisk asterisk -rx 'devstate change Custom:spontan NOT_INUSE'
```

Ein `BUSY`-Device-State erzeugt nicht automatisch einen 3CX-Anruf; er dient hier nur zur Ausloesung des Asterisk-BLF-Hints. Die konkreten Farben und die Zuverlaessigkeit der parallelen Registrierung muessen am realen Telefon geprueft werden.

**Hinweis:** Der initiale Status kann beim ersten Start `UNKNOWN` sein, bis der erste `devstate change`-Befehl ausgefuehrt wird. Der Asterisk-Device-State wird normalerweise in der Asterisk-Datenbank gespeichert; `asterisk-state` ist daher als Docker-Volume persistent.

## Fehlersuche

Zum zeitweisen Mitschneiden der SIP-Signalisierung:

```bash
docker exec blf-asterisk asterisk -rx 'pjsip set logger on'
# ... Registrierung / Taste / Statuswechsel testen ...
docker exec blf-asterisk asterisk -rx 'pjsip set logger off'
```

- **Kein REGISTER / kein Kontakt:** Firewall/Portweiterleitung, SIP-Konto 2, Server-IP und Port pruefen.
- **REGISTER mit 401:** Eine einmalige `401 Unauthorized`-Challenge ist bei SIP-Digest-Authentifizierung normal. Wiederholtes Scheitern danach: Zugangsdaten pruefen.
- **REGISTER funktioniert, aber keine BLF:** Pruefen, ob SUBSCRIBE fuer `9001` ankommt. `core show hints` sollte einen Watcher fuer `9001@presence-test` zeigen. Bei Ablehnung: SIP-Logger und `res_pjsip_exten_state` pruefen.
- **NOTIFY kommt, aber keine Farbe:** BLF-LED-Modus / Tastenbelegung / Yealink-Firmware untersuchen; das ist dann kein reines Server-Erreichbarkeitsproblem.
- **Telefon nach Reprovisionierung wieder ohne Account 2:** 3CX-Template hat lokale Einstellungen ueberschrieben.
- **Host hat bereits eigene SIP-Anlage auf 5062:** `SIP_PORT` andern und Firewall sowie Yealink identisch anpassen.

Asterisk-Referenzen:
- https://docs.asterisk.org/Configuration/Channel-Drivers/SIP/Configuring-res_pjsip/Configuring-res_pjsip-for-Presence-Subscriptions/
- https://docs.asterisk.org/Configuration/Channel-Drivers/SIP/Configuring-res_pjsip/Asterisk-PJSIP-Troubleshooting-Guide/

## Sicherheitsgrenzen dieses Proof of Concept

- **Nur Testbetrieb**, nicht ungeprueft im Internet fuer beliebige IPs exponieren.
- SIP laeuft hier ueber **UDP ohne TLS** und mit Digest-Authentifizierung. SIP-Anmeldungen und Signalisierung sind nicht verschluesselt. Fuer den Produktivbetrieb TLS und Zugangskontrollen einplanen.
- Auf dem Docker-Host die eingehende UDP-5062-Regel nach Moeglichkeit auf die WAN-IP des Testtelefons begrenzen. Kein RTP-Portbereich ist fuer dieses reine BLF-Szenario erforderlich.
- `SIP_PASSWORD` als Dockhand-Secret speichern; es landet danach dennoch in den Container-Umgebungsvariablen und der generierten `pjsip.conf`. Docker-Administratoren koennen darauf zugreifen.
- Bei einem privaten GitHub-Repo ist der Zugriff beschraenkt, aber auch dort gehoeren keine Kennwoerter hinein.
- Es gibt **noch keine HTTPS-CFD-API**; die Statuswechsel erfolgen zunaechst manuell via `docker exec`.
