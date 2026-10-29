# Yealink BLF Control Center – zentraler Multi-Tenant-Statusserver

Version: **1.4 Test-/Pilotversion** · ein Asterisk mit PJSIP, Python-API und browserbasierter Kundenverwaltung · keine Verbindung *vom Server zur 3CX*.

## Funktionsprinzip

```text
3CX CFD (Kunde A)  --HTTPS POST mit Kunden-API-Schlüssel-->  Nginx Proxy Manager:443
                                                             |
                                                             v
                                               BLF Control Center:8787/TCP
                                                 SQLite + Asterisk CLI
                                                             |
                                                             v
Yealink Telefon (Kunde A): SIP REGISTER/SUBSCRIBE -> Asterisk:5062/UDP -> SIP NOTIFY -> LED
```

- Ein zentraler Container für viele Kunden/Anlagen; keine 3CX-Trunks, keine Polling-Verbindung des Statusservers zu Kunden-PBXen.
- Getrennte SIP-Accounts pro **Telefon**, eigene Asterisk-Kontexte und Statuswerte pro **Kunde**. BLF-Nebenstelle `9001` darf bei jedem Kunden dieselbe Nummer sein.
- Eigener API-Schlüssel pro Kunde, der **den Kunden bestimmt**; ein Client kann nicht durch Manipulation von Kunden-IDs andere Anlagen steuern.
- Admin-Weboberfläche unter `/admin` mit Login, Kunden, Telefonen, Statuswerten, API-Key-Rotation und manueller Statusprüfung.
- Sichere, kundenspezifische 3CX-Custom-Template-Downloads (enthalten SIP-Passwörter). Standardmäßig wird **Taste 1** (für T40G/T42G/T46G/T48G sowie T46S/T54W und Modelle in derselben 3CX-Tastengruppe) die Status-BLF `9001` auf SIP-Account 2. **Taste 2 und alle weiteren bleiben weiterhin gemäß 3CX konfigurierbar.**
- Die Callflow-Nummern (etwa 951) bleiben ausschließlich auf der 3CX-Seite. Der Statusserver ruft **keine** 3CX an.

### Hinweis zur Tastenkonfiguration

Taste 1 zeigt nur den Zustand der Spontanschaltung an. Sie ist eine **normale BLF** von Asterisk, kein Callflow-Schalter. Beim Drücken versucht das Telefon in der Regel, `9001` über Account 2 zu wählen; auf Asterisk wird ein solcher Anruf verworfen. Ein-/Ausschalten erfolgt über regulär von 3CX eingerichtete Speed-Dial-/CFD-Tasten oder andere bestehende Wege. Es werden **keine Callflow-Tasten** in der Vorlage hartkodiert.

Die physische Taste 1 ist damit **nicht mehr über BLF-Feld 1 der 3CX konfigurierbar**. Die 3CX-Felder ab 2 bleiben unverändert und belegen die physischen Tasten 2 ff. Für Anlagen mit weiteren Status-BLFs (z. B. 9002/9003) legt die Admin-Oberfläche die Statusressourcen an; die zusätzliche Zuweisung auf freie Yealink-Tasten ist in dieser Version noch manuell bzw. als kundenspezifische Erweiterung der Vorlage vorzunehmen.

## Upgrade vom bisherigen `blf-asterisk`-Testcontainer

**Vorher: Backup des bestehenden Docker-Volumes `asterisk-state` erstellen.** Die neue Version verwendet **dasselbe** Volume und denselben Container-Namen. Bitte **keine zweite Instanz** parallel auf Port 5062 starten.

1. Die vollständigen Dateien dieses ZIP ins Root-Verzeichnis des bisherigen GitHub-Repositories `yealink-blf-status-server` hochladen. Keine `.env`-Datei mit Geheimnissen committen.
2. Dockhand: Bei einem **manuell angelegten Stack mit GitHub-Remote-Build** den Inhalt von `docker-compose.remote.yml` übernehmen und `DEIN-USERNAME` in der GitHub-URL ersetzen. Ein *privates* GitHub-Repository braucht Git-Authentifizierung bzw. einen Dockhand Git-Stack mit `docker-compose.yml` (`build.context: .`).
3. Die **bestehenden Variablen** `SIP_PASSWORD` und `API_TOKEN` für die einmalige Übernahme des bisherigen `status01`-Testkontos **beibehalten**. Ergänzen:

   ```env
   ADMIN_PASSWORD=<starkes-einmaliges-Passwort-mindestens-20-Zeichen>
   SIP_HOST=blf.deine-domain.de
   API_BIND_IP=192.168.178.100
   API_PORT=8787
   SIP_PORT=5062
   ```

   `API_BIND_IP` ist die **private Docker-Host-IP**, auf der Nginx Proxy Manager zugreifen kann. Sitzt Nginx auf demselben Host *außerhalb* von Docker, kann `127.0.0.1` verwendet werden. `0.0.0.0` ist aus Sicherheitsgründen absichtlich nicht erlaubt.

4. Falls der Docker-Host **direkt** eine öffentliche IPv4 besitzt, `SIP_PUBLIC_IP` und `SIP_LOCAL_NET` leer lassen. Hinter NAT diese Parameter passend konfigurieren (SIP_PUBLIC_IP akzeptiert gegenwärtig nur IPv4). FQDN des Servers ist für Telefone `SIP_HOST`; ein HTTP-Nginx-Proxy kann **kein SIP/UDP** weiterleiten.
5. In Dockhand: **Image neu bauen und Stack neu erstellen/deployen**. Neue Version übernimmt bei **erster Datenbankinitialisierung** `status01`, `SIP_PASSWORD`, `API_TOKEN` als Kunden `testanlage`, BLF-Nummer 9001. Ein erneutes Provisionieren/Registrieren des Testtelefons kann nach dem Upgrade erforderlich sein. Der vorübergehend sichtbare SIP-Status kann sich ändern, da sich der Asterisk-Hint-Kontext geändert hat.
6. Der Initialwert für die übernommene Testanlage ist AUS (`0`); gewünschten Istwert nach dem Update über das Admin-Webinterface oder den bisherigen API-Schlüssel erneut melden. Wenn die neue DB existiert, werden `SIP_PASSWORD`/`API_TOKEN` nicht erneut importiert oder zurückgesetzt.
7. Logs, SIP-Registrierung und Hint prüfen:

   ```bash
   asterisk -rx "pjsip show contacts"
   asterisk -rx "core show hints"
   asterisk -rx "pjsip show subscriptions inbound"
   ```

   Diese Befehle **direkt** in der Dockhand-Shell des Containers eingeben (nicht `docker exec` innerhalb des Containers).

### Persistenz

Datenbank und generierte Asterisk-Konfiguration liegen im persistenten Docker-Volume unter `/var/lib/asterisk/blf`. Keine SIP-/API-Secrets in Docker-Images, GitHub oder Logs ablegen. Der Admin-Login verwendet ein PBKDF2-gehashtes Passwort, API-Schlüssel werden zur API-Authentifizierung als SHA-256-Hash und für die optionale Wiederanzeige zusätzlich verschlüsselt (Fernet) gespeichert. SIP-Passwörter werden zum Generieren der PJSIP-Konfiguration **im geschützten lokalen Datenbank-Volume im Klartext** benötigt; schützt dieses Volume samt Backups entsprechend. Die Admin-Passwort-Umgebungsvariable wird nur bei der **Ersteinrichtung** für die Datenbank verwendet; danach ist ein Passwortwechsel über `/admin/password` möglich.

## Nginx Proxy Manager: HTTPS

Die normale HTTP/HTTPS-Weiterleitung ist **nur für die Verwaltungs-/CFD-API** geeignet, nicht für SIP.

| Option | Einstellung |
|---|---|
| Domain Names | `blf-api.deine-domain.de` |
| Scheme | `http` |
| Forward Hostname/IP | Private Docker-Host-IP aus `API_BIND_IP` |
| Forward Port | `8787` |
| SSL | Öffentlich gültiges Zertifikat, Force SSL einschalten |
| Router | Eingehend HTTPS 443 zu Nginx; **kein** öffentlicher TCP-Port 8787 |
| Firewall | TCP 8787 ausschließlich aus Richtung Nginx erlauben |
| SIP | Weiterhin UDP 5062 direkt an Asterisk-Docker-Host |

Sicherheitsmaßnahmen: Admin-Zugriff auf `/admin` über Nginx nach Möglichkeit zusätzlich auf Verwaltungs-IP/VPN beschränken. Asterisk-SIP nur für benötigte Standorte zulassen, soweit sinnvoll. Bei 100 dynamischen Kunden-IP-Adressen langfristig SIP/TLS, Monitoring und Fail2ban/Firewall-Konzept prüfen. HTTPS-Zertifikat auf Nginx aktualisieren, Proxy und Container patchen. Für Dauerbetrieb die Netzwerkschnittstellen und Administration weiter härten.

## Webinterface: Kunden hinzufügen

1. `https://blf-api.deine-domain.de/admin` öffnen. Beim ersten Start mit `ADMIN_PASSWORD` anmelden.
2. **Neuen Kunden anlegen** (`name`, eindeutige `slug`-Kennung). Standardstatus `spontanschaltung` mit BLF-Nummer `9001` wird automatisch eingerichtet.
3. API-Schlüssel nach der Anlage sicher verwahren. Bei Schlüsseln aus Version 1.2 kann er später nach erneuter Admin-Passwortprüfung unter **API-Schlüssel anzeigen** eingesehen werden. Schlüssel aus der alten Version lassen sich nur anzeigen, wenn der frühere `API_TOKEN` noch bekannt ist; sonst einmalig **API-Schlüssel neu erzeugen** verwenden (alter Schlüssel verliert dann sofort seine Gültigkeit).
4. Ein **Telefon hinzufügen**, Bezeichnung eingeben. Das neue SIP-Konto wird serverseitig erzeugt und Asterisk neu geladen.
5. Unter dem Telefon **BLF-Label / XML herunterladen** auswählen; dort das Feld **Beschriftung der Status-BLF (Taste 1)** anpassen (Standard `Status`) und **Label speichern und 3CX-XML herunterladen** klicken. Das Label wird für dieses Telefon gespeichert und beim nächsten Export erneut vorgeschlagen.
6. Kunden bei Bedarf deaktivieren, zusätzliche Statusressourcen (z. B. `notbetrieb`, BLF `9002`) hinzufügen und aktuelle Zustände im Webinterface überprüfen.

**Wichtig:** Der Template-Download ist personalisiert und enthält das SIP-Passwort für Account 2. **Nicht auf öffentliches GitHub hochladen**, nicht unverschlüsselt versenden.

## 3CX-Vorlage für Steuerungs-Telefone

Die beigefügte Originalvorlage `templates/source-yealinkT4x.ph.xml` stammt aus der bereitgestellten 3CX-Konfiguration. Die Admin-Oberfläche erzeugt daraus eine personalisierte Version mit:

- unverändertem Account 1 (3CX)
- einem für dieses Telefon individuellen Account 2 mit SIP-Domain aus `SIP_HOST` und Port 5062
- **physischer Taste 1**: `linekey.1.type=16`, `linekey.1.line=2`, `linekey.1.value=9001`, Label `Status` (je Telefon editierbar vor dem Download)
- **Tasten 2 ff.**: unveränderte 3CX-DSS-Belegungen
- eigenem Vorlagennamen und abgewandelten Yealink-y-Dateinamen (`y100...`) gegenüber der Standardvorlage

Die Taste-1-Belegung umfasst die T46S/T54W-Modellgruppe sowie T40G, T42G, T46G (Modellname in 3CX: Yealink T46) und T48G. Weitere Modelle bitte vor Einsatz in der erzeugten 3CX-Provisionierung gezielt pruefen.

**Einbindung in 3CX:** Nach 3CX-Anleitung ein Custom Phone Template für den jeweiligen Kunden anlegen und das personalisierte XML als Basis verwenden, z. B. unter dem vorgesehenen `CustomTemplates/phones/`-Verzeichnis auf einer selbst verwalteten Installation. Bei einer per 3CX-UI erzeugten Vorlagenkopie beachten, dass Namen, Modelle und y-Dateinamen zueinander passen. Je nach 3CX-Edition/Hosting kann der Zugriff auf die Vorlagen eingeschränkt sein. Das **Ändern eines Custom Templates hebt die normale 3CX-Unterstützung für das Telefon teilweise auf**. Vor Einsatz immer `View Configuration` kontrollieren und eine gezielte Reprovisionierung **nur eines Testtelefons** durchführen. Die `y100...` Dateinamen müssen pro PBX eindeutig sein und gegebenenfalls angepasst werden, falls andere Custom Templates sie bereits verwenden.

**3CX-Tests nach Reprovisionierung:** Account 1 weiterhin registriert, Account 2 registriert, Taste 1 zeigt Status-BLF, Taste 2 und folgende werden von 3CX gesetzt. Die zugehörige IP-Phone-Template-Dokumentation ist in der 3CX-Webseite beschrieben: https://www.3cx.com/docs/custom-ip-phone-templates/

Die mitgelieferte Datei `templates/BEISPIEL-KEINE-ECHTEN-ZUGANGSDATEN.xml` ist **nur ein Muster mit Platzhalterwerten**; sie ist nicht direkt für eine Kundenanlage geeignet. Das richtige XML wird über `/admin` nach dem Anlegen des Telefons exportiert.

## 3CX CFD: Status per HTTPS melden

> 3CX → HTTPS ist die **einzige** Schnittstelle zwischen PBX und diesem Statusserver. Vom Statusserver wird **keine Anfrage zur 3CX gesendet**.

### Ziel-Endpunkt

```http
POST https://blf-api.deine-domain.de/v1/status/spontanschaltung
Content-Type: application/json
X-API-Key: blf_<kundenspezifischer-schluessel>

{"value":1}
```

- `value: 1` = **EIN / BUSY / rote BLF**
- `value: 0` = **AUS / NOT_INUSE / grüne BLF**
- **Kunden-ID wird nicht übertragen!** Die API identifiziert den Kunden aus dem API-Schlüssel.
- Für andere Statusnamen z. B. `/v1/status/notbetrieb`; sie müssen vorher im Dashboard angelegt werden.
- Die alte Route `/v1/status` steht als Alias für `spontanschaltung` bereit.

### Konfiguration im Call Flow Designer

3CX CFD-Komponente **HTTP Request** *nachdem* der 3CX-Globale-Parameter erfolgreich geschrieben wurde:

| CFD-Property | Beispiel |
|---|---|
| RequestType | `POST` |
| URI (String-Expression) | `"https://blf-api.deine-domain.de/v1/status/spontanschaltung"` |
| Content-Type | `application/json` |
| Headers: Name | `X-API-Key` (als Header-Name ohne zusätzliche Quotes) |
| Headers: Value (Expression) | `"blf_DEIN_KUNDEN_TOKEN"` |
| Timeout | `5` Sekunden |
| Content (für EIN als String-Expression) | `"{\"value\":1}"` |
| Content (für AUS als String-Expression) | `"{\"value\":0}"` |

HTTP-Request-Komponente und Properties: https://www.3cx.com/docs/manual/cfd-components/

**Keine Toggle-API verwenden.** Der CFD muss den *wirklichen neuen Wert* `0` oder `1` melden, damit wiederholte Meldungen idempotent bleiben. Wenn andere Wege den 3CX-Parameter ändern, müssen diese ebenfalls die API informieren. Andernfalls wird die LED irgendwann veraltet sein. `ResponseStatusCode == 200` im CFD prüfen, Fehler protokollieren und gegebenenfalls Statusmeldung wiederholen.

### Curl-Test

```bash
curl --fail-with-body -X POST 'https://blf-api.deine-domain.de/v1/status/spontanschaltung' \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: blf_KUNDEN_API_TOKEN' \
  --data '{"value":1}'
```

Erfolgsantwort:

```json
{"ok":true,"value":1,"state":"BUSY","status":"spontanschaltung"}
```

Fehler: `401` Schlüssel ungültig, `400` ungültiger JSON-Wert, `404` Status existiert nicht, `429` mehr als 60 Änderungen/Minute/Kunde, `503` Asterisk nicht erreichbar.

**HTTP 200 bedeutet:** Asterisk hat den Änderungsbefehl angenommen, *nicht* dass jeder Yealink die NOTIFY-Nachricht erhalten hat. Für größere Rollouts SIP-Watcher, Registrierung, Monitoring und Konflikte mit 3CX-NAT/STUN beobachten.

## Tests, Wartung, Grenzen

Lokale Logik- und HTTP-Tests ohne Docker/Asterisk:

```bash
python3 -m unittest discover -s tests -v
```

Das Paket hat automatisierte Testfälle für Login, CSRF, Tenant-API-Isolation, Token-Rotation, Migration und XML-Export. **Ein Docker-Build, der echte Asterisk-Prozess sowie eine 3CX-End-to-End-Provisionierung wurden in dieser Umgebung nicht getestet.** Deshalb zuerst in einer Testanlage deployen und überwachen; nicht unmittelbar an 100 Anlagen ausrollen.

Asterisk-Prozesse nutzen auch im Leerlauf CPU für SIP-Registrierungen, Timer und Watcher. 1–2 % können bei der aktuellen Testanlage normal sein; vor Rollout Last mit ca. 100 SIP-Konten messen, auch nach stündlichen Statuswechseln. SQLite und ein einzelner Docker-Host sind für diese Größenordnung plausibel, aber noch nicht lastgetestet oder hochverfügbar. Datenbankvolumen regelmäßig sichern, Wiederherstellung üben. Langfristig empfehlen sich rollenbasierte Admin-Logins, zweite Administratoren/MFA, TLS für SIP, Audit-Anzeige, IP-Rate-Limiting am Proxy und echte HA-Tests.

## Update 1.0.1 – Fix fehlendes Python-Standardmodul `hmac`

Die erste Multi-Tenant-Dockerfile installierte `python3-minimal`. Unter Ubuntu 24.04
fehlen dadurch fuer diese Anwendung erforderliche Standardbibliotheksmodule wie
`hmac`. Die Dockerfile installiert jetzt das vollstaendige Ubuntu-Paket `python3`.
Ein Import-Smoke-Test im Docker-Build prueft die benoetigten Module.

**Vorgehen fuer bestehende Dockhand-Stacks:** Die korrigierte `Dockerfile` nach
GitHub committen (alle anderen Dateien koennen bleiben). In Dockhand einen
**neuen Build des Images** starten und danach den Container neu erstellen.
Ein Container-Neustart ohne neuen Image-Build behebt den Fehler **nicht**.
Die `docker-compose.remote.yml` und alle bestehenden Umgebungsvariablen koennen
unveraendert bleiben. Das persistente `asterisk-state`-Volume nicht loeschen.

## Update: Yealink-T4x-G-Serie (T40G, T42G, T46G, T48G)

Die generierte kundenspezifische Vorlage enthält nun zusätzlich die Modelle:

| Hardware | 3CX-Modellbezeichnung | SIP-User-Agent | Yealink-Common-CFG |
|---|---|---|---|
| T40G | Yealink T40G | SIP-T40G | y100000000076.cfg |
| T42G | Yealink T42 | SIP-T42G | y100000000029.cfg |
| T46G | Yealink T46 | SIP-T46G | y100000000028.cfg |
| T48G | Yealink T48 | SIP-T48G | y100000000035.cfg |

Die `y100...`-Namen sind die für den 3CX-Custom-Template-Export geänderten
`y000...`-Dateinamen, um Kollisionen mit der Originalvorlage zu vermeiden.
Der Generator reserviert für diese Geräte Taste 1 als BLF `9001` über
SIP-Account 2. Die ab Taste 2 von 3CX provisionierten Einstellungen bleiben
modellabhängig erhalten. Es werden keine Callflow-Tasten fest vorbelegt.

**Vorhandene Kunden/Telefone bleiben erhalten.** Beim Upgrade nur den
GitHub-Code aktualisieren, in Dockhand das Docker-Image **neu bauen** und den
Stack neu erstellen. Das persistente `asterisk-state`-Volume nicht löschen.
Danach im Admin-Webinterface beim vorhandenen Kunden/Telefon die XML-Vorlage
**neu herunterladen** und in der jeweiligen 3CX-Instanz hinterlegen.
Bereits exportierte XML-Dateien aktualisieren sich nicht automatisch.

Ältere G-Geräte sind in aktuellen 3CX-Versionen teils nicht mehr offiziell
unterstützt; nach der Anpassung bitte zuerst an einer Testanlage die
3CX-Modellauswahl sowie das tatsächliche Provisionieren des T46G prüfen.
Ein Custom-Template kann je nach 3CX-Version und Bereitstellungsmodell
zusätzliche Einschränkungen haben. Für manche Modelle kann eine
Neuprovisionierung bzw. ein Werksreset nötig sein.


## Version 1.2 – Telefon löschen, API-Key anzeigen und T4x-G-Serie

- **Telefon löschen:** Unter Kunde → Telefone → **Verwalten / löschen** die
  Details des Telefons öffnen. Den Abschnitt „Telefon dauerhaft löschen“
  ausklappen, zur Bestätigung die SIP-Kennung eintippen und löschen.
  Der SIP-Account wird aus Datenbank und generierter PJSIP-Konfiguration
  entfernt und ein Asterisk-Reload ausgelöst. Exportierte XML-Dateien
  enthalten weiterhin die früheren Zugangsdaten, die nach erfolgreichem
  Reload keine gültige Registrierung mehr ermöglichen sollen.
- **API-Key anzeigen:** Auf der Kundendetailseite „API-Schlüssel anzeigen“
  ausklappen und das Admin-Passwort erneut eingeben. Der Schlüssel wird nur
  auf der explizit angeforderten Antwortseite sichtbar; diese wird mit
  `Cache-Control: no-store` ausgeliefert. Neukunden- und rotierte Schlüssel
  werden verschlüsselt im SQLite-Volume gespeichert (Fernet/AES).
- **Bestehende API-Keys:** Die alte Version hat ausschließlich SHA-256-Hashes
  gespeichert; diese können nicht rückgängig gemacht werden. **Ausnahme:**
  Ist der frühere `API_TOKEN` noch als Dockhand-Variable vorhanden und der
  Hash stimmt überein, übernimmt das System diesen Wert verschlüsselt.
  Anderenfalls für eine erneute Anzeige **einmalig rotieren**. Danach muss
  der neue Schlüssel im betreffenden CFD hinterlegt werden.
- **Verschlüsselungsschlüssel:** Bei erster Initialisierung wird
  `/var/lib/asterisk/blf/.api-key-fernet.key` erstellt (Dateimodus 0600).
  **Diesen Schlüssel zusammen mit dem Datenbank-Volume sichern.** Fehlt
  er später und liegen verschlüsselte API-Schlüssel vor, startet die Anwendung
  aus Sicherheitsgründen nicht mit einem neu erzeugten Schlüssel. Das
  Volume und sein Backup dürfen nicht öffentlich zugänglich sein. Die
  verschlüsselte Speicherung schützt nicht vor einem Angreifer, der
  sowohl Datenbank als auch Schlüsseldatei kontrolliert.
- **Python-Laufzeit:** Das Image enthält jetzt `python3-cryptography` aus
  Ubuntu und testet den Import beim Docker-Build. Image in Dockhand neu
  **bauen** und Stack **neu erstellen**. Die Compose-Datei muss nicht geändert
  werden; das `asterisk-state`-Volume unbedingt beibehalten.
- **Yealink T46G:** In der kundenspezifisch generierten Vorlage als Modell
  **„Yealink T46 [BLF kundenkennung]“** verfügbar. Zusätzlich T42G als
  „Yealink T42“, T48G als „Yealink T48“; T40G war bereits enthalten.
  Bereits gespeicherte Kunden müssen die XML einfach neu herunterladen und
  die aktualisierte Vorlage in der 3CX importieren. Taste 1 ist die
  Status-BLF; übrige Tasten bleiben in 3CX konfigurierbar.

**Sicherheitshinweis:** Der Zugang zum `/admin`-Interface sollte zusätzlich
in Nginx durch VPN oder IP-Allowlist eingeschränkt werden. Die Möglichkeit,
API-Schlüssel wieder anzuzeigen, ist bewusst nur für authentifizierte
Administratoren nach erneuter Passwortprüfung implementiert.


## Version 1.3 – Kunden dauerhaft löschen

Unter **Kunde → Administration → Kunde dauerhaft löschen** kann eine komplette
Kundenanlage gelöscht werden. Die Schaltfläche erfordert die exakte Kundenkennung,
das aktuelle Admin-Passwort sowie den üblichen CSRF-Schutz. Entfernt werden
alle API-Schlüssel, Statuswerte, Telefone/SIP-Konten und kundenbezogenen
Anwendungs-Auditeinträge. Ein minimaler Löschvorgang ohne Kundennamen verbleibt
im Audit-Log. Alte API-Schlüssel sind danach ungültig, SIP-Konten werden aus der
generierten Asterisk-Konfiguration entfernt und Asterisk wird neu geladen.

**Vor dem Löschen:** Volume-Backup erstellen, CFD-Zugänge entfernen und sicherstellen,
dass der Kunde wirklich gelöscht werden soll. Bestehende 3CX-Custom-Templates
und bereits provisionierte Telefonkonfigurationen werden **nicht** automatisch
auf entfernten 3CX-Anlagen geändert – der BLF-Server verbindet sich nie zu 3CX.
Backups und externe Logs bleiben unabhängig von der Datenbanklöschung erhalten.

Eine zusätzliche Migrationssperre verhindert, dass beim Löschen des letzten
Kunden die frühere Testanlage nach einem Container-Neustart durch noch gesetzte
`SIP_PASSWORD` / `API_TOKEN` Variablen automatisch erneut angelegt wird.

## Version 1.4 - BLF-Tastenlabel anpassen

Beim kundenbezogenen Telefonexport kann das **Label der Status-BLF auf Taste 1**
vor dem Download bearbeitet werden. Voreinstellung fuer neue und bisherige Telefone: `Status`.
Die Schaltlogik, Nebenstelle 9001, Account 2 und alle 3CX-Tasten ab Position 2
werden nicht veraendert.

- Kunde oeffnen, Telefon waehlen und **BLF-Label / XML herunterladen** auswaehlen.
- Unter **Beschriftung der Status-BLF (Taste 1)** einen Text eingeben.
- **Label speichern und 3CX-XML herunterladen** klicken. Das Label wird
  je Telefon dauerhaft gespeichert; es kann bei einem spaeteren Export
  erneut angepasst werden.
- Maximal 40 druckbare Zeichen; Zeilenumbrueche sind unzulaessig.
- Nach dem Import der geaenderten XML-Vorlage in 3CX das Telefon neu
  provisionieren, damit das Label auf dem Yealink sichtbar wird.

Beim Update von v1.3 migriert die Datenbank automatisch. Alle Kunden,
Telefone, API-Schluessel und SIP-Zugangsdaten bleiben erhalten.
