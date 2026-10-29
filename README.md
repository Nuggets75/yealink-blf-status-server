# Yealink BLF Control Center – zentraler Multi-Tenant-Statusserver

Version: **1.0 Test-/Pilotversion** · ein Asterisk mit PJSIP, Python-API und browserbasierter Kundenverwaltung · keine Verbindung *vom Server zur 3CX*.

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
- Sichere, kundenspezifische 3CX-Custom-Template-Downloads (enthalten SIP-Passwörter). Standardmäßig wird **Taste 1** (für T46S/T54W sowie Modelle in derselben 3CX-Tastengruppe) die Status-BLF `9001` auf SIP-Account 2. **Taste 2 und alle weiteren bleiben weiterhin gemäß 3CX konfigurierbar.**
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

Datenbank und generierte Asterisk-Konfiguration liegen im persistenten Docker-Volume unter `/var/lib/asterisk/blf`. Keine SIP-/API-Secrets in Docker-Images, GitHub oder Logs ablegen. Der Admin-Login verwendet ein PBKDF2-gehashtes Passwort, API-Schlüssel liegen ausschließlich als SHA-256-Hash vor. SIP-Passwörter werden zum Generieren der PJSIP-Konfiguration **im geschützten lokalen Datenbank-Volume im Klartext** benötigt; schützt dieses Volume samt Backups entsprechend. Die Admin-Passwort-Umgebungsvariable wird nur bei der **Ersteinrichtung** für die Datenbank verwendet; danach ist ein Passwortwechsel über `/admin/password` möglich.

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
3. Den angezeigten **API-Schlüssel sofort kopieren**. Er ist nur einmal sichtbar. Über den Knopf **API-Schlüssel neu erzeugen** kann er ersetzt werden; alter Schlüssel verliert dann sofort seine Gültigkeit.
4. Ein **Telefon hinzufügen**, Bezeichnung eingeben. Das neue SIP-Konto wird serverseitig erzeugt und Asterisk neu geladen.
5. Unter dem Telefon **SIP-Daten** einsehen; dort auch die **kundenspezifische 3CX-XML-Vorlage** herunterladen.
6. Kunden bei Bedarf deaktivieren, zusätzliche Statusressourcen (z. B. `notbetrieb`, BLF `9002`) hinzufügen und aktuelle Zustände im Webinterface überprüfen.

**Wichtig:** Der Template-Download ist personalisiert und enthält das SIP-Passwort für Account 2. **Nicht auf öffentliches GitHub hochladen**, nicht unverschlüsselt versenden.

## 3CX-Vorlage für Steuerungs-Telefone

Die beigefügte Originalvorlage `templates/source-yealinkT4x.ph.xml` stammt aus der bereitgestellten 3CX-Konfiguration. Die Admin-Oberfläche erzeugt daraus eine personalisierte Version mit:

- unverändertem Account 1 (3CX)
- einem für dieses Telefon individuellen Account 2 mit SIP-Domain aus `SIP_HOST` und Port 5062
- **physischer Taste 1**: `linekey.1.type=16`, `linekey.1.line=2`, `linekey.1.value=9001`, Label `Spontanschaltung`
- **Tasten 2 ff.**: unveränderte 3CX-DSS-Belegungen
- eigenem Vorlagennamen und abgewandelten Yealink-y-Dateinamen (`y100...`) gegenüber der Standardvorlage

Die Tastenerweiterung greift derzeit auf die in der hochgeladenen Vorlage zusammengefasste Modellgruppe `SIP-T44U`, `SIP-T44W`, `SIP-T46S`, `SIP-T46U`, `SIP-T54W`. Für andere Modelle wird aktuell **keine** Status-Taste reserviert – Anpassung vor dem produktiven Einsatz erforderlich.

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
