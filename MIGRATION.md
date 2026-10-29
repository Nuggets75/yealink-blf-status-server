# Kurz-Anleitung: bestehender Dockhand-Stack → Multi-Tenant

1. Backup des bestehenden `asterisk-state`-Volumes. Stack nicht verdoppeln.
2. ZIP nach GitHub (Root des bestehenden Repositories) hochladen.
3. In Dockhand den Inhalt von `docker-compose.remote.yml` verwenden (mit deinem GitHub-Benutzernamen), neue Variablen `ADMIN_PASSWORD`, `SIP_HOST`, `API_BIND_IP` ergänzen. Bisherige `SIP_PASSWORD`, `API_TOKEN` **nicht entfernen**, wenn `status01` übernommen werden soll.
4. Docker Image **rebuild**, Container deployen.
5. Nginx Proxy Manager wie bisher für `https://blf-api.<deine-domain>` → `http://<docker-host-privat>:8787` konfigurieren. Kein direktes öffentliches 8787.
6. `https://blf-api.<deine-domain>/admin` öffnen und anmelden.
7. Kunden anlegen → API-Key einmalig kopieren → Telefon anlegen → individuelle 3CX-XML-Vorlage herunterladen. XML niemals öffentlich committen.
8. Status mit Curl schalten und danach mit einem CFD `HTTP Request` bei der Änderung des globalen 3CX-Parameters senden.

WICHTIG: Status-BLF ist **Taste 1**, unabhängig von der Callflow-Taste. Taste 2+ bleiben reguläre 3CX-Tasten. Der Asterisk-Server kontaktiert 3CX niemals direkt.
