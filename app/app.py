#!/usr/bin/env python3
"""Multi-tenant SIP BLF status API and minimal secure administration UI.
Only outbound interaction is local Asterisk CLI; no 3CX connectivity needed.
Stdlib-only for deterministic Docker builds.
"""
import base64
import contextlib
import hashlib
import hmac
import html
import http.cookies
import http.server
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit
from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger('blf')
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
STATE_DIR = Path(os.getenv('BLF_STATE_DIR', '/var/lib/asterisk/blf'))
DB_PATH = STATE_DIR / 'state.sqlite3'
PJSIP_PATH = STATE_DIR / 'pjsip.conf'
EXT_PATH = STATE_DIR / 'extensions.conf'
SOURCE_TEMPLATE = Path('/opt/blf/templates/source-yealinkT4x.ph.xml')
SIP_PORT = int(os.getenv('SIP_PORT', '5062'))
API_PORT = int(os.getenv('API_PORT', '8787'))
API_BIND_IP = os.getenv('API_BIND_IP', '127.0.0.1')
SIP_PUBLIC_IP = os.getenv('SIP_PUBLIC_IP', '')
SIP_LOCAL_NET = os.getenv('SIP_LOCAL_NET', '')
SIP_HOST = os.getenv('SIP_HOST', 'blf.example.de')
DB_LOCK = threading.RLock()
LOGIN_FAILURES = {}
REVEAL_FAILURES = {}
API_ATTEMPTS = {}


@contextlib.contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=10000')
    c.execute('PRAGMA foreign_keys=ON')
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def pw_hash(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    return 'pbkdf2_sha256$350000$' + salt.hex() + '$' + hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 350000).hex()


def pw_verify(pw, encoded):
    try:
        _, iters, salt, digest = encoded.split('$')
        test = hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(test, bytes.fromhex(digest))
    except (ValueError, AttributeError):
        return False


def sha(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def fresh_key():
    return 'blf_' + secrets.token_urlsafe(36)


def ensure_encryption_key(db):
    """Persistent application secret: never replace if encrypted API keys exist."""
    key_path = STATE_DIR / '.api-key-fernet.key'
    if not key_path.exists():
        encrypted = db.execute('SELECT 1 FROM api_keys WHERE token_ciphertext IS NOT NULL LIMIT 1').fetchone()
        if encrypted:
            raise RuntimeError('API-Schluessel-Datei fehlt. Backup der .api-key-fernet.key wiederherstellen!')
        new_key = Fernet.generate_key()
        try:
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as out:
                out.write(new_key)
        except FileExistsError:
            pass
    os.chmod(key_path, 0o600)
    try:
        return Fernet(key_path.read_bytes())
    except (ValueError, TypeError) as ex:
        raise RuntimeError('Ungueltiger API-Key-Verschluesselungsschluessel; Backup pruefen') from ex


def encrypt_api_key(token):
    return Fernet((STATE_DIR / '.api-key-fernet.key').read_bytes()).encrypt(token.encode('utf-8')).decode('ascii')


def decrypt_api_key(ciphertext):
    if not ciphertext:
        return None
    try:
        return Fernet((STATE_DIR / '.api-key-fernet.key').read_bytes()).decrypt(ciphertext.encode('ascii')).decode('utf-8')
    except (InvalidToken, OSError, ValueError) as ex:
        raise RuntimeError('API-Schluessel nicht entschluesselbar. Verschluesselungsdatei/Backup kontrollieren.') from ex


def db_init():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    admin_pw = os.environ.get('ADMIN_PASSWORD', '')
    if not DB_PATH.exists() and len(admin_pw) < 20:
        raise SystemExit('ADMIN_PASSWORD muss zur Initialisierung mindestens 20 Zeichen haben')
    with DB_LOCK, conn() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS tenants (
          id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS status_items (
          id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id),
          slug TEXT NOT NULL, extension INTEGER NOT NULL, value INTEGER NOT NULL DEFAULT 0,
          changed_at INTEGER NOT NULL, UNIQUE(tenant_id,slug), UNIQUE(tenant_id,extension));
        CREATE TABLE IF NOT EXISTS phones (
          id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id),
          label TEXT NOT NULL, sip_user TEXT NOT NULL UNIQUE,
          sip_password TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS api_keys (
          tenant_id INTEGER PRIMARY KEY REFERENCES tenants(id), token_hash TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, tenant_id INTEGER,
          actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
        ''')
        # Schema migration is additive: existing customers, phones and key hashes are retained.
        columns = {row['name'] for row in db.execute('PRAGMA table_info(api_keys)')}
        if 'token_ciphertext' not in columns:
            db.execute('ALTER TABLE api_keys ADD COLUMN token_ciphertext TEXT')
        ensure_encryption_key(db)
        db.execute('PRAGMA journal_mode=WAL')
        if not db.execute("SELECT 1 FROM settings WHERE key='admin_hash'").fetchone():
            db.execute('INSERT INTO settings VALUES (?,?)', ('admin_hash', pw_hash(admin_pw)))
        # One-time migration sentinel. Without it, deleting the last customer
        # would recreate the old test tenant on the next restart if legacy
        # SIP_PASSWORD/API_TOKEN environment variables were still set.
        legacy_done = db.execute("SELECT value FROM settings WHERE key='legacy_import_processed'").fetchone()
        if not legacy_done and not db.execute('SELECT 1 FROM tenants').fetchone():
            legacy_sip = os.getenv('SIP_PASSWORD', '')
            legacy_api = os.getenv('API_TOKEN', '')
            if legacy_sip and legacy_api:
                now = int(time.time())
                tenant_id = db.execute('INSERT INTO tenants(slug,name,created_at) VALUES(?,?,?)',
                                       ('testanlage', 'Testanlage (übernommen)', now)).lastrowid
                db.execute('INSERT INTO status_items(tenant_id,slug,extension,value,changed_at) VALUES(?,?,?,?,?)',
                           (tenant_id, 'spontanschaltung', 9001, 0, now))
                db.execute('INSERT INTO phones(tenant_id,label,sip_user,sip_password,created_at) VALUES(?,?,?,?,?)',
                           (tenant_id, 'Bisheriges Testtelefon', 'status01', legacy_sip, now))
                db.execute('INSERT INTO api_keys(tenant_id,token_hash,token_ciphertext) VALUES(?,?,?)',
                           (tenant_id, sha(legacy_api), encrypt_api_key(legacy_api)))
                log.info('Bisheriges status01 SIP-Konto als Testanlage übernommen')
        if not legacy_done:
            db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('legacy_import_processed','1')")
        # Previous test installations may still have the legacy API_TOKEN in Dockhand.
        # Recover only this *known* secret; arbitrary SHA-256 hashes are not reversible.
        legacy_api = os.getenv('API_TOKEN', '')
        if legacy_api:
            db.execute('UPDATE api_keys SET token_ciphertext=? WHERE token_hash=? AND token_ciphertext IS NULL',
                       (encrypt_api_key(legacy_api), sha(legacy_api)))
        db.commit()
    os.chmod(DB_PATH, 0o600)


def atomic_text(path, content):
    with tempfile.NamedTemporaryFile('w', dir=path.parent, prefix='._', delete=False, encoding='utf-8') as f:
        f.write(content)
        tmp = Path(f.name)
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def generate_configs():
    """All interpolated strings are server-created or strictly validated."""
    with DB_LOCK, conn() as db:
        tenants = db.execute('SELECT id FROM tenants WHERE active=1 ORDER BY id').fetchall()
        phones = db.execute('SELECT p.*,t.id AS tid FROM phones p JOIN tenants t ON p.tenant_id=t.id WHERE p.active=1 AND t.active=1 ORDER BY p.id').fetchall()
        statuses = db.execute('SELECT s.*,t.id AS tid FROM status_items s JOIN tenants t ON s.tenant_id=t.id WHERE t.active=1 ORDER BY s.tenant_id,s.extension').fetchall()
    sip = ['; Generated by BLF Manager; DO NOT EDIT', '[global]', 'type=global', 'user_agent=Yealink-BLF-MultiTenant', '', '[transport-blf]', 'type=transport', 'protocol=udp', f'bind=0.0.0.0:{SIP_PORT}']
    if SIP_PUBLIC_IP:
        sip += [f'external_signaling_address={SIP_PUBLIC_IP}', f'external_signaling_port={SIP_PORT}']
    if SIP_LOCAL_NET:
        sip.append(f'local_net={SIP_LOCAL_NET}')
    for p in phones:
        name = p['sip_user']
        tid = p['tid']
        sip += ['', f'[{name}]', 'type=endpoint', 'transport=transport-blf', f'context=blf_t{tid}', f'subscribe_context=blf_t{tid}',
                'disallow=all', 'allow=alaw,ulaw', f'auth=auth-{name}', f'aors={name}',
                'allow_subscribe=yes', 'rewrite_contact=yes', 'force_rport=yes', 'rtp_symmetric=yes', 'direct_media=no',
                '', f'[auth-{name}]', 'type=auth', 'auth_type=userpass', f'username={name}', f'password={p["sip_password"]}',
                '', f'[{name}]', 'type=aor', 'max_contacts=1', 'remove_existing=yes', 'qualify_frequency=60']
    ext = ['; Generated by BLF Manager; DO NOT EDIT', '[general]', 'static=yes', 'writeprotect=yes', '']
    for t in tenants:
        tid = t['id']
        ext += [f'[blf_t{tid}]']
        for s in statuses:
            if s['tid'] == tid:
                ext += [f'exten => {s["extension"]},hint,Custom:blf_t{tid}_{s["slug"]}',
                        f'exten => {s["extension"]},1,Hangup()']
        ext += ['exten => _X.,1,Hangup()', '']
    atomic_text(PJSIP_PATH, '\n'.join(sip) + '\n')
    atomic_text(EXT_PATH, '\n'.join(ext) + '\n')


def ast(command, timeout=7):
    try:
        result = subprocess.run(['/usr/sbin/asterisk', '-rx', command], capture_output=True, text=True, timeout=timeout)
        if result.returncode or 'No such command' in result.stdout or 'Unable to connect' in result.stderr:
            log.error('Asterisk command failed: %s rc=%s', command.split(' ')[0], result.returncode)
            return False
        return True
    except (OSError, subprocess.TimeoutExpired):
        log.exception('Asterisk CLI not available')
        return False


def reload_asterisk():
    generate_configs()
    return ast('dialplan reload') and ast('pjsip reload')


def apply_status(db, tenant_id, status_slug, value, actor):
    with DB_LOCK:
        s = db.execute('SELECT s.*,t.active FROM status_items s JOIN tenants t ON s.tenant_id=t.id WHERE s.tenant_id=? AND s.slug=?', (tenant_id,status_slug)).fetchone()
        if not s or not s['active']:
            return None
        state = 'BUSY' if value == 1 else 'NOT_INUSE'
        if not ast(f'devstate change Custom:blf_t{tenant_id}_{status_slug} {state}'):
            raise RuntimeError('Asterisk nicht erreichbar')
        db.execute('UPDATE status_items SET value=?,changed_at=? WHERE id=?', (value,int(time.time()),s['id']))
        db.execute('INSERT INTO audit(ts,tenant_id,actor,action,detail) VALUES(?,?,?,?,?)',
                   (int(time.time()),tenant_id,actor,'status',f'{status_slug}={value}'))
        db.commit()
        return state


def sync_states():
    with DB_LOCK, conn() as db:
        rows = db.execute('SELECT s.tenant_id,s.slug,s.value FROM status_items s JOIN tenants t ON s.tenant_id=t.id WHERE t.active=1').fetchall()
        for item in rows:
            ast(f'devstate change Custom:blf_t{item["tenant_id"]}_{item["slug"]} {"BUSY" if item["value"] else "NOT_INUSE"}')


def e(value):
    return html.escape(str(value), quote=True)


CSS = '''
:root{color-scheme:light;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;color:#17233b;background:#f3f6fa}
*{box-sizing:border-box}body{margin:0}header{background:#142339;color:#fff;padding:18px max(22px,calc((100vw - 1150px)/2));display:flex;justify-content:space-between;align-items:center;gap:16px}header b{font-size:19px}
main{max-width:1150px;margin:30px auto;padding:0 20px 50px}.row{display:flex;gap:14px;align-items:center;flex-wrap:wrap}.spread{justify-content:space-between}.card{background:#fff;border:1px solid #dfe6ef;border-radius:14px;padding:22px;margin:16px 0;box-shadow:0 4px 16px #152c4208}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:16px}.grid .card{margin:0}h1{font-size:28px;margin:0 0 8px}h2{font-size:19px;margin:0 0 16px}h3{font-size:15px;margin:0 0 8px}p{line-height:1.5}label{font-size:13px;font-weight:650;display:block;margin:10px 0 5px}input,select{display:block;width:100%;padding:10px 12px;border-radius:9px;border:1px solid #bdcbdc;background:#fff;font:inherit}button,.button{display:inline-block;border:0;border-radius:9px;background:#1768bc;color:white;padding:10px 14px;font-size:14px;font-weight:650;text-decoration:none;cursor:pointer}button.secondary,.button.secondary{background:#e8edf5;color:#20364f}button.warn{background:#ba3d3d}form.inline{display:inline}form.inline button{padding:7px 10px;font-size:13px}small,.muted{color:#697b91}table{width:100%;border-collapse:collapse}td,th{padding:10px 8px;text-align:left;border-bottom:1px solid #eef1f5;font-size:14px}th{font-size:12px;color:#607086;text-transform:uppercase}.pill{border-radius:99px;padding:5px 9px;font-size:12px;font-weight:700;background:#f9e8e6;color:#963f33}.pill.off{background:#e7f5ec;color:#217543}.secret{word-break:break-all;background:#f1f5fb;border:1px solid #d3dfeb;border-radius:9px;padding:13px;font-family:monospace;font-size:13px}.error{background:#fff0ef;border:1px solid #efb4b0;padding:12px;border-radius:8px;color:#932d2d}.ok{background:#eaf8ed;border:1px solid #c4e8c9;padding:12px;border-radius:8px}.sub{font-size:14px;color:#687a8d;margin:0 0 14px}.w400{max-width:450px}.right{text-align:right}a{color:#1b65a8}header a,header button{color:#fff;background:transparent;text-decoration:none;font-weight:600}pre{white-space:pre-wrap;word-break:break-all}summary{cursor:pointer;font-weight:650}
'''


def page(title, content, top='', minimal=False):
    nav = '<header><b>◉ BLF Control Center</b>' + (f'<span class="row"><a href="/admin">Kunden</a><a href="/admin/password">Passwort ändern</a><form class="inline" method="post" action="/admin/logout">{top}<button>Abmelden</button></form></span>' if not minimal else '') + '</header>'
    return '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + e(title) + ' – BLF Control</title><style>' + CSS + '</style></head><body>' + nav + '<main>' + content + '</main></body></html>'


def csrf_field(session):
    return '<input type="hidden" name="csrf" value="' + e(session['csrf']) + '">'


def tenant_panel(db, tenant, session, token=None, notice=''):
    tid = tenant['id']
    stat = db.execute('SELECT * FROM status_items WHERE tenant_id=? ORDER BY extension', (tid,)).fetchall()
    phones = db.execute('SELECT * FROM phones WHERE tenant_id=? ORDER BY id', (tid,)).fetchall()
    csrf = csrf_field(session)
    key_row = db.execute('SELECT token_ciphertext FROM api_keys WHERE tenant_id=?', (tid,)).fetchone()
    key_recoverable = bool(key_row and key_row['token_ciphertext'])
    msg = f'<div class="ok">{e(notice)}</div>' if notice else ''
    if token:
        msg += '<div class="ok"><b>API-Schlüssel (nach Passwortprüfung erneut abrufbar):</b><div class="secret">' + e(token) + '</div></div>'
    out = f'<p><a href="/admin">← Alle Kunden</a></p><h1>{e(tenant["name"])}</h1><p class="sub">Kennung: {e(tenant["slug"])} · ID: {tid} · {"Aktiv" if tenant["active"] else "Deaktiviert"}</p>' + msg
    out += f'<div class="grid"><section class="card"><h2>Schnittstelle (3CX CFD)</h2><p class="sub">URL ist für alle Anlagen gleich; der API-Schlüssel bestimmt den Kunden.</p><code>POST /v1/status/spontanschaltung</code><p><code>X-API-Key: &lt;Kundenschlüssel&gt;</code></p><p><code>{{"value":1}}</code> oder <code>{{"value":0}}</code></p>'
    if key_recoverable:
        out += (f'<details><summary>API-Schlüssel anzeigen (Admin-Passwort erforderlich)</summary>'
                f'<form method="post" action="/admin/tenants/{tid}/reveal">{csrf}'
                '<label>Admin-Passwort</label><input type="password" name="password" autocomplete="current-password" required>'
                '<p><button type="submit">Schlüssel anzeigen</button></p></form></details>')
    else:
        out += '<p class="muted">Bestehender Schlüssel nur als Hash gespeichert: nicht wiederherstellbar. Zum Anzeigen bitte einmalig einen neuen Schlüssel erzeugen.</p>'
    out += f'<p><form method="post" action="/admin/tenants/{tid}/rotate">{csrf}<button class="secondary">API-Schlüssel neu erzeugen</button></form></p><p class="muted"><small>Achtung: Der alte Schlüssel wird dabei sofort ungültig.</small></p></section>'

    out += f'<section class="card"><h2>Administration</h2><form method="post" action="/admin/tenants/{tid}/active">{csrf}<button class="{ "warn" if tenant["active"] else "secondary" }">{ "Kunde deaktivieren" if tenant["active"] else "Kunde aktivieren" }</button></form><p class="sub">Deaktivierung sperrt API-Zugriff und entfernt SIP-Konten aus der aktiven Konfiguration.</p>'
    out += (f'<details style="margin-top:18px"><summary>Kunde dauerhaft löschen</summary>'
            f'<p class="sub"><strong>Unwiderruflich:</strong> {len(phones)} Telefon(e), {len(stat)} Statuswert(e), alle API-Schlüssel und zugehörige Ereignisse werden entfernt. '
            'Nach dem Löschen funktionieren bisherige CFD-Schlüssel und SIP-Konten nicht mehr. Bestehende Telefonvorlagen müssen bei 3CX separat entfernt werden.</p>'
            f'<form method="post" action="/admin/tenants/{tid}/delete">{csrf}'
            f'<label>Zur Bestätigung die Kundenkennung <code>{e(tenant["slug"])}</code> eingeben</label>'
            '<input name="confirm" required autocomplete="off" spellcheck="false">'
            '<label>Admin-Passwort erneut eingeben</label>'
            '<input type="password" name="password" autocomplete="current-password" required>'
            '<p><button class="warn" type="submit">Kunde und alle Daten unwiderruflich löschen</button></p>'
            '</form></details></section></div>')
    out += '<section class="card"><h2>Statusanzeigen</h2><table><tr><th>Name</th><th>BLF-Nummer</th><th>Zustand</th><th>Aktion</th></tr>'
    for s in stat:
        if s['value']:
            new_val, label = 0, 'Auf AUS setzen'
        else:
            new_val, label = 1, 'Auf EIN setzen'
        out += f'<tr><td>{e(s["slug"])}</td><td>{s["extension"]}</td><td><span class="pill {"" if s["value"] else "off"}">{"EIN / BUSY" if s["value"] else "AUS / IDLE"}</span></td><td><form class="inline" method="post" action="/admin/tenants/{tid}/set">{csrf}<input type="hidden" name="slug" value="{e(s["slug"])}"><input type="hidden" name="value" value="{new_val}"><button class="secondary">{label}</button></form></td></tr>'
    out += f'</table><details style="margin-top:18px"><summary>Status hinzufügen (max. 3 empfohlen)</summary><form method="post" action="/admin/tenants/{tid}/status">{csrf}<label>Interne Bezeichnung (a-z, 0-9, -)</label><input name="slug" required pattern="[a-z][a-z0-9-]{{1,30}}" placeholder="notbetrieb"><label>BLF-Nebenstelle</label><input type="number" name="extension" required min="100" max="99999" placeholder="9002"><p><button>Status anlegen</button></p></form></details></section>'
    out += '<section class="card"><h2>Telefone</h2><p class="sub">Jedes Telefon erhält individuelle SIP-Zugangsdaten. Der Export enthält diese vertraulichen Werte und muss geschützt behandelt werden.</p><table><tr><th>Bezeichnung</th><th>SIP-Konto</th><th>3CX-Telefonvorlage</th><th>Aktiv</th><th>Verwalten</th></tr>'
    for p in phones:
        out += f'<tr><td>{e(p["label"])}</td><td><code>{e(p["sip_user"])}</code></td><td><a href="/admin/phones/{p["id"]}/template">XML herunterladen</a> · <a href="/admin/phones/{p["id"]}/settings">SIP-Daten</a></td><td><form class="inline" method="post" action="/admin/phones/{p["id"]}/active">{csrf}<button class="secondary">{"Deaktivieren" if p["active"] else "Aktivieren"}</button></form></td><td><a href="/admin/phones/{p["id"]}/settings">Verwalten / löschen</a></td></tr>'
    out += f'</table><form method="post" action="/admin/tenants/{tid}/phone">{csrf}<label>Telefonbezeichnung</label><input name="label" maxlength="80" required placeholder="Empfang T54W"><p><button>Telefon anlegen</button></p></form></section>'
    out += '<p class="muted">3CX-Kontakt: Der Server verbindet sich niemals mit einer 3CX-Anlage. Ausschließlich CFD → HTTPS-API und Telefon → SIP sind erforderlich.</p>'
    return page(tenant['name'], out, csrf)


def build_template(phone, tenant, sip_host, sip_port):
    """Per-customer 3CX template. Sensitive output, admin-authenticated only."""
    original = SOURCE_TEMPLATE.read_text('utf-8')
    # Keep the untouched 3CX key mappings for every model except the selected
    # control phones. Modify precisely the first key of the matching model group.
    # Yealink T40G/T42G/T48G share key groups with other models: nested IF
    # branches preserve the stock behavior for those other models.
    status_key = ("# NEXPERTO: Taste 1 / zentraler Statusserver (kein Callflow)\n"
                  "linekey.1.line = 2\n"
                  "linekey.1.value = 9001\n"
                  "linekey.1.type = 16\n"
                  "linekey.1.pickup_value =\n"
                  "linekey.1.extension =\n"
                  "linekey.1.label = Spontanschaltung\n")
    groups = (
        ('{IF ua=SIP-T44U,SIP-T44W,SIP-T46G,SIP-T46S,SIP-T46U,SIP-T54W}', None),
        ('{IF ua=SIP-T23P,SIP-T23G,SIP-T40G,SIP-T40P}', 'SIP-T40G'),
        ('{IF ua=SIP-T41S,SIP-T42G,SIP-T42S,SIP-T41U,SIP-T42U}', 'SIP-T42G'),
        ('{IF ua=SIP-T48G,SIP-T48S,SIP-T57W,SIP-T48U}', 'SIP-T48G'),
    )
    for marker, only_model in groups:
        head, sep, tail = original.partition(marker)
        if not sep:
            raise RuntimeError('Telefonvorlagenblock nicht gefunden: ' + marker)
        start = tail.find('#Configure Line Key1')
        end = tail.find('#Configure Line Key2')
        group_end = tail.find('{ENDIF}')
        if start < 0 or end < 0 or end <= start or group_end < start:
            raise RuntimeError('Linekey-Tastendefinition nicht gefunden: ' + marker)
        previous = tail[start:end]
        if only_model:
            replacement = (f'{{IF ua={only_model}}}\n' + status_key
                           + '{ELSE}\n' + previous + '{ENDIF}\n')
        else:
            replacement = status_key
        tail = tail[:start] + replacement + tail[end:]
        original = head + marker + tail
    # Account.2 is defined only once in the MAC-specific config CDATA.
    marker = groups[0][0]
    # Per-phone account.2 config is placed in MAC-specific config CDATA, before the
    # linekey branch. 3CX account.1 settings are untouched.
    snippet = ('\n# NEXPERTO: BLF-SIP-Konto 2 / eigener Kunde. Nicht in GitHub speichern.\n'
               'account.2.enable = 1\n'
               f'account.2.label = BLF {tenant["slug"]}\n'
               f'account.2.display_name = BLF {tenant["slug"]}\n'
               f'account.2.user_name = {phone["sip_user"]}\n'
               f'account.2.auth_name = {phone["sip_user"]}\n'
               f'account.2.password = {phone["sip_password"]}\n'
               'account.2.sip_server.1.transport_type = 0\n'
               f'account.2.sip_server.1.address = {sip_host}\n'
               f'account.2.sip_server.1.port = {sip_port}\n'
               'account.2.sip_server.1.expires = 300\n'
               'account.2.sip_server.1.register_on_enable = 1\n'
               'account.2.sip_server.1.failback_mode = 0\n'
               'account.2.outbound_proxy_enable = 0\n'
               '\n')
    loc = original.find(marker)
    original = original[:loc] + snippet + original[loc:]
    # Distinct template name for different customers, no model UA change.
    original = original.replace('<name>Yealink T4X</name>',
                                f'<name>Yealink T4X BLF {tenant["slug"]}</name>', 1)
    original = original.replace('<description>Yealink T4X SIP Phone</description>',
                                '<description>Yealink T4X BLF Steuerung</description>', 1)
    # Standard-y-File-Namen nicht mit der 3CX-Vorlage kollidieren lassen.
    # Falls schon eine eigene Vorlage die y100...-Namen verwendet: manuell anpassen.
    original = original.replace('y000000000', 'y100000000')
    # 3CX erwartet im Header und im ersten CDATA/<filename>-Block identische Modellnamen.
    model_suffix = ' [BLF ' + tenant['slug'] + ']'
    original, n_model = re.subn(r'(<model\s+ua=\"[^\"]+\"[^>]*>)(Yealink [^<]+)(</model>)',
                                 lambda m: m.group(1) + m.group(2) + model_suffix + m.group(3), original)
    original, n_names = re.subn(r'(<model name=\")(Yealink [^\"]+)(\" filename=)',
                                 lambda m: m.group(1) + m.group(2) + model_suffix + m.group(3), original)
    if n_model == 0 or n_model != n_names:
        raise RuntimeError('3CX-Modellnamen in Vorlage stimmen nicht überein')
    return original


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'BLFControl/1'
    sys_version = ''
    protocol_version = 'HTTP/1.0'
    timeout = 10

    def log_message(self, fmt, *args):
        # Avoid leaking any tokens or user-provided query into logs.
        log.info('%s %s', self.client_address[0], fmt % args)

    def output(self, status, body, mime='text/html; charset=utf-8', headers=None):
        if isinstance(body, str): body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if headers:
            for key, value in headers.items(): self.send_header(key, value)
        self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass

    def json_out(self, code, payload):
        self.output(code, json.dumps(payload, separators=(',', ':')), 'application/json; charset=utf-8')

    def redirect(self, path, headers=None):
        self.output(303, '', headers={'Location':path, **(headers or {})})

    def parse_body(self, max_size=4096):
        if self.headers.get('Transfer-Encoding'): raise ValueError('chunked nicht erlaubt')
        sizes = self.headers.get_all('Content-Length', [])
        if len(sizes) != 1 or not sizes[0].isdigit(): raise ValueError('Content-Length fehlt')
        size = int(sizes[0]);
        if size < 1 or size > max_size: raise ValueError('Ungültige Body-Größe')
        return self.rfile.read(size)

    def form(self):
        if self.headers.get('Content-Type', '').split(';')[0].lower() != 'application/x-www-form-urlencoded':
            raise ValueError('Formulardaten erwartet')
        return {key: val[0] for key, val in parse_qs(self.parse_body().decode('utf-8'), keep_blank_values=True, max_num_fields=20).items()}

    def session(self):
        cookie = http.cookies.SimpleCookie()
        try: cookie.load(self.headers.get('Cookie',''))
        except http.cookies.CookieError: return None
        raw = cookie.get('__Host-blf_session')
        if not raw: return None
        token = raw.value
        if not re.fullmatch('[A-Za-z0-9_-]{30,120}', token): return None
        with conn() as db:
            return db.execute('SELECT csrf,expires_at FROM sessions WHERE token_hash=? AND expires_at>?',
                              (sha(token), int(time.time()))).fetchone()

    def require_admin(self):
        session = self.session()
        if session is None:
            self.redirect('/admin/login')
        return session

    def admin_form(self):
        s = self.require_admin()
        if s is None: return None,None
        try: f = self.form()
        except (ValueError,UnicodeError) as ex:
            self.error(400, str(ex)); return None,None
        if not hmac.compare_digest(f.get('csrf',''), s['csrf']):
            self.error(403,'Ungültiger CSRF-Schutz');return None,None
        return s,f

    def error(self, code, msg):
        self.output(code, page('Fehler', f'<div class="error">{e(msg)}</div><p><a href="/admin">Zurück</a></p>'))

    def do_GET(self):
        path=urlsplit(self.path).path
        if path == '/healthz':
            self.json_out(200, {'ok':True}); return
        if path == '/admin/login':
            form = '<div class="card w400"><h1>Admin-Anmeldung</h1><p class="sub">BLF Control Center</p><form method="post" action="/admin/login"><label>Admin-Passwort</label><input type="password" name="password" autocomplete="current-password" required><p><button>Anmelden</button></p></form></div>'
            self.output(200,page('Anmeldung',form,minimal=True)); return
        if path == '/': self.redirect('/admin');return
        if path.startswith('/v1/'):
            self.json_out(404,{'error':'not_found'});return
        session=self.require_admin()
        if session is None: return
        with conn() as db:
            if path=='/admin':
                ts=db.execute('SELECT t.*, (SELECT COUNT(*) FROM phones p WHERE p.tenant_id=t.id) AS phones, (SELECT COUNT(*) FROM status_items s WHERE s.tenant_id=t.id) AS statuses FROM tenants t ORDER BY name').fetchall()
                cards=''.join(f'<section class="card"><h2><a href="/admin/tenants/{t["id"]}">{e(t["name"])}</a></h2><p class="sub">{e(t["slug"])} · {t["phones"]} Telefon(e) · {t["statuses"]} Statuswert(e)</p><span class="pill {"" if t["active"] else "off"}">{"Aktiv" if t["active"] else "Gesperrt"}</span></section>' for t in ts)
                out=f'<div class="row spread"><div><h1>Kundenverwaltung</h1><p class="sub">{len(ts)} Kunden angelegt · zentraler BLF-Server</p></div></div><div class="grid">{cards or "<p>Noch keine Kunden vorhanden.</p>"}</div>'
                out+=f'<section class="card w400"><h2>Neuen Kunden anlegen</h2><form method="post" action="/admin/tenants">{csrf_field(session)}<label>Kundenname</label><input name="name" maxlength="80" required placeholder="Beispiel GmbH"><label>Kennung</label><input name="slug" maxlength="32" required pattern="[a-z][a-z0-9-]{{1,30}}" placeholder="beispiel-gmbh"><p><button>Kunden anlegen</button></p></form></section>'
                self.output(200,page('Kunden',out,csrf_field(session)));return
            if path=='/admin/password':
                out=f'<div class="card w400"><h1>Admin-Passwort ändern</h1><form method="post" action="/admin/password">{csrf_field(session)}<label>Altes Passwort</label><input type="password" name="old" required><label>Neues Passwort (mind. 20 Zeichen)</label><input type="password" name="new" minlength="20" required><p><button>Passwort ändern</button></p></form></div>'
                self.output(200,page('Passwort',out,csrf_field(session)));return
            m=re.fullmatch(r'/admin/tenants/(\d+)',path)
            if m:
                t=db.execute('SELECT * FROM tenants WHERE id=?',(int(m.group(1)),)).fetchone()
                if not t: self.error(404,'Kunde nicht gefunden');return
                self.output(200,tenant_panel(db,t,session));return
            m=re.fullmatch(r'/admin/phones/(\d+)/(template|settings)',path)
            if m:
                p=db.execute('SELECT * FROM phones WHERE id=?',(int(m.group(1)),)).fetchone()
                if not p: self.error(404,'Telefon nicht gefunden');return
                t=db.execute('SELECT * FROM tenants WHERE id=?',(p['tenant_id'],)).fetchone()
                if m.group(2)=='template':
                    try: content=build_template(p,t,SIP_HOST,SIP_PORT)
                    except (OSError,RuntimeError) as ex: self.error(500,str(ex));return
                    self.output(200,content,'application/xml; charset=utf-8',{'Content-Disposition':f'attachment; filename="blf-{t["slug"]}-{p["id"]}.xml"'});return
                out=f'<p><a href="/admin/tenants/{t["id"]}">← Kunde</a></p><h1>{e(p["label"])}</h1><div class="card"><h2>SIP-Konto 2</h2><p>Server: <code>{e(SIP_HOST)}:{SIP_PORT}/UDP</code></p><p>Benutzer / Auth-Name: <code>{e(p["sip_user"])}</code></p><p>Passwort:</p><div class="secret">{e(p["sip_password"])}</div><p><a class="button" href="/admin/phones/{p["id"]}/template">Kundenspezifische 3CX-XML laden</a></p><p class="muted">Vertraulich: XML enthält SIP-Zugangsdaten und gehört nicht ins öffentliche GitHub.</p></div>'
                out += (f'<div class="card"><details><summary>Telefon dauerhaft löschen</summary>'
                        '<p class="sub">Das SIP-Konto wird aus der aktiven Asterisk-Konfiguration entfernt. Ein Export dieser XML wird anschließend nicht mehr möglich sein.</p>'
                        f'<form method="post" action="/admin/phones/{p["id"]}/delete">{csrf_field(session)}'
                        f'<label>Zur Bestätigung exakt <code>{e(p["sip_user"])}</code> eingeben</label>'
                        '<input name="confirm" required autocomplete="off" placeholder="SIP-Benutzer eingeben">'
                        '<p><button class="warn" type="submit">Telefon unwiderruflich löschen</button></p>'
                        '</form></details></div>')

                self.output(200,page('Telefon',out,csrf_field(session)));return
        self.error(404,'Seite nicht gefunden')

    def do_POST(self):
        path=urlsplit(self.path).path
        if path.startswith('/v1/'):
            self.handle_api(path);return
        if path=='/admin/login':
            self.handle_login();return
        session, f=self.admin_form()
        if session is None: return
        with DB_LOCK, conn() as db:
            if path=='/admin/logout':
                # session hash by cookie; invalidate all sessions on logout (single admin)
                db.execute('DELETE FROM sessions'); db.commit()
                self.redirect('/admin/login',{'Set-Cookie':'__Host-blf_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict'});return
            if path=='/admin/password':
                stored=db.execute("SELECT value FROM settings WHERE key='admin_hash'").fetchone()['value']
                if not pw_verify(f.get('old',''),stored) or len(f.get('new',''))<20:
                    self.error(400,'Altes Passwort falsch oder neues zu kurz');return
                db.execute("UPDATE settings SET value=? WHERE key='admin_hash'",(pw_hash(f['new']),))
                db.execute('DELETE FROM sessions');db.commit()
                self.redirect('/admin/login',{'Set-Cookie':'__Host-blf_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict'});return
            if path=='/admin/tenants':
                slug=f.get('slug','').strip().lower(); name=f.get('name','').strip()
                if not re.fullmatch('[a-z][a-z0-9-]{1,30}',slug) or not 1<=len(name)<=80:
                    self.error(400,'Ungültiger Kundenname oder Kennung');return
                try:
                    now=int(time.time()); token=fresh_key()
                    tid=db.execute('INSERT INTO tenants(slug,name,created_at) VALUES(?,?,?)',(slug,name,now)).lastrowid
                    db.execute('INSERT INTO status_items(tenant_id,slug,extension,value,changed_at) VALUES(?,?,?,?,?)',(tid,'spontanschaltung',9001,0,now))
                    db.execute('INSERT INTO api_keys(tenant_id,token_hash,token_ciphertext) VALUES(?,?,?)',(tid,sha(token),encrypt_api_key(token)))
                    db.commit()
                except sqlite3.IntegrityError:
                    self.error(409,'Kundenkennung existiert bereits');return
                if not reload_asterisk():
                    self.error(503,'Kunde gespeichert, Asterisk Reload fehlgeschlagen. Bitte Logs kontrollieren.');return
                t=db.execute('SELECT * FROM tenants WHERE id=?',(tid,)).fetchone()
                self.output(200,tenant_panel(db,t,session,token,'Kunde angelegt.'));return
            m=re.fullmatch(r'/admin/tenants/(\d+)/(rotate|reveal|active|phone|status|set|delete)',path)
            if m:
                tid=int(m.group(1)); action=m.group(2)
                t=db.execute('SELECT * FROM tenants WHERE id=?',(tid,)).fetchone()
                if not t: self.error(404,'Kunde nicht vorhanden');return
                if action=='delete':
                    # Deliberately require CSRF (admin_form), exact tenant slug,
                    # and password reauthentication before destructive deletion.
                    if not hmac.compare_digest(f.get('confirm',''), t['slug']):
                        self.error(400,'Zur Löschbestätigung die Kundenkennung exakt eingeben.');return
                    ip = self.client_address[0]
                    now = time.monotonic()
                    recent = [x for x in REVEAL_FAILURES.get(ip, []) if x > now - 900]
                    if len(recent) >= 5:
                        self.error(429,'Zu viele fehlgeschlagene Passwortprüfungen.');return
                    stored = db.execute("SELECT value FROM settings WHERE key='admin_hash'").fetchone()['value']
                    if not pw_verify(f.get('password',''), stored):
                        recent.append(now)
                        REVEAL_FAILURES[ip] = recent
                        self.error(403,'Admin-Passwort ist falsch');return
                    REVEAL_FAILURES.pop(ip,None)
                    # Use a single transaction and FK checks; no orphan rows.
                    nphones = db.execute('SELECT COUNT(*) FROM phones WHERE tenant_id=?',(tid,)).fetchone()[0]
                    nstatuses = db.execute('SELECT COUNT(*) FROM status_items WHERE tenant_id=?',(tid,)).fetchone()[0]
                    db.execute('DELETE FROM api_keys WHERE tenant_id=?',(tid,))
                    db.execute('DELETE FROM phones WHERE tenant_id=?',(tid,))
                    db.execute('DELETE FROM status_items WHERE tenant_id=?',(tid,))
                    db.execute('DELETE FROM audit WHERE tenant_id=?',(tid,))
                    db.execute('DELETE FROM tenants WHERE id=?',(tid,))
                    # Retain a minimal action trace without names, MACs or secrets.
                    db.execute('INSERT INTO audit(ts,tenant_id,actor,action,detail) VALUES(?,?,?,?,?)',
                               (int(time.time()),None,'admin','tenant_delete',
                                f'tenant_id={tid} phones={nphones} statuses={nstatuses}'))
                    db.commit()
                    if not reload_asterisk():
                        self.error(503,'Kunde gelöscht, aber Asterisk-Reload fehlgeschlagen. Bitte Logs kontrollieren und Stack neu starten.');return
                    self.redirect('/admin');return
                if action=='rotate':
                    token=fresh_key()
                    db.execute('UPDATE api_keys SET token_hash=?,token_ciphertext=? WHERE tenant_id=?',
                               (sha(token),encrypt_api_key(token),tid));db.commit()
                    self.output(200,tenant_panel(db,t,session,token,'API-Schlüssel erneuert.'));return
                if action=='reveal':
                    ip = self.client_address[0]
                    now = time.monotonic()
                    recent = [x for x in REVEAL_FAILURES.get(ip, []) if x > now - 900]
                    if len(recent) >= 5:
                        self.error(429, 'Zu viele fehlgeschlagene Passwortprüfungen.');return
                    stored = db.execute("SELECT value FROM settings WHERE key='admin_hash'").fetchone()['value']
                    if not pw_verify(f.get('password', ''), stored):
                        recent.append(now)
                        REVEAL_FAILURES[ip] = recent
                        self.error(403, 'Admin-Passwort ist falsch');return
                    REVEAL_FAILURES.pop(ip,None)
                    key_row = db.execute('SELECT token_ciphertext FROM api_keys WHERE tenant_id=?',(tid,)).fetchone()
                    if not key_row or not key_row['token_ciphertext']:
                        self.error(409,'Dieser ältere API-Key lässt sich nicht wiederherstellen. Bitte neuen Schlüssel erzeugen.');return
                    try: token = decrypt_api_key(key_row['token_ciphertext'])
                    except RuntimeError:
                        self.error(503,'API-Schlüssel kann nicht entschlüsselt werden. Key-Backup prüfen.');return
                    self.output(200,tenant_panel(db,t,session,token,'API-Schlüssel nach Passwortprüfung angezeigt.'));return
                if action=='active':
                    db.execute('UPDATE tenants SET active=? WHERE id=?',(0 if t['active'] else 1,tid));db.commit()
                    if not reload_asterisk(): self.error(503,'Änderung gespeichert, Asterisk Reload fehlgeschlagen');return
                    self.redirect(f'/admin/tenants/{tid}');return
                if action=='status':
                    slug=f.get('slug','').strip().lower(); ext=f.get('extension','')
                    if not re.fullmatch('[a-z][a-z0-9-]{1,30}',slug) or not ext.isdigit() or not 100 <= int(ext) <= 99999:
                        self.error(400,'Statusname oder BLF-Nummer ungültig');return
                    try:
                        db.execute('INSERT INTO status_items(tenant_id,slug,extension,changed_at) VALUES(?,?,?,?)',(tid,slug,int(ext),int(time.time())));db.commit()
                    except sqlite3.IntegrityError:
                        self.error(409,'Statusname oder BLF-Nummer bereits belegt');return
                    if not reload_asterisk(): self.error(503,'Status gespeichert, Reload fehlgeschlagen');return
                    self.redirect(f'/admin/tenants/{tid}');return
                if action=='phone':
                    label=f.get('label','').strip()
                    if not 1<=len(label)<=80: self.error(400,'Telefonname ungültig');return
                    password=secrets.token_urlsafe(28)
                    pid=db.execute('INSERT INTO phones(tenant_id,label,sip_user,sip_password,created_at) VALUES(?,?,?,?,?)',
                                   (tid,label,'_pending_'+secrets.token_hex(8),password,int(time.time()))).lastrowid
                    name=f'blf_t{tid}_p{pid}'
                    db.execute('UPDATE phones SET sip_user=? WHERE id=?',(name,pid));db.commit()
                    if not reload_asterisk(): self.error(503,'Telefon gespeichert, Reload fehlgeschlagen');return
                    self.redirect(f'/admin/phones/{pid}/settings');return
                if action=='set':
                    slug=f.get('slug',''); val=f.get('value','')
                    if val not in ('0','1'):
                        self.error(400,'Ungültiger Status');return
                    try: result=apply_status(db,tid,slug,int(val),'admin')
                    except RuntimeError: self.error(503,'Asterisk nicht erreichbar');return
                    if result is None: self.error(404,'Status nicht gefunden oder Kunde deaktiviert');return
                    self.redirect(f'/admin/tenants/{tid}');return
            m=re.fullmatch(r'/admin/phones/(\d+)/(active|delete)',path)
            if m:
                pid=int(m.group(1));p=db.execute('SELECT * FROM phones WHERE id=?',(pid,)).fetchone()
                if not p: self.error(404,'Telefon nicht gefunden');return
                if m.group(2)=='delete':
                    if not hmac.compare_digest(f.get('confirm',''), p['sip_user']):
                        self.error(400,'Bitte die exakte SIP-Kennung des Telefons bestätigen.');return
                    db.execute('DELETE FROM phones WHERE id=?', (pid,))
                    db.execute('INSERT INTO audit(ts,tenant_id,actor,action,detail) VALUES(?,?,?,?,?)',
                               (int(time.time()),p['tenant_id'],'admin','phone_delete',
                                f'phone_id={pid} user={p["sip_user"]}'))
                    db.commit()
                    if not reload_asterisk(): self.error(503,'Telefon gelöscht, aber Asterisk-Reload fehlgeschlagen. Logs kontrollieren.');return
                    self.redirect(f'/admin/tenants/{p["tenant_id"]}');return
                db.execute('UPDATE phones SET active=? WHERE id=?',(0 if p['active'] else 1,pid));db.commit()
                if not reload_asterisk(): self.error(503,'Telefonzustand gespeichert, Reload fehlgeschlagen');return
                self.redirect(f'/admin/tenants/{p["tenant_id"]}');return
        self.error(404,'Aktion nicht gefunden')

    def handle_login(self):
        try: f=self.form()
        except (ValueError,UnicodeError): self.error(400,'Ungültige Anmeldung');return
        ip=self.client_address[0]  # do not trust spoofable X-Forwarded-For
        now=time.monotonic()
        with DB_LOCK:
            recent=[t for t in LOGIN_FAILURES.get(ip,[]) if t > now-900]
            if len(recent)>=5:
                self.error(429,'Zu viele Versuche. Bitte später erneut anmelden.');return
            with conn() as db:
                stored=db.execute("SELECT value FROM settings WHERE key='admin_hash'").fetchone()['value']
                password=f.get('password','')
                ok=pw_verify(password,stored)
                if not ok:
                    recent.append(now);LOGIN_FAILURES[ip]=recent
                    self.error(401,'Anmeldung fehlgeschlagen');return
                LOGIN_FAILURES.pop(ip,None)
                token=secrets.token_urlsafe(48)
                csrf=secrets.token_urlsafe(32)
                db.execute('DELETE FROM sessions WHERE expires_at<?',(int(time.time()),))
                db.execute('INSERT INTO sessions VALUES(?,?,?)',(sha(token),csrf,int(time.time())+8*3600))
                db.commit()
                self.redirect('/admin',{'Set-Cookie':f'__Host-blf_session={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800'})

    def handle_api(self,path):
        if path != '/v1/status' and not re.fullmatch(r'/v1/status/[a-z][a-z0-9-]{1,30}',path):
            self.json_out(404,{'error':'not_found'});return
        raw_key=self.headers.get('X-API-Key','')
        if not 32<=len(raw_key)<=256:
            self.json_out(401,{'error':'unauthorized'});return
        with conn() as db:
            t=db.execute('SELECT t.* FROM tenants t JOIN api_keys a ON a.tenant_id=t.id WHERE a.token_hash=? AND t.active=1',(sha(raw_key),)).fetchone()
            if not t:
                self.json_out(401,{'error':'unauthorized'});return
            try:
                if self.headers.get('Content-Type','').split(';')[0].lower()!='application/json':
                    self.json_out(415,{'error':'json_required'});return
                data=json.loads(self.parse_body(512).decode('utf-8'))
            except (ValueError,UnicodeError):
                self.json_out(400,{'error':'invalid_json'});return
            if type(data) is not dict or set(data)!={'value'} or type(data['value']) is not int or data['value'] not in (0,1):
                self.json_out(400,{'error':'only_value_0_or_1_allowed'});return
            slug=path.removeprefix('/v1/status/').strip('/') if path!='/v1/status' else 'spontanschaltung'
            now=time.monotonic()
            with DB_LOCK:
                attempts=[a for a in API_ATTEMPTS.get(t['id'],[]) if a > now-60]
                if len(attempts)>=60:
                    self.json_out(429,{'error':'rate_limited'});return
                attempts.append(now);API_ATTEMPTS[t['id']]=attempts
                try: state=apply_status(db,t['id'],slug,data['value'],'api')
                except RuntimeError:
                    self.json_out(503,{'error':'asterisk_unavailable'});return
            if state is None:
                self.json_out(404,{'error':'status_not_found'});return
            self.json_out(200,{'ok':True,'value':data['value'],'state':state,'status':slug})


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--init':
        db_init();generate_configs();return
    db_init()
    # Wait for Asterisk CLI to become available before restoring desired statuses.
    for _ in range(30):
        if ast('core show version',timeout=3):break
        time.sleep(1)
    sync_states()
    server=Server((API_BIND_IP,API_PORT),Handler)
    log.info('BLF API + Admin UI listening on %s:%s',API_BIND_IP,API_PORT)
    try: server.serve_forever(poll_interval=0.5)
    finally: server.server_close()


if __name__ == '__main__': main()
