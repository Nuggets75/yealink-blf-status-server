"""End-to-end HTTP/security smoke tests without a live Asterisk process."""
import http.client
import importlib.util
import os
from pathlib import Path
import re
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET

SRC = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('blf', SRC/'app'/'app.py')
blf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(blf)

class BLFTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        blf.STATE_DIR = Path(self.tmp.name)/'state'
        blf.DB_PATH = blf.STATE_DIR/'state.sqlite3'
        blf.PJSIP_PATH = blf.STATE_DIR/'pjsip.conf'
        blf.EXT_PATH = blf.STATE_DIR/'extensions.conf'
        blf.SOURCE_TEMPLATE=SRC/'templates'/'source-yealinkT4x.ph.xml'
        os.environ['ADMIN_PASSWORD'] = 'UnitTestAdminPasswordIsVeryLong123'
        os.environ['SIP_PASSWORD'] = 'legacy_password_1234567890'
        os.environ['API_TOKEN'] = 'legacy_api_token_12345678901234567890123456789'
        blf.LOGIN_FAILURES.clear()
        blf.API_ATTEMPTS.clear()
        blf.db_init()
        blf.generate_configs()
        self.commands=[]
        self.old_ast=blf.ast
        blf.ast=lambda cmd,timeout=7: self.commands.append(cmd) or True
        self.server=blf.Server(('127.0.0.1',0), blf.Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.cookie=None
        self.csrf=None
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3)
        blf.ast=self.old_ast
        self.tmp.cleanup()
    def call(self,method,path,body=None,headers=None):
        con=http.client.HTTPConnection('127.0.0.1',self.server.server_port, timeout=5)
        h=headers.copy() if headers else {}
        if self.cookie: h['Cookie']=self.cookie
        con.request(method,path,body,headers=h)
        res=con.getresponse();data=res.read().decode();hd=dict(res.getheaders());status=res.status;con.close()
        if 'Set-Cookie' in hd:self.cookie=hd['Set-Cookie'].split(';')[0]
        return status,data,hd
    def login(self):
        status,body,h=self.call('POST','/admin/login','password=UnitTestAdminPasswordIsVeryLong123',{'Content-Type':'application/x-www-form-urlencoded'})
        self.assertEqual(status,303)
        status,body,h=self.call('GET','/admin')
        self.assertEqual(status,200)
        self.csrf=re.search('name="csrf" value="([^"]+)"',body).group(1)
        return body
    def form(self,path,params):
        from urllib.parse import urlencode
        return self.call('POST',path,urlencode({'csrf':self.csrf,**params}),{'Content-Type':'application/x-www-form-urlencoded'})
    def api(self,key,val,path='/v1/status'):
        return self.call('POST',path,'{"value":'+str(val)+'}',{'Content-Type':'application/json','X-API-Key':key})
    def test_legacy_import(self):
        with blf.conn() as c:
            self.assertEqual(c.execute('SELECT sip_user FROM phones').fetchone()[0],'status01')
            self.assertIn('subscribe_context=blf_t1',blf.PJSIP_PATH.read_text())
            self.assertIn('9001,hint,Custom:blf_t1_spontanschaltung',blf.EXT_PATH.read_text())
    def test_admin_login_and_csrf(self):
        self.assertEqual(self.call('GET','/admin')[0],303)
        self.login()
        self.assertEqual(self.call('POST','/admin/tenants','name=Injected&slug=injected',{'Content-Type':'application/x-www-form-urlencoded'})[0],403)
    def test_multitenant_create_and_api_isolation(self):
        self.login()
        status,body,headers=self.form('/admin/tenants',{'name':'Kunde zwei','slug':'kunde-zwei'})
        self.assertEqual(status,200)
        key=re.search('class="secret">(blf_[^<]+)</div>',body).group(1)
        tid=re.search(r'Kennung: kunde-zwei · ID: (\d+)',body).group(1)
        self.assertEqual(self.api(key,1)[0],200)
        self.assertIn(f'devstate change Custom:blf_t{tid}_spontanschaltung BUSY',self.commands)
        self.assertEqual(self.api(key,1,'/v1/status/notbetrieb')[0],404)
        self.assertEqual(self.api('wrong'*20,1)[0],401)
        self.assertEqual(self.api(key,'true')[0],400)
        self.assertEqual(self.api(os.environ['API_TOKEN'],0)[0],200)
        self.assertIn('devstate change Custom:blf_t1_spontanschaltung NOT_INUSE',self.commands)
    def test_export_per_customer_template(self):
        self.login()
        status,body,headers=self.form('/admin/tenants/1/phone',{'label':'Telefon T54W'})
        self.assertEqual(status,303)
        pid=re.search(r'/admin/phones/(\d+)/settings',headers['Location']).group(1)
        status, xml, h=self.call('GET',f'/admin/phones/{pid}/template')
        self.assertEqual(status,200)
        ET.fromstring(xml)
        self.assertIn('linekey.1.line = 2',xml)
        self.assertIn('linekey.1.value = 9001',xml)
        self.assertIn('linekey.2.value = %%type%%',xml)
        self.assertIn('account.2.sip_server.1.address = blf.example.de',xml)
        self.assertIn('account.2.user_name = blf_t1_p',xml)
        self.assertIn('account.1.sip_server.1.address = %%pbx_ip%%',xml)
        self.assertNotIn('linekey.1.value = 951',xml)
        self.assertIn('y100000000066.cfg',xml)
        self.cookie=None
        self.assertEqual(self.call('GET',f'/admin/phones/{pid}/template')[0],303)
    def test_token_rotation_revokes_old(self):
        self.login()
        old=os.environ['API_TOKEN']
        status,body,_=self.form('/admin/tenants/1/rotate',{})
        self.assertEqual(status,200)
        new=re.search('class="secret">(blf_[^<]+)</div>',body).group(1)
        self.assertEqual(self.api(old,1)[0],401)
        self.assertEqual(self.api(new,1)[0],200)

    def test_api_key_reveal_requires_password_and_is_encrypted_at_rest(self):
        self.login()
        status,body,_=self.form('/admin/tenants',{'name':'Kunde mit key','slug':'kunde-key'})
        self.assertEqual(status,200)
        token=re.search('class="secret">(blf_[^<]+)</div>',body).group(1)
        tid=re.search(r'Kennung: kunde-key · ID: (\d+)',body).group(1)
        with blf.conn() as db:
            row=db.execute('SELECT token_hash,token_ciphertext FROM api_keys WHERE tenant_id=?',(tid,)).fetchone()
            self.assertNotIn(token,row['token_ciphertext'])
            self.assertEqual(row['token_hash'],blf.sha(token))
        status,ordinary,_=self.call('GET',f'/admin/tenants/{tid}')
        self.assertEqual(status,200)
        self.assertNotIn(token,ordinary)
        self.assertIn('API-Schlüssel anzeigen',ordinary)
        status,body,_=self.form(f'/admin/tenants/{tid}/reveal',{'password':'wrong-password'})
        self.assertEqual(status,403)
        self.assertNotIn(token,body)
        status,body,headers=self.form(f'/admin/tenants/{tid}/reveal',{'password':'UnitTestAdminPasswordIsVeryLong123'})
        self.assertEqual(status,200)
        self.assertIn(token,body)
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertEqual(self.api(token,0)[0],200)

    def test_old_hash_only_key_needs_rotation(self):
        self.login()
        with blf.conn() as db:
            db.execute('UPDATE api_keys SET token_ciphertext=NULL WHERE tenant_id=1')
        status,body,_=self.call('GET','/admin/tenants/1')
        self.assertEqual(status,200)
        self.assertIn('nicht wiederherstellbar',body)
        status,body,_=self.form('/admin/tenants/1/reveal',{'password':'UnitTestAdminPasswordIsVeryLong123'})
        self.assertEqual(status,409)
        self.assertEqual(self.api(os.environ['API_TOKEN'],1)[0],200)
        status,body,_=self.form('/admin/tenants/1/rotate',{})
        self.assertEqual(status,200)
        new=re.search('class="secret">(blf_[^<]+)</div>',body).group(1)
        status,body,_=self.form('/admin/tenants/1/reveal',{'password':'UnitTestAdminPasswordIsVeryLong123'})
        self.assertEqual(status,200)
        self.assertIn(new,body)

    def test_phone_delete_confirmation_and_pjsip_revocation(self):
        self.login()
        status,body,headers=self.form('/admin/tenants/1/phone',{'label':'T46G test'})
        self.assertEqual(status,303)
        pid=int(re.search(r'/admin/phones/(\d+)/settings',headers['Location']).group(1))
        with blf.conn() as db:
            p=db.execute('SELECT sip_user FROM phones WHERE id=?',(pid,)).fetchone()
            user=p['sip_user']
        self.assertIn(f'[{user}]',blf.PJSIP_PATH.read_text())
        status,body,_=self.call('GET',f'/admin/phones/{pid}/settings')
        self.assertEqual(status,200)
        self.assertIn('Telefon dauerhaft löschen',body)
        self.assertEqual(self.form(f'/admin/phones/{pid}/delete',{'confirm':'wrong'})[0],400)
        with blf.conn() as db:
            self.assertIsNotNone(db.execute('SELECT id FROM phones WHERE id=?',(pid,)).fetchone())
        status,body,headers=self.form(f'/admin/phones/{pid}/delete',{'confirm':user})
        self.assertEqual(status,303)
        self.assertEqual(headers['Location'],'/admin/tenants/1')
        with blf.conn() as db:
            self.assertIsNone(db.execute('SELECT id FROM phones WHERE id=?',(pid,)).fetchone())
            self.assertIsNotNone(db.execute('SELECT id FROM audit WHERE action="phone_delete"').fetchone())
        self.assertNotIn(f'[{user}]',blf.PJSIP_PATH.read_text())
        self.assertEqual(self.call('GET',f'/admin/phones/{pid}/settings')[0],404)

    def test_legacy_g_model_export_and_first_key_mapping(self):
        self.login()
        status,body,headers=self.form('/admin/tenants/1/phone',{'label':'T46G'})
        self.assertEqual(status,303)
        pid=int(re.search(r'/admin/phones/(\d+)/settings',headers['Location']).group(1))
        status,xml,_=self.call('GET',f'/admin/phones/{pid}/template')
        self.assertEqual(status,200)
        root=ET.fromstring(xml)
        models={m.attrib['ua']:m.text for m in root.findall('.//models/model')}
        self.assertIn('SIP-T46G',models)
        self.assertIn('Yealink T46 [BLF testanlage]',models['SIP-T46G'])
        for model in ('SIP-T42G','SIP-T46G','SIP-T48G','SIP-T40G'):
            self.assertIn(model,models)
        for file in ('y100000000028.cfg','y100000000029.cfg','y100000000035.cfg','y100000000076.cfg'):
            self.assertIn(file,xml)
        self.assertIn('linekey.1.line = 2',xml)
        self.assertIn('linekey.2.value = %%type%%',xml)
        self.assertIn('account.2.sip_server.1.address = blf.example.de',xml)

    def test_existing_database_schema_migrates_without_losing_api_key(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            saved=(blf.STATE_DIR,blf.DB_PATH,blf.PJSIP_PATH,blf.EXT_PATH)
            try:
                blf.STATE_DIR=Path(tmp)/'state';blf.STATE_DIR.mkdir()
                blf.DB_PATH=blf.STATE_DIR/'state.sqlite3'
                blf.PJSIP_PATH=blf.STATE_DIR/'pjsip.conf'
                blf.EXT_PATH=blf.STATE_DIR/'extensions.conf'
                with sqlite3.connect(blf.DB_PATH) as old_db:
                    old_db.execute('CREATE TABLE api_keys (tenant_id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE)')
                    old_db.execute('INSERT INTO api_keys(tenant_id,token_hash) VALUES(1,?)',(blf.sha(os.environ['API_TOKEN']),))
                    old_db.execute('CREATE TABLE tenants (id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL)')
                    old_db.execute("INSERT INTO tenants VALUES(1,'testanlage','Testanlage',1,123)")
                blf.db_init()
                with blf.conn() as db:
                    row=db.execute('SELECT * FROM api_keys WHERE tenant_id=1').fetchone()
                    self.assertEqual(row['token_hash'],blf.sha(os.environ['API_TOKEN']))
                    self.assertEqual(blf.decrypt_api_key(row['token_ciphertext']),os.environ['API_TOKEN'])
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM tenants').fetchone()[0],1)
                self.assertTrue((blf.STATE_DIR/'.api-key-fernet.key').is_file())
                self.assertEqual((blf.STATE_DIR/'.api-key-fernet.key').stat().st_mode & 0o777,0o600)
            finally:
                blf.STATE_DIR,blf.DB_PATH,blf.PJSIP_PATH,blf.EXT_PATH=saved

    def test_encrypted_keys_require_original_key_file(self):
        self.login()
        with blf.conn() as db:
            self.assertTrue(db.execute('SELECT token_ciphertext FROM api_keys LIMIT 1').fetchone()[0])
        path=blf.STATE_DIR/'.api-key-fernet.key'
        path.unlink()
        with self.assertRaisesRegex(RuntimeError,'Backup'):
            blf.db_init()

    def test_tenant_delete_requires_confirmation_and_reauthentication(self):
        self.login()
        status, page, _ = self.call('GET','/admin/tenants/1')
        self.assertEqual(status,200)
        self.assertIn('Kunde dauerhaft löschen', page)
        url='/admin/tenants/1/delete'
        secret=os.environ['ADMIN_PASSWORD']
        self.assertEqual(self.form(url,{'confirm':'testanlage','password':'wrong'})[0],403)
        self.assertEqual(self.form(url,{'confirm':'wrong','password':secret})[0],400)
        from urllib.parse import urlencode
        self.assertEqual(self.call('POST',url,urlencode({'confirm':'testanlage','password':secret}),{'Content-Type':'application/x-www-form-urlencoded'})[0],403)
        with blf.conn() as db:
            self.assertIsNotNone(db.execute('SELECT 1 FROM tenants WHERE id=1').fetchone())
            self.assertIsNotNone(db.execute('SELECT 1 FROM api_keys WHERE tenant_id=1').fetchone())
        self.cookie=None
        self.assertEqual(self.call('POST',url,'csrf=dummy&confirm=testanlage&password=x',{'Content-Type':'application/x-www-form-urlencoded'})[0],303)

    def test_tenant_delete_removes_all_resources_and_retains_other_tenants(self):
        self.login()
        status,body,_=self.form('/admin/tenants',{'name':'Other customer','slug':'other-customer'})
        self.assertEqual(status,200)
        other_key=re.search('class="secret">(blf_[^<]+)</div>',body).group(1)
        other_tid=int(re.search(r'Kennung: other-customer · ID: (\d+)',body).group(1))
        status,_,headers=self.form('/admin/tenants/1/phone',{'label':'Delete me'})
        self.assertEqual(status,303)
        pid=int(re.search(r'/admin/phones/(\d+)/settings',headers['Location']).group(1))
        with blf.conn() as db:
            p=db.execute('SELECT sip_user FROM phones WHERE id=?',(pid,)).fetchone()
            user=p['sip_user']
        self.assertIn(user,blf.PJSIP_PATH.read_text())
        self.assertEqual(self.api(os.environ['API_TOKEN'],1)[0],200)
        status,body,headers=self.form('/admin/tenants/1/delete',{'confirm':'testanlage','password':os.environ['ADMIN_PASSWORD']})
        self.assertEqual(status,303)
        self.assertEqual(headers['Location'],'/admin')
        with blf.conn() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM tenants WHERE id=1').fetchone())
            for table in ('phones','status_items','api_keys','audit'):
                self.assertEqual(db.execute(f'SELECT count(*) FROM {table} WHERE tenant_id=1').fetchone()[0],0)
            self.assertIsNotNone(db.execute('SELECT 1 FROM tenants WHERE id=?',(other_tid,)).fetchone())
            event=db.execute("SELECT tenant_id,detail FROM audit WHERE action='tenant_delete'").fetchone()
            self.assertIsNone(event['tenant_id'])
            self.assertNotIn('testanlage',event['detail'])
        self.assertEqual(self.api(os.environ['API_TOKEN'],0)[0],401)
        self.assertEqual(self.api(other_key,1)[0],200)
        self.assertNotIn(user,blf.PJSIP_PATH.read_text())
        self.assertNotIn('[blf_t1]',blf.EXT_PATH.read_text())
        self.assertIn(f'[blf_t{other_tid}]',blf.EXT_PATH.read_text())
        self.assertEqual(self.call('GET','/admin/tenants/1')[0],404)
        self.assertEqual(self.call('GET',f'/admin/phones/{pid}/settings')[0],404)

    def test_last_tenant_delete_does_not_reimport_legacy_credentials_on_restart(self):
        self.login()
        url='/admin/tenants/1/delete'
        self.assertEqual(self.form(url,{'confirm':'testanlage','password':os.environ['ADMIN_PASSWORD']})[0],303)
        with blf.conn() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM tenants').fetchone()[0],0)
            self.assertEqual(db.execute("SELECT value FROM settings WHERE key='legacy_import_processed'").fetchone()[0],'1')
        blf.db_init()
        blf.generate_configs()
        with blf.conn() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM tenants').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM phones').fetchone()[0],0)
        self.assertEqual(self.api(os.environ['API_TOKEN'],1)[0],401)

if __name__=='__main__': unittest.main()
