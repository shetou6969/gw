import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from gwlib import model,node,control,agent,protocols,security,updater

class ModelTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.patches=[patch.object(node,'STATE',self.root),patch.object(model,'DB',self.root/'db'),patch.object(node,'check')]
        for p in self.patches:p.start()
        model.init();self.c=model.connect();model.begin(self.c)
        self.a=model.register(self.c,{'name':'A','ip':'127.0.0.1'});self.b=model.register(self.c,{'name':'B','ip':'127.0.0.2'});self.at='a'*48;self.bt='b'*48
        model.enroll(self.c,{'id':self.a['id'],'secret':self.a['secret'],'credential':self.at},'127.0.0.1')
        model.enroll(self.c,{'id':self.b['id'],'secret':self.b['secret'],'credential':self.bt},'127.0.0.2')
    def tearDown(self):
        self.c.rollback();self.c.close()
        for p in self.patches:p.stop()
        self.tmp.cleanup()
    def row(self,ident):return self.c.execute('SELECT * FROM nodes WHERE id=?',(ident,)).fetchone()
    def save(self,target=None,port=12000,owner=None):
        return model.save_protocol(self.c,{'node_id':owner or self.a['id'],'spec':{'name':'test','kind':'socks','port':port,'egress':{'type':'node','node':target} if target else {'type':'direct'}}})
    def poll(self,who='a',**kw):
        n=self.a if who=='a' else self.b;t=self.at if who=='a' else self.bt;ip='127.0.0.1' if who=='a' else '127.0.0.2'
        return model.poll(self.c,{'id':n['id'],**kw},t,ip)
    def test_unregistered_rejected(self):
        with self.assertRaises(PermissionError):model.enroll(self.c,{'id':'bad','secret':'bad','credential':'x'*48},'127.0.0.1')
    def test_wrong_ip_rejected(self):
        n=model.register(self.c,{'name':'C','ip':'127.0.0.3'})
        with self.assertRaises(PermissionError):model.enroll(self.c,{'id':n['id'],'secret':n['secret'],'credential':'c'*48},'127.0.0.4')
    def test_expired_rejected(self):
        n=model.register(self.c,{'name':'C','ip':'127.0.0.3'});self.c.execute('UPDATE nodes SET join_expiry=0 WHERE id=?',(n['id'],))
        with self.assertRaises(PermissionError):model.enroll(self.c,{'id':n['id'],'secret':n['secret'],'credential':'c'*48},'127.0.0.3')
    def test_replay_with_different_credential_rejected(self):
        with self.assertRaises(PermissionError):model.enroll(self.c,{'id':self.a['id'],'secret':self.a['secret'],'credential':'z'*48},'127.0.0.1')
    def test_exact_retry_after_lost_response(self):
        self.assertTrue(model.enroll(self.c,{'id':self.a['id'],'secret':self.a['secret'],'credential':self.at},'127.0.0.1')['approved'])
    def test_node_isolation(self):
        with self.assertRaises(PermissionError):model.poll(self.c,{'id':self.b['id']},self.at,'127.0.0.2')
    def test_node_peer_rechecked(self):
        with self.assertRaises(PermissionError):model.poll(self.c,{'id':self.a['id']},self.at,'127.0.0.2')
    def test_auto_two_sided_link(self):
        p=self.save(self.b['id']);a=json.loads(self.row(self.a['id'])['desired']);b=json.loads(self.row(self.b['id'])['desired'])
        out=a['files']['p-'+p['id']+'.json']['outbounds'][0];inbound=b['files']['link-'+p['id']+'.json']['inbounds'][0]
        self.assertEqual(out['password'],inbound['password']);self.assertEqual(out['server_port'],inbound['listen_port']);self.assertEqual(out['type'],'shadowsocks')
        rules=b['files']['link-'+p['id']+'.json']['route']['rules'];self.assertEqual(rules[0]['source_ip_cidr'],['127.0.0.1/32']);self.assertEqual(rules[1]['action'],'reject')
    def test_local_controller_node_uses_public_ip_for_relay(self):
        local=model.register(self.c,{'name':'local','ip':'198.51.100.7','join_ip':'127.0.0.1'})
        model.enroll(self.c,{'id':local['id'],'secret':local['secret'],'credential':'c'*48},'127.0.0.1')
        p=self.save(self.b['id'],owner=local['id'])
        target=json.loads(self.row(self.b['id'])['desired'])
        rules=target['files']['link-'+p['id']+'.json']['route']['rules']
        self.assertEqual(rules[0]['source_ip_cidr'],['198.51.100.7/32'])
    def test_destination_before_source(self):
        self.save(self.b['id']);r=self.poll();self.assertIsNone(r['desired']);self.assertIn(self.b['id'],r['waiting'])
        dest=self.poll('b');self.assertIsNotNone(dest['desired']);self.poll('b',applied=dest['revision']);self.assertIsNotNone(self.poll()['desired'])
    def test_port_collision(self):
        self.save()
        with self.assertRaises(ValueError):self.save(port=12000)
    def test_cycle_rejected(self):
        self.save(self.b['id'])
        with self.assertRaises(ValueError):self.save(self.a['id'],owner=self.b['id'])
    def test_stale_edit_rejected(self):
        p=self.save();raw={'id':p['id'],'expected_revision':0,'node_id':self.a['id'],'spec':{'name':'x','kind':'socks','port':12001,'egress':{'type':'direct'}}}
        with self.assertRaises(ValueError):model.save_protocol(self.c,raw)
    def test_protocol_delete_waits_for_both(self):
        p=self.save(self.b['id']);op=model.remove_protocol(self.c,p['id'])
        self.assertFalse(json.loads(self.row(self.a['id'])['desired'])['files']);self.assertFalse(json.loads(self.row(self.b['id'])['desired'])['files'])
        self.poll(applied=self.row(self.a['id'])['revision'])
        self.assertEqual(self.c.execute('SELECT phase FROM operations WHERE id=?',(op,)).fetchone()[0],'pending')
        self.poll('b',applied=self.row(self.b['id'])['revision'])
        self.assertEqual(self.c.execute('SELECT phase FROM operations WHERE id=?',(op,)).fetchone()[0],'complete')
        self.assertFalse(self.c.execute('SELECT 1 FROM protocols WHERE id=?',(p['id'],)).fetchone())
    def test_node_delete_cascade_and_ack(self):
        self.save(self.b['id']);op=model.remove_node(self.c,self.b['id'])
        self.assertEqual(self.row(self.b['id'])['phase'],'deleting');self.assertTrue(self.poll('b')['purge'])
        self.poll(applied=self.row(self.a['id'])['revision']);self.assertEqual(self.c.execute('SELECT phase FROM operations WHERE id=?',(op,)).fetchone()[0],'pending')
        self.assertTrue(self.poll('b',purged=True)['terminate']);self.assertEqual(self.row(self.b['id'])['phase'],'deleted')
        self.assertEqual(self.c.execute('SELECT phase FROM operations WHERE id=?',(op,)).fetchone()[0],'complete')
        self.assertTrue(self.poll('b',purged=True)['terminate']) # Lost final response can be retried.
    def test_delete_never_enrolled_completes(self):
        n=model.register(self.c,{'name':'C','ip':'127.0.0.3'});op=model.remove_node(self.c,n['id'])
        # Existing A/B may receive initial empty config as part of reconciliation.
        self.poll(applied=self.row(self.a['id'])['revision']);self.poll('b',applied=self.row(self.b['id'])['revision'])
        self.assertEqual(self.c.execute('SELECT phase FROM operations WHERE id=?',(op,)).fetchone()[0],'complete')

class AgentTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.patches=[patch.object(node,'STATE',self.root),patch.object(node,'ROOT',self.root/'data')]
        for p in self.patches:p.start()
    def tearDown(self):
        for p in self.patches:p.stop()
        self.tmp.cleanup()
    def test_local_node_cleanup_preserves_controller_install(self):
        (self.root/'role').write_text('both\n')
        (self.root/'install-complete').touch()
        (self.root/'agent.json').write_text('{}')
        with patch.object(node,'run'):
            node.finish_cleanup()
        self.assertEqual((self.root/'role').read_text(),'controller\n')
        self.assertTrue((self.root/'install-complete').exists())
        self.assertFalse((self.root/'agent.json').exists())
    def test_combined_upgrade_starts_both_services(self):
        cert=self.root/'tls.crt';cert.write_text('test cert')
        (self.root/'controller.json').write_text(json.dumps({'cert':str(cert),'web_port':8443}))
        with patch.object(updater.node,'run') as run,patch.object(updater.time,'sleep'),patch.object(updater.ssl,'PEM_cert_to_DER_cert',return_value=b'cert'),patch.object(updater.http.client,'HTTPSConnection') as connection:
            connection.return_value.sock.getpeercert.return_value=b'cert'
            response=connection.return_value.getresponse.return_value
            response.status=200;response.read.return_value=b'{"version":"0.4.0"}'
            updater.health('both','0.4.0')
        self.assertEqual([x.args[0][-1] for x in run.call_args_list],['gw-controller','gw-agent'])
        connection.return_value.request.assert_called_once_with('GET','/healthz')
    def test_failed_enrollment_does_not_save_agent(self):
        with patch.object(agent,'request',side_effect=PermissionError('no')):
            with self.assertRaises(PermissionError):agent.join('example.com',9443,'1234567890abcdef.secret.'+'a'*64)
        self.assertFalse((self.root/'agent.json').exists());self.assertFalse((self.root/'enrollment-pending.json').exists())
    def test_network_failure_keeps_retry_state(self):
        with patch.object(agent,'request',side_effect=OSError('offline')):
            with self.assertRaises(OSError):agent.join('example.com',9443,'1234567890abcdef.secret.'+'a'*64)
        self.assertFalse((self.root/'agent.json').exists());self.assertTrue((self.root/'enrollment-pending.json').exists())
    def test_cleanup_before_receipt_and_credential_removal(self):
        state={}
        with patch.object(agent,'request',side_effect=[{'purge':True},{'terminate':True}]),patch.object(agent,'info',return_value={}),patch.object(node,'cleanup') as cleanup,patch.object(node,'finish_cleanup') as finish:
            self.assertTrue(agent.step({'id':'a'},state));cleanup.assert_called_once();finish.assert_not_called();self.assertTrue(state['purged'])
            self.assertFalse(agent.step({'id':'a'},state));finish.assert_called_once()
    def test_failed_apply_not_acknowledged(self):
        with patch.object(agent,'request',return_value={'desired':{},'revision':2}),patch.object(agent,'info',return_value={}),patch.object(node,'apply_bundle',side_effect=ValueError('bad')):
            state={'applied':1};agent.step({'id':'a'},state);self.assertEqual(state['applied'],1)
    def test_restart_failure_rolls_back(self):
        node.initialize();old=node.snapshot();new={'base':old['base'],'files':{'a.json':{}}}
        with patch.object(node,'check'),patch.object(node,'service',side_effect=[RuntimeError('restart'),None]):
            with self.assertRaises(RuntimeError):node.apply_bundle(new)
        self.assertEqual(node.snapshot(),old)
    def test_deleted_configuration_not_in_backup(self):
        node.initialize();node.atomic(node.ROOT/'conf/secret.json',{'password':'old-secret'})
        with patch.object(node,'check'),patch.object(node,'service'):node.apply_bundle({'base':{},'files':{}})
        self.assertFalse(list(node.ROOT.rglob('secret.json')));self.assertFalse((node.ROOT/'.transaction').exists())
    def test_recover_interrupted_transaction(self):
        node.initialize();import shutil
        backup=node.ROOT/'.transaction';backup.mkdir();shutil.copy2(node.ROOT/'config.json',backup/'config.json');shutil.copytree(node.ROOT/'conf',backup/'conf');node.atomic(node.ROOT/'config.json',{'changed':True})
        node.recover();self.assertNotIn('changed',node.snapshot()['base'])
    def test_refuse_unowned_directory(self):
        node.ROOT.mkdir();(node.ROOT/'user-file').write_text('keep')
        with self.assertRaises(ValueError):node.initialize()
        self.assertTrue((node.ROOT/'user-file').exists())
    def test_reject_path_traversal(self):
        with self.assertRaises(ValueError):node.validate({'base':{},'files':{'../x.json':{}}})

class WebTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.patches=[patch.object(node,'STATE',self.root),patch.object(model,'DB',self.root/'db')]
        for p in self.patches:p.start()
        model.init();control.set_password('admin','test-password-12345')
        self.web=control.Server(('127.0.0.1',0),control.Handler);self.agent=control.Server(('127.0.0.1',0),control.Handler);self.agent.surface='agent'
        for s in (self.web,self.agent):threading.Thread(target=s.serve_forever,daemon=True).start()
    def tearDown(self):
        for s in (self.web,self.agent):s.shutdown();s.server_close()
        for p in self.patches:p.stop()
        self.tmp.cleanup()
    def call(self,path,body=None,token='',server=None):
        server=server or self.web
        req=urllib.request.Request(f'http://127.0.0.1:{server.server_port}'+path,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Bearer '+token})
        try:
            with urllib.request.urlopen(req) as r:return r.status,json.load(r)
        except urllib.error.HTTPError as e:return e.code,json.load(e)
    def test_password_and_session(self):
        self.assertEqual(self.call('/api/state')[0],401)
        code,value=self.call('/api/login',{'username':'admin','password':'test-password-12345'});self.assertEqual(code,200)
        self.assertEqual(self.call('/api/state',token=value['token'])[0],200)
        self.call('/api/logout',{},value['token']);self.assertEqual(self.call('/api/state',token=value['token'])[0],401)
    def test_two_factor_setup_login_and_recovery_replay(self):
        password='test-password-12345'
        code,login=self.call('/api/login',{'username':'admin','password':password})
        self.assertEqual(code,200)
        token=login['token']
        code,setup=self.call('/api/2fa/begin',{'password':password},token)
        self.assertEqual(code,200)
        otp=security.totp(setup['secret'],int(time.time()//30))
        code,confirmed=self.call('/api/2fa/confirm',{'password':password,'otp':otp},token)
        self.assertEqual(code,200)
        self.assertEqual(len(confirmed['codes']),10)
        self.assertEqual(self.call('/api/login',{'username':'admin','password':password})[0],401)
        recovery=confirmed['codes'][0]
        self.assertEqual(self.call('/api/login',{'username':'admin','password':password,'otp':recovery})[0],200)
        self.assertEqual(self.call('/api/login',{'username':'admin','password':password,'otp':recovery})[0],401)
    def test_separate_ports(self):
        self.assertEqual(self.call('/api/state',server=self.agent)[0],404)
        self.assertEqual(self.call('/api/login',{'username':'admin','password':'test-password-12345'},server=self.agent)[0],404)
    def test_login_rate_limit(self):
        for _ in range(5):self.assertEqual(self.call('/api/login',{'username':'admin','password':'wrong'})[0],401)
        code,v=self.call('/api/login',{'username':'admin','password':'test-password-12345'});self.assertEqual(code,401);self.assertIn('尝试过多',v['error'])
    def test_password_not_plaintext(self):
        saved=(self.root/'account.json').read_text();self.assertNotIn('test-password-12345',saved)

if __name__=='__main__':unittest.main()
