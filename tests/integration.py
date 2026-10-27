"""Real HTTPS registration + automatic encrypted A/B routing + two-sided cleanup.
Requires a real official sing-box binary, TLS 1.3 capable Python and curl.
No system services or production servers are modified.
"""
import contextlib
import hashlib
import http.server
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from gwlib import node,model,control,agent,protocols
CORE=Path(sys.argv[1]).resolve()

def freeport():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data=b'GW_V2_CHAIN_OK';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*a):pass

with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
    root=Path(td)
    for obj,attr,value in [(node,'STATE',root),(node,'CORE',CORE),(model,'DB',root/'db'),(control,'SETTINGS',root/'controller.json')]:stack.enter_context(patch.object(obj,attr,value))
    model.init();control.set_password('admin','integration-only-password')
    pem=subprocess.check_output([str(CORE),'generate','tls-keypair','localhost'],text=True)
    cert=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',pem,re.S).group(0)
    key=re.search(r'-----BEGIN .*?PRIVATE KEY-----.*?-----END .*?PRIVATE KEY-----',pem,re.S).group(0)
    (root/'cert.pem').write_text(cert);(root/'key.pem').write_text(key)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(root/'cert.pem',root/'key.pem')
    hits=[]
    class Handler(control.Handler):
        def do_POST(self):hits.append(self.path);super().do_POST()
    servers=[]
    for surface in ('web','agent'):
        server=control.Server(('127.0.0.1',0),Handler);server.surface=surface;server.tls_context=ctx
        threading.Thread(target=server.serve_forever,daemon=True).start();stack.callback(server.server_close);stack.callback(server.shutdown);servers.append(server)
    web,api=servers
    node.atomic(control.SETTINGS,{'public_host':'localhost','web_port':web.server_port,'agent_port':api.server_port,'cert':str(root/'cert.pem'),'key':str(root/'key.pem')})
    clientctx=ssl.create_default_context(cafile=str(root/'cert.pem'))
    token=''
    def call(path,body=None):
        req=urllib.request.Request(f'https://localhost:{web.server_port}'+path,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        with urllib.request.urlopen(req,context=clientctx) as r:return json.load(r)
    token=call('/api/login',{'username':'admin','password':'integration-only-password'})['token']
    configs=[]
    for label,ip in [('A','::1'),('B','127.0.0.1')]:
        reg=call('/api/node/add',{'name':label,'ip':ip,'join_ip':'127.0.0.1','relay_min':20000,'relay_max':29999})
        ident,secret,pin=reg['code'].split('.')
        cfg={'host':'localhost','port':api.server_port,'id':ident,'fingerprint':pin,'credential':secrets.token_urlsafe(48)}
        assert agent.request(cfg,'/agent/enroll',{'id':ident,'secret':secret,'credential':cfg['credential']})['approved']
        configs.append(cfg)
    a,b=configs
    print('PASS HTTPS account login, IP registration, pinned one-time enrollment')
    before=len(hits)
    try:agent.request({**a,'fingerprint':'0'*64},'/agent/poll',{'id':a['id']})
    except ssl.SSLError:pass
    else:raise AssertionError('Wrong pin accepted')
    time.sleep(.1);assert len(hits)==before
    print('PASS wrong certificate pin rejected before sending HTTP credentials')
    for kind in protocols.KINDS:
        s=protocols.normalize({'name':kind,'kind':kind,'port':freeport(),'target':'127.0.0.1','target_port':80})
        node.check({'base':{'outbounds':[{'type':'direct','tag':'direct'}]},'files':{'test.json':{'inbounds':[protocols.inbound(s,'test')]}}})
        out=protocols.client(s,'127.0.0.1')
        if out:node.check({'base':{'outbounds':[out]},'files':{}})
    print('PASS 22 web protocol templates and their client configurations')
    port=freeport()
    result=call('/api/protocol/save',{'node_id':a['id'],'spec':{'name':'A via B','kind':'socks','port':port,'username':'gw','password':'test-password','egress':{'type':'node','node':b['id']}}})
    def poll(cfg,applied=0,**kw):return agent.request(cfg,'/agent/poll',{'id':cfg['id'],'applied':applied,**kw})
    assert poll(a)['desired'] is None
    desiredB=poll(b);assert desiredB['desired']
    processes={}
    def start(label,bundle):
        d=root/label;d.mkdir(exist_ok=True);conf=d/'conf'
        if conf.exists():__import__('shutil').rmtree(conf)
        conf.mkdir();node.atomic(d/'config.json',bundle['base'])
        for name,c in bundle['files'].items():node.atomic(conf/name,c)
        if label in processes:
            p=processes[label]
            if p.poll() is None:p.terminate();p.wait(timeout=10)
        log=open(d/'log','a');stack.callback(log.close)
        p=subprocess.Popen([str(CORE),'run','-c',str(d/'config.json'),'-C',str(conf)],stdout=log,stderr=log);processes[label]=p
        stack.callback(lambda p=p: (p.terminate(),p.wait(timeout=10)) if p.poll() is None else None)
        time.sleep(.3)
        if p.poll() is not None:raise RuntimeError((d/'log').read_text())
    start('B',desiredB['desired']);poll(b,desiredB['revision']);desiredA=poll(a);assert desiredA['desired'];start('A',desiredA['desired']);poll(a,desiredA['revision'])
    target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target);threading.Thread(target=target.serve_forever,daemon=True).start();stack.callback(target.server_close);stack.callback(target.shutdown)
    def fetch():return subprocess.run(['curl','--silent','--show-error','--max-time','5','--noproxy','','--proxy',f'socks5h://gw:test-password@127.0.0.1:{port}',f'http://127.0.0.1:{target.server_port}/'],capture_output=True)
    response=fetch()
    if response.returncode or response.stdout!=b'GW_V2_CHAIN_OK':raise RuntimeError(response.stderr.decode()+'\n'+(root/'A/log').read_text()+'\n'+(root/'B/log').read_text())
    print('PASS actual A -> automatically generated SS2022 link B -> target traffic')
    # Even with the link key, a source address outside A's registered address is rejected.
    wrong_port=freeport();link_out=next(iter(desiredA['desired']['files'].values()))['outbounds'][0].copy();link_out['server']='::1'
    start('untrusted-source',{'base':{'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':wrong_port}],'outbounds':[link_out]},'files':{}})
    denied=subprocess.run(['curl','--silent','--max-time','3','--noproxy','','--proxy',f'socks5h://127.0.0.1:{wrong_port}',f'http://127.0.0.1:{target.server_port}/'],capture_output=True)
    assert denied.returncode!=0,'Internal link accepted unregistered source IP'
    print('PASS internal encrypted listener rejects a different source address')
    processes['B'].terminate();processes['B'].wait(timeout=10);assert fetch().returncode!=0
    print('PASS no direct fallback when B is unavailable')
    deleted=call('/api/protocol/delete',{'id':result['id']});newA=poll(a,desiredA['revision']);assert not newA['desired']['files'];start('A',newA['desired']);poll(a,newA['revision'])
    state=call('/api/state');op=next(x for x in state['operations'] if x['id']==deleted['operation']);assert op['phase']=='pending'
    newB=poll(b,desiredB['revision']);assert not newB['desired']['files'];start('B',newB['desired']);poll(b,newB['revision'])
    state=call('/api/state');op=next(x for x in state['operations'] if x['id']==deleted['operation']);assert op['phase']=='complete';assert not state['protocols'];assert fetch().returncode!=0
    print('PASS protocol deletion removes both listeners, waits for offline B and completes on acknowledgement')
    print('ALL REAL-CORE INTEGRATION CHECKS PASSED')
