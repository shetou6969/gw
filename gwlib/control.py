"""Separate HTTPS web and agent listeners; account login and audit API."""
import hashlib
import hmac
import html
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import threading
import time
from . import node,model,protocols,security,version,qrcode

SETTINGS=node.STATE/'controller.json'

def password_hash(password,salt):return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),600000).hex()
def set_password(username,password):
    if not username or len(username)>64 or len(password)<12:raise ValueError('账号不能为空，密码至少 12 位')
    salt=secrets.token_hex(16);node.atomic(node.STATE/'account.json',{'username':username,'salt':salt,'hash':password_hash(password,salt)})

def verify(username,password):
    a=json.loads((node.STATE/'account.json').read_text())
    valid=hmac.compare_digest(password_hash(password,a['salt']),a['hash'])
    return hmac.compare_digest(username.encode(),a['username'].encode()) and valid

def throttle(peer):
    with model.connect() as c:
        model.begin(c);r=c.execute('SELECT * FROM login_limits WHERE ip=?',(peer,)).fetchone();now=time.time()
        if r and r['until']>now and r['count']>=5:raise PermissionError('尝试过多，请稍后再试')
        count=r['count']+1 if r and r['until']>now else 1
        c.execute('INSERT OR REPLACE INTO login_limits VALUES(?,?,?)',(peer,count,now+60));c.execute('DELETE FROM login_limits WHERE until<?',(now-3600,))

def login(b,peer):
    if len(str(b.get('password','')))>1024:raise PermissionError('登录失败')
    throttle(peer)
    token=secrets.token_urlsafe(32)
    with model.connect() as c:
        model.begin(c)
        if not verify(str(b.get('username','')),str(b.get('password',''))):raise PermissionError('账号或密码错误')
        security.consume(c,b.get('otp',''))
        c.execute('DELETE FROM login_limits WHERE ip=?',(peer,));c.execute('DELETE FROM sessions WHERE expires<?',(time.time(),));c.execute('INSERT INTO sessions VALUES(?,?)',(model.digest(token),time.time()+28800));model.audit(c,'管理员登录','web')
    return {'token':token}

def fingerprint():
    settings=json.loads(SETTINGS.read_text());pem=Path(settings['cert']).read_text()
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()

def enrollment(result):
    cfg=json.loads(SETTINGS.read_text());result['code']=result['id']+'.'+result.pop('secret')+'.'+fingerprint()
    result['host']=cfg['public_host'];result['port']=cfg['agent_port'];return result

def view(c):
    ns=[]
    for r in c.execute("SELECT * FROM nodes WHERE phase!='deleted' ORDER BY name"):
        n=dict(r)
        for key in ('join_hash','join_expiry','token_hash','desired','command'):n.pop(key,None)
        for key in ('settings','info','deps'):n[key]=json.loads(n[key])
        n['online']=bool(n['seen'] and time.time()-n['seen']<45)
        ns.append(n)
    ps=[]
    for r in c.execute('SELECT * FROM protocols WHERE deleted=0'):
        p=dict(r);s=json.loads(p.pop('spec'));p['name']=s['name'];p['kind']=s['kind'];p['port']=s['port'];p['egress']=s['egress']['type'];p['target']=s['egress'].get('node');p['link_port']=s.get('link_port');ps.append(p)
    return {'controller_version':version.current(),'api_version':version.API_VERSION,'security':security.status(c),'nodes':ns,'protocols':ps,'operations':[dict(r) for r in c.execute('SELECT * FROM operations ORDER BY at DESC LIMIT 100')],
            'audit':[dict(r) for r in c.execute('SELECT * FROM audit ORDER BY at DESC LIMIT 100')],'kinds':protocols.KINDS,'methods':protocols.METHODS}

class Handler(BaseHTTPRequestHandler):
    server_version='GW'
    def log_message(self,*args):pass
    def reply(self,status,value,as_html=False):
        raw=value.encode() if as_html else json.dumps(value,ensure_ascii=False).encode()
        self.send_response(status);self.send_header('Content-Type','text/html; charset=utf-8' if as_html else 'application/json; charset=utf-8');self.send_header('Content-Length',str(len(raw)))
        for key,value in {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' blob:; frame-ancestors 'none'"}.items():self.send_header(key,value)
        self.end_headers();self.wfile.write(raw)
    def body(self):
        n=int(self.headers.get('Content-Length','0'))
        if not 0<n<=2*1024*1024:raise ValueError('请求体大小无效')
        b=json.loads(self.rfile.read(n))
        if not isinstance(b,dict):raise ValueError('需要 JSON 对象')
        return b
    def token(self):
        s=self.headers.get('Authorization','');return s[7:] if s.startswith('Bearer ') else ''
    def admin(self):
        with model.connect() as c:r=c.execute('SELECT 1 FROM sessions WHERE hash=? AND expires>?',(model.digest(self.token()),time.time())).fetchone()
        if not r:raise PermissionError('请重新登录')
    def wrap(self,fn):
        try:fn()
        except PermissionError as e:self.reply(401,{'error':str(e)})
        except (ValueError,KeyError,TypeError) as e:self.reply(400,{'error':str(e)})
        except Exception as e:
            # No raw config/private key in HTTP or logs.
            print('请求失败：'+type(e).__name__,flush=True);self.reply(500,{'error':'操作未提交：配置校验或服务处理失败，请检查所填协议参数'})
    def do_GET(self):self.wrap(self.get)
    def do_POST(self):self.wrap(self.post)
    def get(self):
        if self.server.surface!='web':return self.reply(404,{'error':'此端口仅用于节点接入'})
        if self.path=='/healthz':return self.reply(200,{'version':version.current(),'api_version':version.API_VERSION})
        if self.path=='/':return self.reply(200,(Path(__file__).parent/'panel.html').read_text(),True)
        self.admin()
        with model.connect() as c:
            if self.path=='/api/state':return self.reply(200,view(c))
            if self.path.startswith('/api/protocol/'):
                pid=self.path.rsplit('/',1)[-1];r=c.execute('SELECT * FROM protocols WHERE id=? AND deleted=0',(pid,)).fetchone()
                if not r:raise ValueError('协议不存在')
                p=dict(r);p['spec']=json.loads(p['spec']);return self.reply(200,p)
            if self.path.startswith('/api/export/'):
                pid=self.path.rsplit('/',1)[-1];r=c.execute('SELECT p.*,n.ip FROM protocols p JOIN nodes n ON n.id=p.node_id WHERE p.id=? AND p.deleted=0',(pid,)).fetchone()
                if not r:raise ValueError('协议不存在')
                s=json.loads(r['spec']);out=protocols.client(s,r['ip']);url=protocols.share(s,r['ip'])
                return self.reply(200,{'name':s['name'],'url':url,'qr_svg':qrcode.svg(url) if url else None,'outbound':out,'client':{'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':1080}], 'outbounds':[out]} if out else None})
        self.reply(404,{'error':'不存在'})
    def post(self):
        if self.server.surface=='agent':
            b=self.body()
            with model.connect() as c:
                model.begin(c)
                if self.path=='/agent/enroll':result=model.enroll(c,b,self.client_address[0])
                elif self.path=='/agent/poll':result=model.poll(c,b,self.token(),self.client_address[0])
                else:return self.reply(404,{'error':'此端口仅用于节点接入'})
            return self.reply(200,result)
        if self.path=='/api/login':return self.reply(200,login(self.body(),self.client_address[0]))
        self.admin();b=self.body()
        if self.path.startswith('/api/2fa/'):
            throttle(self.client_address[0])
            account=json.loads((node.STATE/'account.json').read_text())
            if not verify(account['username'],str(b.get('password',''))):raise PermissionError('当前密码错误')
            with model.connect() as c:
                model.begin(c)
                if self.path=='/api/2fa/begin':result=security.begin_setup(c,account['username'])
                elif self.path=='/api/2fa/confirm':result=security.confirm_setup(c,str(b.get('otp','')),self.token())
                elif self.path=='/api/2fa/disable':security.disable(c,str(b.get('otp','')));result={'ok':True}
                else:raise ValueError('未知 2FA 操作')
            return self.reply(200,result)
        if self.path=='/api/password':
            throttle(self.client_address[0])
            if not verify(b['username'],b['current']):raise PermissionError('当前账号密码错误')
            if len(b['password'])<12:raise ValueError('新密码至少 12 位')
            with model.connect() as c:
                model.begin(c);security.consume(c,b.get('otp',''))
                set_password(b['username'],b['password']);c.execute('DELETE FROM sessions');model.audit(c,'修改管理员密码','web')
            return self.reply(200,{'ok':True})
        if self.path=='/api/logout':
            with model.connect() as c:c.execute('DELETE FROM sessions WHERE hash=?',(model.digest(self.token()),))
            return self.reply(200,{'ok':True})
        with model.connect() as c:
            model.begin(c)
            if self.path=='/api/node/add':result=enrollment(model.register(c,b))
            elif self.path=='/api/node/reissue':result=enrollment(model.reissue(c,b['id']))
            elif self.path=='/api/node/delete':result={'operation':model.remove_node(c,b['id'])}
            elif self.path=='/api/protocol/save':result=model.save_protocol(c,b)
            elif self.path=='/api/protocol/delete':result={'operation':model.remove_protocol(c,b['id'])}
            elif self.path=='/api/node/settings':
                r=c.execute("SELECT * FROM nodes WHERE id=? AND phase='active'",(b['id'],)).fetchone()
                if not r:raise ValueError('节点不可用')
                settings=json.loads(r['settings']);level=b.get('log_level','info')
                if level not in ('trace','debug','info','warn','error','fatal'):raise ValueError('日志等级无效')
                settings.update(log_level=level,dns=model.address(b['dns']) if b.get('dns') else '')
                c.execute('UPDATE nodes SET settings=? WHERE id=?',(json.dumps(settings),b['id']));goals=model.reconcile(c);result={'operation':model.operation(c,'settings',b['id'],goals)}
            elif self.path=='/api/node/command':
                r=c.execute("SELECT * FROM nodes WHERE id=? AND phase='active'",(b['id'],)).fetchone()
                if not r:raise ValueError('节点不可用')
                if r['command_id']!=r['command_ack']:raise ValueError('前一操作尚未回执')
                command=b.get('command')
                if command not in ('start','stop','restart','logs','bbr','upgrade'):raise ValueError('不支持的操作')
                payload={'type':command}
                if command=='upgrade':
                    import re
                    version=str(b.get('version',''))
                    if not re.fullmatch(r'\d+\.\d+\.\d+',version):raise ValueError('请输入明确的稳定版本号')
                    payload['version']=version
                c.execute('UPDATE nodes SET command=?,command_id=command_id+1 WHERE id=?',(json.dumps(payload),b['id']));model.audit(c,'节点操作 '+command,b['id']);result={'ok':True}
            else:return self.reply(404,{'error':'不存在'})
        self.reply(200,result)

class Server(ThreadingHTTPServer):
    daemon_threads=True
    surface='web'
    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(64)
        super().__init__(*args,**kwargs)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):request.close();return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:
            if isinstance(request,ssl.SSLSocket):request.do_handshake()
            super().process_request_thread(request,address)
        except (OSError,ssl.SSLError):self.shutdown_request(request)
        finally:self.slots.release()
    def get_request(self):
        sock,addr=super().get_request();sock.settimeout(15)
        if getattr(self,'tls_context',None):
            try:sock=self.tls_context.wrap_socket(sock,server_side=True,do_handshake_on_connect=False)
            except Exception:sock.close();raise
        return sock,addr

def serve():
    model.init();cfg=json.loads(SETTINGS.read_text());ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(cfg['cert'],cfg['key'])
    servers=[]
    for surface,port in [('web',cfg['web_port']),('agent',cfg['agent_port'])]:
        server=Server((cfg.get('bind','0.0.0.0'),port),Handler);server.surface=surface;server.tls_context=ctx;servers.append(server)
    threading.Thread(target=servers[1].serve_forever,daemon=True).start();servers[0].serve_forever()
