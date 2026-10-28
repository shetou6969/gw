"""Controller desired-state graph. SQLite transactions cover topology and cleanup goals."""
import copy
import hashlib
import ipaddress
import json
import secrets
import sqlite3
import time
from . import node,protocols
DB=node.STATE/'controller-v2.sqlite3'

def digest(s):return hashlib.sha256(s.encode()).hexdigest()
def address(ip):return str(ipaddress.ip_address(ip).ipv4_mapped or ipaddress.ip_address(ip)) if isinstance(ipaddress.ip_address(ip),ipaddress.IPv6Address) else str(ipaddress.ip_address(ip))

def connect():
    c=sqlite3.connect(DB,timeout=30);c.row_factory=sqlite3.Row;c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA foreign_keys=ON');return c

def init():
    node.STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,name TEXT NOT NULL,ip TEXT NOT NULL,join_ip TEXT NOT NULL,phase TEXT NOT NULL DEFAULT 'pending',join_hash TEXT,join_expiry REAL,token_hash TEXT,seen REAL,info TEXT NOT NULL DEFAULT '{}',status TEXT NOT NULL DEFAULT '',desired TEXT,revision INTEGER NOT NULL DEFAULT 0,applied INTEGER NOT NULL DEFAULT 0,deps TEXT NOT NULL DEFAULT '{}',settings TEXT NOT NULL DEFAULT '{}',command TEXT,command_id INTEGER NOT NULL DEFAULT 0,command_ack INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS protocols(id TEXT PRIMARY KEY,node_id TEXT NOT NULL,spec TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,deleted INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,kind TEXT NOT NULL,target TEXT NOT NULL,goals TEXT NOT NULL,phase TEXT NOT NULL DEFAULT 'pending',at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(at REAL NOT NULL,event TEXT NOT NULL,target TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS login_limits(ip TEXT PRIMARY KEY,count INTEGER NOT NULL,until REAL NOT NULL);
        ''')
    with connect() as c:
        from . import security
        security.init(c)
    DB.chmod(0o600)

def audit(c,event,target):c.execute('INSERT INTO audit VALUES(?,?,?)',(time.time(),event,target))
def begin(c):c.execute('BEGIN IMMEDIATE')

def register(c,b):
    name=protocols.text(b.get('name'),'名称',maxlen=120);ip=address(b['ip']);join_ip=address(b.get('join_ip') or ip)
    if not name:raise ValueError('请输入节点名称')
    if c.execute("SELECT 1 FROM nodes WHERE ip=? AND phase!='deleted'",(ip,)).fetchone():raise ValueError('该 IP 已登记')
    lo=node.port(b.get('relay_min',20000));hi=node.port(b.get('relay_max',29999))
    if hi<lo:raise ValueError('内部转发端口范围无效')
    ident=secrets.token_hex(8);secret=secrets.token_urlsafe(32)
    c.execute('INSERT INTO nodes(id,name,ip,join_ip,join_hash,join_expiry,settings) VALUES(?,?,?,?,?,?,?)',(ident,name,ip,join_ip,digest(secret),time.time()+1800,json.dumps({'relay_min':lo,'relay_max':hi,'log_level':'info','dns':''})))
    audit(c,'登记节点',ident);return {'id':ident,'secret':secret,'expires_in':1800}

def reissue(c,ident):
    r=c.execute('SELECT * FROM nodes WHERE id=?',(ident,)).fetchone()
    if not r or r['phase'] not in ('pending','active'):raise ValueError('节点状态不允许重新接入')
    if r['phase']=='active':raise ValueError('已接入节点不能直接重置，请先删除并完成远端清理')
    secret=secrets.token_urlsafe(32);c.execute('UPDATE nodes SET join_hash=?,join_expiry=? WHERE id=?',(digest(secret),time.time()+1800,ident));return {'id':ident,'secret':secret,'expires_in':1800}

def enroll(c,b,peer):
    r=c.execute('SELECT * FROM nodes WHERE id=?',(b.get('id'),)).fetchone()
    import hmac
    if r and r['phase']=='active' and address(peer)==r['join_ip'] and hmac.compare_digest(r['token_hash'] or '',digest(b.get('credential',''))):return {'approved':True,'id':r['id'],'version':'1.14.4'}
    if not r or r['phase']!='pending' or r['join_expiry']<time.time() or address(peer)!=r['join_ip'] or not hmac.compare_digest(r['join_hash'] or '',digest(b.get('secret',''))):raise PermissionError('未登记、IP 不匹配、接入码失效或已使用')
    credential=b.get('credential','')
    if len(credential)<40 or len(credential)>200:raise ValueError('节点凭据无效')
    c.execute("UPDATE nodes SET phase='active',token_hash=?,join_hash=NULL,join_expiry=NULL,status='已认证，等待安装上线' WHERE id=?",(digest(credential),r['id']))
    audit(c,'节点接入认证通过',r['id']);return {'approved':True,'id':r['id'],'version':'1.14.4'}

def rows(c):return {r['id']:dict(r) for r in c.execute("SELECT * FROM nodes WHERE phase!='deleted'")}
def entries(c):return [dict(r) for r in c.execute('SELECT * FROM protocols WHERE deleted=0')]

def graph(c):
    ns=rows(c);ps=entries(c);deps={i:set() for i in ns}
    for p in ps:
        s=json.loads(p['spec']);e=s['egress']
        if e['type']=='node':
            if e['node']==p['node_id']:raise ValueError('本机出口请直接选择本机')
            if e['node'] not in ns or ns[e['node']]['phase']!='active':raise ValueError('出口节点未接入或正在删除')
            deps[p['node_id']].add(e['node'])
    visiting=set();visited=set()
    def visit(n):
        if n in visiting:raise ValueError('出口依赖形成环，请改用无环拓扑')
        if n in visited:return
        visiting.add(n)
        for d in deps[n]:visit(d)
        visiting.remove(n);visited.add(n)
    for n in ns:visit(n)
    return ns,ps,deps

def build(c):
    ns,ps,deps=graph(c);configs={};used={i:set() for i in ns}
    for n,r in ns.items():
        settings=json.loads(r['settings']);base={'log':{'level':settings.get('log_level','info'),'timestamp':True},'outbounds':[{'type':'direct','tag':'direct'}]}
        dns=settings.get('dns')
        if dns:base.update(dns={'servers':[{'type':'udp','tag':'dns','server':address(dns)}]},route={'default_domain_resolver':'dns'})
        configs[n]={'base':base,'files':{}}
    for p in ps:
        s=json.loads(p['spec']);owner=p['node_id'];port=s['port']
        if owner not in ns or ns[owner]['phase']!='active':raise ValueError('协议所在节点不可用')
        if port in used[owner]:raise ValueError('节点协议监听端口冲突')
        used[owner].add(port)
    # Reserve existing internal ports before allocating new ones.
    for p in ps:
        s=json.loads(p['spec']);e=s['egress']
        if e['type']=='node' and s.get('link_port'):
            if s['link_port'] in used[e['node']]:raise ValueError('协议端口与内部转发端口冲突')
            used[e['node']].add(s['link_port'])
    for p in ps:
        s=json.loads(p['spec']);pid=p['id'];owner=p['node_id'];tag='p-'+pid;outtag='out-'+pid;e=s['egress']
        out=copy.deepcopy(e)
        if e['type']=='node':
            dest=e['node'];settings=json.loads(ns[dest]['settings']);port=s.get('link_port')
            if not port:
                port=next((i for i in range(settings['relay_min'],settings['relay_max']+1) if i not in used[dest]),None)
                if not port:raise ValueError('出口节点内部转发端口已用尽')
                used[dest].add(port);s['link_port']=port;c.execute('UPDATE protocols SET spec=? WHERE id=?',(json.dumps(s),pid))
            remote='link-'+pid
            listener={'type':'shadowsocks','tag':remote,'listen':'::','listen_port':port,'method':'2022-blake3-aes-128-gcm','password':s['link_key']}
            # A local agent may poll over loopback while relay traffic exits via its public IP.
            src=ns[owner]['join_ip']
            if src in ('127.0.0.1','::1') and ns[owner]['ip']!=src:src=ns[owner]['ip']
            prefix=128 if ':' in src else 32
            configs[dest]['files'][remote+'.json']={'inbounds':[listener],'route':{'rules':[
                {'inbound':[remote],'source_ip_cidr':[f'{src}/{prefix}'],'action':'route','outbound':'direct'},
                {'inbound':[remote],'action':'reject'}]}}
            out={'type':'shadowsocks','server':ns[dest]['ip'],'server_port':port,'method':listener['method'],'password':s['link_key']}
        out['tag']=outtag
        configs[owner]['files'][tag+'.json']={'inbounds':[protocols.inbound(s,tag)],'outbounds':[out],'route':{'rules':[{'inbound':[tag],'action':'route','outbound':outtag}]}}
    return ns,ps,deps,configs

def reconcile(c):
    ns,ps,deps,configs=build(c)
    changed={}
    for ident,bundle in configs.items():
        encoded=json.dumps(bundle,sort_keys=True)
        if ns[ident]['desired']!=encoded:
            node.check(bundle)
            ns[ident]['revision']+=1
            c.execute('UPDATE nodes SET desired=?,revision=? WHERE id=?',(encoded,ns[ident]['revision'],ident));changed[ident]=ns[ident]['revision']
    for ident in ns:
        requirements={d:ns[d]['revision'] for d in deps[ident]}
        c.execute('UPDATE nodes SET deps=? WHERE id=?',(json.dumps(requirements),ident))
    return changed

def save_protocol(c,b):
    owner=b['node_id'];r=c.execute("SELECT * FROM nodes WHERE id=? AND phase='active'",(owner,)).fetchone()
    if not r:raise ValueError('请先安装节点并通过接入认证')
    pid=b.get('id') or secrets.token_hex(8)
    old=c.execute('SELECT * FROM protocols WHERE id=? AND deleted=0',(pid,)).fetchone()
    if b.get('id') and not old:raise ValueError('协议不存在')
    if old and int(b.get('expected_revision',-1))!=old['revision']:raise ValueError('协议已被其他操作修改，请重新打开编辑')
    if old and old['node_id']!=owner:raise ValueError('不能直接迁移协议所在节点')
    spec=protocols.normalize(b['spec'],json.loads(old['spec']) if old else None)
    c.execute('INSERT INTO protocols(id,node_id,spec) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET spec=excluded.spec,revision=protocols.revision+1',(pid,owner,json.dumps(spec)))
    goals=reconcile(c);op=operation(c,'publish',pid,goals);audit(c,'保存协议',pid);return {'id':pid,'operation':op}

def operation(c,kind,target,goals):
    ident=secrets.token_hex(8);c.execute('INSERT INTO operations(id,kind,target,goals,at) VALUES(?,?,?,?,?)',(ident,kind,target,json.dumps(goals),time.time()));complete_operations(c);return ident

def remove_protocol(c,ident):
    r=c.execute('SELECT * FROM protocols WHERE id=? AND deleted=0',(ident,)).fetchone()
    if not r:raise ValueError('协议不存在')
    c.execute('UPDATE protocols SET deleted=1 WHERE id=?',(ident,));goals=reconcile(c)
    audit(c,'删除协议并清理两端',ident);return operation(c,'delete-protocol',ident,goals)

def remove_node(c,ident):
    r=c.execute('SELECT * FROM nodes WHERE id=?',(ident,)).fetchone()
    if not r or r['phase'] in ('deleted','deleting'):raise ValueError('节点不存在或已在清理中')
    for p in entries(c):
        s=json.loads(p['spec'])
        if p['node_id']==ident or s['egress'].get('node')==ident:c.execute('UPDATE protocols SET deleted=1 WHERE id=?',(p['id'],))
    was_pending=r['phase']=='pending'
    c.execute("UPDATE nodes SET phase=?,join_hash=NULL,status=? WHERE id=?",('deleted' if was_pending else 'deleting','未接入，无远端配置' if was_pending else '等待远端清理',ident))
    goals=reconcile(c)
    if not was_pending:goals[ident]='purged'
    audit(c,'删除节点及引用协议',ident);return operation(c,'delete-node',ident,goals)

def complete_operations(c):
    for op in c.execute("SELECT * FROM operations WHERE phase='pending'").fetchall():
        goals=json.loads(op['goals']);complete=True
        for ident,wanted in goals.items():
            r=c.execute('SELECT phase,applied FROM nodes WHERE id=?',(ident,)).fetchone()
            if not r or (wanted=='purged' and r['phase']!='deleted') or (wanted!='purged' and r['phase']!='deleted' and r['applied']<wanted):complete=False
        if complete:
            c.execute("UPDATE operations SET phase='complete' WHERE id=?",(op['id'],))
            if op['kind']=='delete-protocol':c.execute('DELETE FROM protocols WHERE id=? AND deleted=1',(op['target'],))
            if op['kind']=='delete-node':
                for p in c.execute('SELECT * FROM protocols WHERE deleted=1').fetchall():
                    s=json.loads(p['spec'])
                    if p['node_id']==op['target'] or s['egress'].get('node')==op['target']:c.execute('DELETE FROM protocols WHERE id=?',(p['id'],))


def poll(c,b,token,peer):
    import hmac
    r=c.execute('SELECT * FROM nodes WHERE id=?',(b.get('id'),)).fetchone()
    if not r or not r['token_hash'] or not hmac.compare_digest(r['token_hash'],digest(token)) or address(peer)!=r['join_ip']:raise PermissionError('节点认证失败')
    if r['phase']=='deleted':return {'terminate':True}
    applied=int(b.get('applied',0));ack=int(b.get('command_ack',0))
    if not 0<=applied<=r['revision'] or not 0<=ack<=r['command_id']:raise ValueError('回执无效')
    c.execute('UPDATE nodes SET seen=?,info=?,status=?,applied=?,command_ack=? WHERE id=?',(time.time(),json.dumps(b.get('info',{})),str(b.get('status',''))[:500],applied,ack,r['id']))
    if r['phase']=='deleting':
        if b.get('purged'):
            c.execute("UPDATE nodes SET phase='deleted',desired=NULL,info='{}',status='远端配置已清理' WHERE id=?",(r['id'],));complete_operations(c)
            return {'terminate':True}
        return {'purge':True}
    if r['phase']!='active':raise PermissionError('节点未激活')
    complete_operations(c);waiting=[]
    for dest,rev in json.loads(r['deps']).items():
        dep=c.execute('SELECT applied,phase FROM nodes WHERE id=?',(dest,)).fetchone()
        if not dep or dep['phase']!='active' or dep['applied']<rev:waiting.append(dest)
    return {'revision':r['revision'],'desired':json.loads(r['desired']) if r['desired'] and applied<r['revision'] and not waiting else None,
            'waiting':waiting,'command_id':r['command_id'],'command':json.loads(r['command']) if r['command'] and ack<r['command_id'] else None}
