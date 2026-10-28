"""All web protocol forms compile to official sing-box configuration."""
import base64
import copy
import ipaddress
import json
import re
import secrets
import subprocess
import uuid
from urllib.parse import urlencode,quote
from . import node

KINDS=['vless-reality','vless-http2-reality','tuic','trojan','hysteria2','anytls','shadowsocks','socks','direct',
       'vmess-tcp','vmess-http','vmess-quic','vmess-ws']+[f'{p}-{t}-tls' for p in ['vmess','vless','trojan'] for t in ['ws','h2','httpupgrade']]
METHODS=['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305','aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305','xchacha20-ietf-poly1305']

def text(v,name,default='',maxlen=253):
    v=str(v if v is not None else default).strip()
    if len(v)>maxlen or any(ord(c)<32 for c in v):raise ValueError(name+' 无效')
    return v

def host(v):
    v=text(v,'地址')
    try:ipaddress.ip_address(v);return v
    except ValueError:pass
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',v):raise ValueError('地址必须是 IP 或域名')
    return v

def tls_needed(kind):
    return kind in ('tuic','trojan','hysteria2','anytls','vmess-quic') or kind.endswith('-tls')

def normalize(raw,previous=None):
    previous=previous or {};s=copy.deepcopy(raw)
    s['name']=text(s.get('name'),'名称',maxlen=120)
    if not s['name']:raise ValueError('请输入协议名称')
    kind=s.get('kind')
    if kind not in KINDS:raise ValueError('不支持的协议')
    s['port']=node.port(s.get('port'))
    s['uuid']=s.get('uuid') or previous.get('uuid') or str(uuid.uuid4());uuid.UUID(s['uuid'])
    s['password']=s.get('password') or previous.get('password') or secrets.token_urlsafe(24)
    s['username']=text(s.get('username') or previous.get('username') or 'gw','用户名',maxlen=64)
    s['path']=text(s.get('path') or '/gw','路径',maxlen=256)
    if not s['path'].startswith('/'):raise ValueError('传输路径须以 / 开头')
    s['sni']=host(s.get('sni') or 'www.microsoft.com')
    if 'reality' in kind:
        if previous.get('private_key'):
            s['private_key']=previous['private_key'];s['public_key']=previous['public_key'];s['short_id']=previous['short_id']
        else:
            out=node.run([node.CORE,'generate','reality-keypair'],stdout=subprocess.PIPE).stdout.decode()
            pair=dict(line.split(': ',1) for line in out.strip().splitlines())
            s.update(private_key=pair['PrivateKey'],public_key=pair['PublicKey'],short_id=secrets.token_hex(4))
    if kind=='shadowsocks':
        method=s.get('method') or '2022-blake3-aes-128-gcm'
        if method not in METHODS:raise ValueError('不支持的 Shadowsocks 加密方式')
        s['method']=method
        if method.startswith('2022-'):
            n=16 if '128' in method else 32
            supplied=raw.get('password') or (previous.get('password') if previous.get('method')==method else '')
            s['password']=supplied or base64.b64encode(secrets.token_bytes(n)).decode()
            try:decoded=base64.b64decode(s['password'],validate=True)
            except Exception:raise ValueError('SS2022 密钥必须为 Base64')
            if len(decoded)!=n:raise ValueError(f'该 SS2022 密钥解码后须为 {n} 字节')
    if tls_needed(kind):
        mode=s.get('tls_mode') or 'selfsigned';s['tls_mode']=mode
        if mode=='acme':
            domain=host(s.get('domain') or '')
            try:ipaddress.ip_address(domain)
            except ValueError:pass
            else:raise ValueError('自动证书需要域名')
            s['domain']=domain;s['tls']={'enabled':True,'server_name':domain,'certificate_provider':{'type':'acme','domain':[domain]}}
        elif mode in ('selfsigned','pem'):
            if mode=='pem':
                cert=raw.get('certificate') or previous.get('certificate');key=raw.get('key') or previous.get('key')
                if not cert or not key:raise ValueError('请提供 PEM 证书及私钥')
            elif previous.get('tls_mode')=='selfsigned' and previous.get('certificate') and previous.get('sni')==s['sni']:
                cert,key=previous['certificate'],previous['key']
            else:
                pem=node.run([node.CORE,'generate','tls-keypair',s['sni']],stdout=subprocess.PIPE).stdout.decode()
                cert=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',pem,re.S).group(0)
                key=re.search(r'-----BEGIN .*?PRIVATE KEY-----.*?-----END .*?PRIVATE KEY-----',pem,re.S).group(0)
            if len(cert)>65536 or len(key)>16384:raise ValueError('证书过大')
            s['certificate']=cert;s['key']=key
            s['tls']={'enabled':True,'server_name':s['sni'],'certificate':cert.splitlines(),'key':key.splitlines()}
        else:raise ValueError('无效 TLS 证书方式')
    if kind=='direct':s['target']=host(s.get('target'));s['target_port']=node.port(s.get('target_port'))
    e=s.get('egress',{'type':'direct'});typ=e.get('type')
    if typ=='socks':
        e={'type':'socks','server':host(e.get('server')),'server_port':node.port(e.get('server_port')),'version':'5',
           'username':text(e.get('username',''),'SOCKS 用户名',maxlen=128),'password':str(e.get('password',''))}
        if len(e['password'])>1024:raise ValueError('SOCKS 密码过长')
    elif typ=='node':
        if not re.fullmatch('[0-9a-f]{16}',e.get('node','')):raise ValueError('请选择出口节点')
        e={'type':'node','node':e['node']}
    elif typ=='direct':e={'type':'direct'}
    else:raise ValueError('无效出口类型')
    s['egress']=e
    # Retain stable inter-node link key/port on edits; never trust client-supplied link credentials.
    s['link_key']=(previous.get('link_key') if previous.get('egress')==e else None) or base64.b64encode(secrets.token_bytes(16)).decode()
    s['link_port']=previous.get('link_port') if previous.get('egress')==e else None
    return s

def inbound(s,tag):
    k=s['kind'];typ=k.split('-')[0]
    if typ=='hysteria2':typ='hysteria2'
    b={'type':typ,'tag':tag,'listen':'::','listen_port':s['port']}
    if typ in ('vless','vmess'):b['users']=[{'uuid':s['uuid']}]
    elif typ=='tuic':b.update(users=[{'uuid':s['uuid'],'password':s['password']}],congestion_control='bbr')
    elif typ in ('trojan','hysteria2','anytls'):b['users']=[{'password':s['password']}]
    elif typ=='shadowsocks':b.update(method=s['method'],password=s['password'])
    elif typ=='socks':b['users']=[{'username':s['username'],'password':s['password']}]
    elif typ=='direct':b.update(override_address=s['target'],override_port=s['target_port'])
    if 'reality' in k:
        b['tls']={'enabled':True,'server_name':s['sni'],'reality':{'enabled':True,'handshake':{'server':s['sni'],'server_port':443},'private_key':s['private_key'],'short_id':[s['short_id']]}}
        if k=='vless-reality':b['users'][0]['flow']='xtls-rprx-vision'
        else:b['transport']={'type':'http'}
    elif tls_needed(k):b['tls']=copy.deepcopy(s['tls'])
    if typ in ('tuic','hysteria2') or k=='vmess-quic':b['tls']['alpn']=['h3']
    if k.startswith(('vmess-','vless-','trojan-')) and 'reality' not in k:
        transport=k.split('-')[1]
        if transport!='tcp':
            b['transport']={'type':'http' if transport=='h2' else transport}
            if transport in ('ws','h2','http','httpupgrade'):b['transport']['path']=s['path']
    return b

def client(s,ip):
    b=inbound(s,'client');b.pop('listen');b.pop('listen_port');b['server']=ip;b['server_port']=s['port']
    users=b.pop('users',[])
    if users:b.update(users[0])
    if 'tls' in b:
        b['tls'].pop('key',None);b['tls'].pop('certificate_provider',None)
        if s.get('tls_mode')=='acme':b['tls']['server_name']=s['domain']
        if 'reality' in s['kind']:
            b['tls']['reality']={'enabled':True,'public_key':s['public_key'],'short_id':s['short_id']}
            b['tls']['utls']={'enabled':True,'fingerprint':'chrome'}
    if s['kind']=='direct':return None
    return b

def share(s,ip):
    k=s['kind']
    if tls_needed(k) and s.get('tls_mode')=='selfsigned':return None # Use exported client JSON with the exact trusted certificate.
    typ=k.split('-')[0];addr=f'[{ip}]' if ':' in ip else ip
    label=quote(s['name'],safe='');q={};secret=s['uuid']
    if k=='shadowsocks':
        secret=base64.urlsafe_b64encode((s['method']+':'+s['password']).encode()).decode().rstrip('=')
        return f'ss://{secret}@{addr}:{s["port"]}#{label}'
    if typ=='vmess':
        c=client(s,ip);t=c.get('transport',{});d={'v':'2','ps':s['name'],'add':ip,'port':str(s['port']),'id':s['uuid'],'aid':'0','net':t.get('type','tcp'),'path':t.get('path',''),'tls':'tls' if 'tls' in c else '', 'sni':c.get('tls',{}).get('server_name','')}
        return 'vmess://'+base64.b64encode(json.dumps(d,ensure_ascii=False).encode()).decode()
    if typ in ('trojan','hysteria2','anytls'):secret=quote(s['password'],safe='')
    elif typ=='tuic':secret=s['uuid']+':'+quote(s['password'],safe='')
    elif typ in ('socks','direct'):return None
    if 'reality' in k:q={'encryption':'none','security':'reality','sni':s['sni'],'pbk':s['public_key'],'sid':s['short_id'],'fp':'chrome','flow':'xtls-rprx-vision' if k=='vless-reality' else '', 'type':'tcp' if k=='vless-reality' else 'http'}
    elif tls_needed(k):
        q={'security':'tls','sni':s.get('domain') if s.get('tls_mode')=='acme' else s['sni']}
        if k.endswith('-tls'):q.update(type={'h2':'http'}.get(k.split('-')[1],k.split('-')[1]),path=s['path'])
        if typ in ('tuic','hysteria2'):q['alpn']='h3'
    return f'{typ}://{secret}@{addr}:{s["port"]}?{urlencode(q)}#{label}'
