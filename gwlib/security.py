"""RFC 6238 TOTP, replay protection, setup confirmation and hashed recovery codes."""
import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from urllib.parse import quote,urlencode
from . import model,qrcode


def init(c):
    c.execute('CREATE TABLE IF NOT EXISTS auth_security(id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0, secret TEXT, pending_secret TEXT, pending_until REAL, last_counter INTEGER NOT NULL DEFAULT -1, recovery TEXT NOT NULL DEFAULT \'[]\')')
    c.execute('INSERT OR IGNORE INTO auth_security(id) VALUES(1)')

def totp(secret,counter,digits=6,algorithm='sha1'):
    key=base64.b32decode(secret+'='*((-len(secret))%8),casefold=True)
    mac=hmac.new(key,struct.pack('>Q',counter),algorithm).digest();offset=mac[-1]&15
    value=struct.unpack('>I',mac[offset:offset+4])[0]&0x7fffffff
    return str(value%(10**digits)).zfill(digits)

def matched_counter(secret,code,last=-1,now=None):
    if not re.fullmatch(r'\d{6}',str(code)):return None
    counter=int((time.time() if now is None else now)//30)
    for candidate in (counter,counter-1,counter+1):
        if candidate>=0 and candidate>last and hmac.compare_digest(totp(secret,candidate),str(code)):return candidate
    return None

def status(c):
    init(c);r=c.execute('SELECT * FROM auth_security WHERE id=1').fetchone()
    return {'enabled':bool(r['enabled']),'recovery_remaining':len(json.loads(r['recovery']))}

def consume(c,code):
    """Call under BEGIN IMMEDIATE: same OTP/recovery code cannot win two requests."""
    init(c);r=c.execute('SELECT * FROM auth_security WHERE id=1').fetchone()
    if not r['enabled']:return
    normalized=str(code).strip().replace('-','').replace(' ','').lower()
    recovery=json.loads(r['recovery']);hashed=model.digest(normalized)
    if len(normalized)==16 and hashed in recovery:
        recovery.remove(hashed);c.execute('UPDATE auth_security SET recovery=? WHERE id=1',(json.dumps(recovery),));return
    counter=matched_counter(r['secret'],str(code).strip(),r['last_counter'])
    if counter is None:raise PermissionError('动态码/恢复码无效、已使用或已过期')
    c.execute('UPDATE auth_security SET last_counter=? WHERE id=1',(counter,))

def begin_setup(c,username):
    init(c)
    if status(c)['enabled']:raise ValueError('已开启 2FA，不能覆盖现有密钥')
    secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
    c.execute('UPDATE auth_security SET pending_secret=?,pending_until=? WHERE id=1',(secret,time.time()+600))
    uri='otpauth://totp/'+quote('GW Panel:'+username,safe='')+'?'+urlencode({'secret':secret,'issuer':'GW Panel','algorithm':'SHA1','digits':6,'period':30})
    return {'secret':secret,'uri':uri,'svg':qrcode.svg(uri),'expires_in':600}

def confirm_setup(c,code,session):
    init(c);r=c.execute('SELECT * FROM auth_security WHERE id=1').fetchone()
    if r['enabled'] or not r['pending_secret'] or r['pending_until']<time.time():raise ValueError('2FA 设置已失效，请重新生成')
    counter=matched_counter(r['pending_secret'],code)
    if counter is None:raise PermissionError('动态码不正确')
    codes=[secrets.token_hex(8) for _ in range(10)]
    c.execute('UPDATE auth_security SET enabled=1,secret=pending_secret,pending_secret=NULL,pending_until=NULL,last_counter=?,recovery=? WHERE id=1',(counter,json.dumps([model.digest(x) for x in codes])))
    c.execute('DELETE FROM sessions WHERE hash!=?',(model.digest(session),));model.audit(c,'开启 2FA','web')
    return {'codes':['-'.join(x[i:i+4] for i in range(0,16,4)) for x in codes]}

def disable(c,code):
    consume(c,code);reset(c);model.audit(c,'关闭 2FA','web')

def reset(c):
    init(c);c.execute("UPDATE auth_security SET enabled=0,secret=NULL,pending_secret=NULL,pending_until=NULL,last_counter=-1,recovery='[]' WHERE id=1");c.execute('DELETE FROM sessions')
