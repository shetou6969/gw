"""Agent enrolment uses an out-of-band TLS fingerprint before sending any secret."""
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import ssl
import subprocess
import time
from . import node,version


def request(cfg,path,body):
    # A pinned SHA256 certificate is the trust anchor for self-signed and public certificates.
    # No HTTP bytes or credentials are sent before verifying the peer's certificate.
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    connection=http.client.HTTPSConnection(cfg['host'],int(cfg['port']),context=context,timeout=30)
    try:
        connection.connect();actual=hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(actual,cfg['fingerprint']):raise ssl.SSLError('主控证书指纹不匹配，未发送认证信息')
        headers={'Content-Type':'application/json'}
        if cfg.get('credential'):headers['Authorization']='Bearer '+cfg['credential']
        connection.request('POST',path,body=json.dumps(body).encode(),headers=headers)
        response=connection.getresponse();raw=response.read(2*1024*1024+1)
        if len(raw)>2*1024*1024:raise ValueError('主控响应过大')
        value=json.loads(raw)
        if response.status!=200:raise PermissionError(value.get('error','主控拒绝接入'))
        return value
    finally:connection.close()

def join(host,port,code):
    parts=code.strip().split('.')
    if len(parts)!=3 or len(parts[2])!=64:raise ValueError('接入码格式无效，请从面板完整复制')
    ident,secret,fingerprint=parts
    int(fingerprint,16)
    cfg={'host':host,'port':node.port(port),'id':ident,'fingerprint':fingerprint,'credential':secrets.token_urlsafe(48)}
    node.atomic(node.STATE/'enrollment-pending.json',{'config':cfg,'secret':secret})
    return finish_enrollment(cfg,secret)

def finish_enrollment(cfg,secret):
    try:result=request(cfg,'/agent/enroll',{'id':cfg['id'],'secret':secret,'credential':cfg['credential']})
    except PermissionError:
        (node.STATE/'enrollment-pending.json').unlink(missing_ok=True)
        raise
    if not result.get('approved'):raise PermissionError('主控未批准')
    # Save only after the controller verifies registration, source IP and the one-time key.
    node.atomic(node.STATE/'agent.json',cfg);(node.STATE/'enrollment-pending.json').unlink(missing_ok=True);return result

_cpu_previous=None

def info():
    global _cpu_previous
    data={'agent_version':version.current(),'api_version':version.API_VERSION,'hostname':socket.gethostname(),'os':platform.platform(),'arch':platform.machine(),'cpu_count':os.cpu_count(),'load':list(os.getloadavg())}
    try:
        values=list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:]));total=sum(values);idle=values[3]+(values[4] if len(values)>4 else 0)
        if _cpu_previous and total>_cpu_previous[0]:data['cpu_percent']=round(100*(1-(idle-_cpu_previous[1])/(total-_cpu_previous[0])),1)
        _cpu_previous=(total,idle)
        mem={l.split(':')[0]:int(l.split()[1])*1024 for l in Path('/proc/meminfo').read_text().splitlines()}
        data.update(memory_total=mem['MemTotal'],memory_used=mem['MemTotal']-mem.get('MemAvailable',mem['MemFree']),uptime=int(float(Path('/proc/uptime').read_text().split()[0])))
        rx=tx=0
        for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
            nic,values=line.split(':');values=values.split()
            if nic.strip()!='lo':rx+=int(values[0]);tx+=int(values[8])
        data.update(rx_bytes=rx,tx_bytes=tx)
    except (OSError,ValueError,KeyError):pass
    disk=shutil.disk_usage('/');data.update(disk_total=disk.total,disk_used=disk.used)
    try:data['core_version']=node.run([node.CORE,'version'],stdout=subprocess.PIPE).stdout.decode().splitlines()[0]
    except Exception:data['core_version']='未安装'
    try:data['service']=subprocess.run(['systemctl','is-active',node.SERVICE],capture_output=True,text=True,timeout=5).stdout.strip()
    except Exception:data['service']='未知'
    return data

def command(job):
    typ=job['type']
    if typ in ('start','stop','restart'):node.service(typ);return '服务操作完成：'+typ
    if typ=='logs':
        result=node.run(['journalctl','-u',node.SERVICE,'-n','60','--no-pager','-o','short-iso'],stdout=subprocess.PIPE).stdout.decode(errors='replace')
        return result[-16000:]
    if typ=='bbr':
        node.run(['modprobe','tcp_bbr'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        available=Path('/proc/sys/net/ipv4/tcp_available_congestion_control').read_text().split()
        if 'bbr' not in available:raise ValueError('内核不支持 BBR')
        if not (node.STATE/'bbr-before.json').exists():
            before={key:node.run(['sysctl','-n',key],stdout=subprocess.PIPE).stdout.decode().strip() for key in ['net.core.default_qdisc','net.ipv4.tcp_congestion_control']}
            node.atomic(node.STATE/'bbr-before.json',before)
        Path('/etc/sysctl.d/99-gw-bbr.conf').write_text('net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n')
        node.run(['sysctl','-p','/etc/sysctl.d/99-gw-bbr.conf'],stdout=subprocess.PIPE,stderr=subprocess.PIPE);return 'BBR 已启用'
    if typ=='upgrade':
        from .download import install
        install('core',job['version'])
        try:node.service('restart')
        except Exception:
            old=Path(str(node.CORE)+'.previous')
            if old.exists():shutil.copy2(old,node.CORE);node.service('restart')
            raise
        return '核心已升级：'+job['version']
    raise ValueError('不支持的指令')

def step(cfg,state):
    status=state.get('status','等待同步');report={} if state.get('purged') else info()
    if state.get('command_result'):report['command_result']=state['command_result']
    response=request(cfg,'/agent/poll',{'id':cfg['id'],'applied':state.get('applied',0),'command_ack':state.get('command_ack',0),'purged':state.get('purged',False),'status':status,'info':report})
    if response.get('terminate'):
        node.finish_cleanup();return False
    if response.get('purge'):
        node.cleanup();state.update(purged=True,status='远端配置已清理，等待主控确认')
    else:
        if response.get('desired') is not None:
            try:node.apply_bundle(response['desired']);state.update(applied=response['revision'],status='配置已应用')
            except Exception as e:state['status']='配置未应用，保留旧配置：'+type(e).__name__
        elif response.get('waiting'):state['status']='等待出口节点先完成配置'
        if response.get('command'):
            try:state['command_result']=command(response['command']);state['status']='操作完成'
            except Exception as e:state['command_result']='执行失败：'+type(e).__name__;state['status']='操作失败'
            state['command_ack']=response['command_id']
    node.atomic(node.STATE/'agent-state.json',state);return True

def loop():
    cfg=json.loads((node.STATE/'agent.json').read_text());path=node.STATE/'agent-state.json'
    state=json.loads(path.read_text()) if path.exists() else {'applied':0,'command_ack':0,'status':'等待同步'}
    if not state.get('purged') and node.recover():node.service('restart')
    while True:
        try:
            if not step(cfg,state):return
        except Exception as e:print('主控通信/清理失败，稍后重试：'+type(e).__name__,flush=True)
        time.sleep(10)
