"""Owned node configuration: atomic file switch, validation, rollback and decommission."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

STATE=Path(os.environ.get('GW_STATE','/etc/gw'))
ROOT=Path(os.environ.get('GW_NODE_ROOT','/var/lib/gw-node'))
CORE=Path(os.environ.get('GW_CORE','/opt/gw/bin/sing-box'))
SERVICE='gw-proxy'

def run(args,**kw):return subprocess.run([str(a) for a in args],check=True,timeout=90,**kw)
def port(v):
    n=int(v)
    if not 1<=n<=65535:raise ValueError('端口必须为 1–65535')
    return n

def atomic(path,obj):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,tmp=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(obj,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def validate(bundle):
    if not isinstance(bundle,dict) or not isinstance(bundle.get('base'),dict) or not isinstance(bundle.get('files'),dict):raise ValueError('配置格式无效')
    for name,c in bundle['files'].items():
        if not isinstance(name,str) or name!=Path(name).name or not name.endswith('.json') or name.startswith('.') or not isinstance(c,dict):raise ValueError('配置路径无效')

def check(bundle):
    validate(bundle)
    with tempfile.TemporaryDirectory() as tmp:
        tmp=Path(tmp);(tmp/'conf').mkdir();atomic(tmp/'base.json',bundle['base'])
        for n,c in bundle['files'].items():atomic(tmp/'conf'/n,c)
        run([CORE,'check','-c',tmp/'base.json','-C',tmp/'conf'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)

def service(action):
    if action not in ('restart','start','stop'):raise ValueError('不支持的服务操作')
    run(['systemctl',action,SERVICE],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if action!='stop':time.sleep(.5);run(['systemctl','is-active','--quiet',SERVICE])

def initialize():
    if ROOT.exists() and any(ROOT.iterdir()) and not (ROOT/'.gw-owned').exists():raise ValueError('目标目录已有非 GW 数据，拒绝接管')
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700);(ROOT/'conf').mkdir(exist_ok=True)
    (ROOT/'.gw-owned').touch(mode=0o600)
    if not (ROOT/'config.json').exists():atomic(ROOT/'config.json',{'outbounds':[{'type':'direct','tag':'direct'}]})

def snapshot():
    return {'base':json.loads((ROOT/'config.json').read_text()),'files':{p.name:json.loads(p.read_text()) for p in (ROOT/'conf').glob('*.json')}}

def recover():
    backup=ROOT/'.transaction'
    if backup.exists():
        if (ROOT/'conf').exists():shutil.rmtree(ROOT/'conf')
        shutil.copytree(backup/'conf',ROOT/'conf');shutil.copy2(backup/'config.json',ROOT/'config.json')
        shutil.rmtree(backup)
        return True
    return False

def apply_bundle(bundle):
    validate(bundle)
    if not (ROOT/'.gw-owned').exists():raise ValueError('拒绝修改非 GW 管理目录')
    with open(ROOT/'.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);recover();check(bundle)
        with tempfile.TemporaryDirectory(dir=ROOT,prefix='.stage-') as td:
            stage=Path(td);(stage/'conf').mkdir();atomic(stage/'config.json',bundle['base'])
            for name,c in bundle['files'].items():atomic(stage/'conf'/name,c)
            backup=ROOT/'.transaction';pending=stage/'backup';pending.mkdir()
            shutil.copy2(ROOT/'config.json',pending/'config.json');shutil.copytree(ROOT/'conf',pending/'conf')
            os.replace(pending,backup)
            try:
                os.replace(ROOT/'conf',stage/'old-conf');os.replace(stage/'conf',ROOT/'conf');os.replace(stage/'config.json',ROOT/'config.json')
                service('restart')
            except BaseException:
                recover()
                try:service('restart')
                except Exception:pass
                raise
            # Deleted credentials are not retained in old configuration backups.
            shutil.rmtree(backup)
        for stale in ROOT.glob('.stage-*'):
            if stale.is_dir():shutil.rmtree(stale)

def cleanup():
    # A receipt must be sent before removing the agent credential itself.
    if ROOT.exists() and not (ROOT/'.gw-owned').exists():raise ValueError('缺少所有权标记，拒绝清理')
    unit=Path('/etc/systemd/system/gw-proxy.service')
    if unit.exists():
        service('stop');run(['systemctl','disable',SERVICE],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if ROOT.exists():shutil.rmtree(ROOT)
    bbr=STATE/'bbr-before.json'
    if bbr.exists():
        previous=json.loads(bbr.read_text())
        for key,managed in [('net.core.default_qdisc','fq'),('net.ipv4.tcp_congestion_control','bbr')]:
            current=run(['sysctl','-n',key],stdout=subprocess.PIPE).stdout.decode().strip()
            if current==managed:run(['sysctl','-w',key+'='+previous[key]],stdout=subprocess.PIPE)
        Path('/etc/sysctl.d/99-gw-bbr.conf').unlink(missing_ok=True);bbr.unlink()
    if unit.exists():unit.unlink();run(['systemctl','daemon-reload'])

def finish_cleanup():
    unit=Path('/etc/systemd/system/gw-agent.service')
    if unit.exists():
        run(['systemctl','disable','gw-agent'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        unit.unlink()
    run(['systemctl','daemon-reload'])
    for name in ('agent.json','agent-state.json','install-complete','role','enrollment-pending.json'):
        (STATE/name).unlink(missing_ok=True)
    # The current process returns successfully; Restart=on-failure cannot resurrect it.
