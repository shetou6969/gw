"""Download only from named upstream release APIs; verify SHA256 before extraction."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import tarfile
import tempfile
import urllib.request
from . import node

REPOS={'core':'SagerNet/sing-box','caddy':'caddyserver/caddy'}

def fetch(url):
    request=urllib.request.Request(url,headers={'User-Agent':'GW-Panel/0.2'})
    with urllib.request.urlopen(request, timeout=120) as r: return r.read()

def install(kind, version='', destination=None, system='linux'):
    if kind not in REPOS: raise ValueError('仅支持 sing-box/Caddy 官方仓库')
    if version and not re.fullmatch(r'v?\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?',version): raise ValueError('无效版本号')
    release='tags/v'+version.lstrip('v') if version else 'latest'
    meta=json.loads(fetch('https://api.github.com/repos/'+REPOS[kind]+'/releases/'+release))
    ver=meta['tag_name'].lstrip('v')
    arch={'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}.get(platform.machine())
    if not arch: raise ValueError('仅支持 amd64/arm64')
    filename=f'sing-box-{ver}-{system}-{arch}.tar.gz' if kind=='core' else f'caddy_{ver}_{system}_{arch}.tar.gz'
    asset=next((a for a in meta['assets'] if a['name']==filename),None)
    if not asset: raise ValueError('官方发行包不存在：'+filename)
    expected=asset.get('digest','') or ''
    if not expected.startswith('sha256:'):
        checks=next((a for a in meta['assets'] if 'checksum' in a['name'].lower() and a['name'].endswith('.txt')),None)
        if not checks: raise ValueError('官方未提供 SHA256，拒绝安装此版本')
        lines=fetch(checks['browser_download_url']).decode().splitlines()
        expected=next(('sha256:'+l.split()[0] for l in lines if len(l.split())>=2 and l.split()[-1].lstrip('*')==filename),'')
    data=fetch(asset['browser_download_url'])
    if expected!='sha256:'+hashlib.sha256(data).hexdigest(): raise ValueError('SHA256 校验不匹配')
    target=Path(destination) if destination else (node.CORE if kind=='core' else Path('/usr/local/bin/caddy'))
    target.parent.mkdir(parents=True,exist_ok=True)
    binary='sing-box' if kind=='core' else 'caddy'
    with tempfile.TemporaryDirectory(dir=target.parent) as tmp:
        archive=Path(tmp)/'release.tar.gz';archive.write_bytes(data)
        with tarfile.open(archive) as tf:
            member=next((m for m in tf.getmembers() if m.isfile() and Path(m.name).name==binary),None)
            if not member: raise ValueError('发行包缺少核心程序')
            candidate=Path(tmp)/binary
            with tf.extractfile(member) as src,open(candidate,'wb') as dst: shutil.copyfileobj(src,dst)
            candidate.chmod(0o755)
        node.run([candidate,'version'],stdout=__import__('subprocess').PIPE)
        if kind=='core' and (node.ROOT/'config.json').exists():
            node.run([candidate,'check','-c',node.ROOT/'config.json','-C',node.ROOT/'conf'])
        if target.exists(): shutil.copy2(target,str(target)+'.previous')
        os.replace(candidate,target)
    return meta['tag_name']
