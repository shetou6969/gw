"""Verified GitHub Releases, safe extraction, backup and rollback for manager upgrades."""
import compileall
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path,PurePosixPath
import re
import shutil
import sqlite3
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from . import node,version
INSTALL=Path('/opt/gw')
CODE_ROOT=Path(__file__).resolve().parents[1]
MAX_DOWNLOAD=32*1024*1024

def valid_repo(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',value) or value.startswith('YOUR_'):raise ValueError('需要有效的 GitHub owner/repository')
    return value

def repository():
    file=node.STATE/'release-source.json'
    if not file.exists():file=CODE_ROOT/'REPOSITORY.json'
    return valid_repo(json.loads(file.read_text())['repository'])

def semver(v):
    if not re.fullmatch(r'\d+\.\d+\.\d+',v):raise ValueError('只支持稳定版本号 X.Y.Z')
    return tuple(map(int,v.split('.')))

def fetch(url):
    if not url.startswith(('https://api.github.com/','https://github.com/')):raise ValueError('非 GitHub 发布地址')
    req=urllib.request.Request(url,headers={'User-Agent':'GW-Panel-Updater','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=120) as response:data=response.read(MAX_DOWNLOAD+1)
    if len(data)>MAX_DOWNLOAD:raise ValueError('发行包超出大小限制')
    return data

def release(repo,wanted=None):
    repo=valid_repo(repo)
    if wanted:semver(wanted)
    meta=json.loads(fetch(f'https://api.github.com/repos/{repo}/releases/'+('tags/v'+wanted if wanted else 'latest')))
    if meta.get('draft') or meta.get('prerelease'):raise ValueError('不安装草稿或预发布版本')
    tag=meta['tag_name'];v=tag.removeprefix('v');semver(v)
    if tag!='v'+v or wanted and v!=wanted:raise ValueError('发布版本不匹配')
    asset=next((a for a in meta.get('assets',[]) if a['name']=='gw-panel.tar.gz'),None)
    checks=next((a for a in meta.get('assets',[]) if a['name']=='SHA256SUMS'),None)
    if not asset or not checks:raise ValueError('缺少 gw-panel.tar.gz 或 SHA256SUMS；请发布正式 Release')
    prefix=f'https://github.com/{repo}/releases/download/{tag}/'
    for item in (asset,checks):
        if not item['browser_download_url'].startswith(prefix):raise ValueError('发行资源不属于指定仓库/版本')
    return meta,asset,checks

def download(repo,destination,wanted=None):
    meta,asset,checks=release(repo,wanted);data=fetch(asset['browser_download_url']);actual=hashlib.sha256(data).hexdigest()
    sums=fetch(checks['browser_download_url']).decode()
    expected=next((line.split()[0] for line in sums.splitlines() if len(line.split())==2 and line.split()[1].lstrip('*')=='gw-panel.tar.gz'),None)
    if not expected or not re.fullmatch('[0-9a-f]{64}',expected) or actual!=expected:raise ValueError('发行包 SHA256 不匹配')
    digest=asset.get('digest')
    if digest and digest!='sha256:'+actual:raise ValueError('GitHub 资源摘要不匹配')
    path=Path(destination)/'release.tar.gz';path.write_bytes(data)
    with tarfile.open(path,'r:gz') as archive:
        members=archive.getmembers();names=set();total=0
        for member in members:
            p=PurePosixPath(member.name)
            if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='gw-panel' or member.name in names or not (member.isfile() or member.isdir()):raise ValueError('发行包含危险路径、重复项或链接')
            names.add(member.name);total+=member.size
            if total>MAX_DOWNLOAD:raise ValueError('发行包解压大小超限')
        for member in members:
            target=Path(destination)/member.name
            if member.isdir():target.mkdir(parents=True,exist_ok=True,mode=0o700)
            else:
                target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                with archive.extractfile(member) as src,open(target,'wb') as dst:shutil.copyfileobj(src,dst)
                target.chmod(0o700 if member.name.endswith('.sh') else 0o600)
    root=Path(destination)/'gw-panel';expected_version=meta['tag_name'][1:]
    if (root/'VERSION').read_text().strip()!=expected_version:raise ValueError('包内 VERSION 与 Release 标签不同')
    manifest=json.loads((root/'REPOSITORY.json').read_text())
    if manifest.get('repository')!=repo:raise ValueError('发行包仓库来源不匹配')
    if not compileall.compile_dir(root,quiet=1):raise ValueError('管理程序语法检查失败')
    subprocess.run(['bash','-n',str(root/'install.sh')],check=True,capture_output=True)
    return root,expected_version

def backup_state(destination):
    destination.mkdir(mode=0o700)
    for path in node.STATE.iterdir():
        if path.suffix=='.json':shutil.copy2(path,destination/path.name)
        elif path.name.endswith('.sqlite3'):
            with sqlite3.connect(path) as src,sqlite3.connect(destination/path.name) as dst:src.backup(dst)

def restore_state(source):
    for path in source.iterdir():
        if path.name.endswith('.sqlite3'):
            for suffix in ('-wal','-shm'):(node.STATE/(path.name+suffix)).unlink(missing_ok=True)
        shutil.copy2(path,node.STATE/path.name)

def health(role,expected):
    time.sleep(1)
    for service in services(role):node.run(['systemctl','is-active','--quiet',service])
    if role in ('controller','both'):
        cfg=json.loads((node.STATE/'controller.json').read_text());pem=Path(cfg['cert']).read_text();pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        conn=http.client.HTTPSConnection('127.0.0.1',cfg['web_port'],context=context,timeout=10)
        try:
            conn.connect()
            if hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()!=pin:raise ValueError('本地主控证书不符')
            conn.request('GET','/healthz');response=conn.getresponse();data=json.loads(response.read(4096))
            if response.status!=200 or data.get('version')!=expected:raise ValueError('主控新版本健康检查失败')
        finally:conn.close()

def services(role):
    if role=='controller':return ('gw-controller',)
    if role=='node':return ('gw-agent',)
    if role=='both':return ('gw-controller','gw-agent')
    raise ValueError('无效安装角色')

def install_package(source,new_version):
    source=Path(source);semver(new_version)
    if source.resolve()==INSTALL.resolve():raise ValueError('不能用当前运行目录覆盖自身')
    if semver(new_version)<semver((INSTALL/'VERSION').read_text().strip()):raise ValueError('拒绝降级，避免数据结构不兼容')
    role=(node.STATE/'role').read_text().strip()
    active_services=services(role)
    backup=INSTALL.parent/'gw.previous';stage=INSTALL.parent/'.gw-update-stage'
    if stage.exists():shutil.rmtree(stage)
    shutil.copytree(source,stage,ignore=shutil.ignore_patterns('__pycache__','.git','release.tar.gz'))
    if (INSTALL/'bin').exists():shutil.copytree(INSTALL/'bin',stage/'bin',dirs_exist_ok=True)
    if not compileall.compile_dir(stage,quiet=1):raise ValueError('新版本语法检查失败')
    subprocess.run(['bash','-n',str(stage/'install.sh')],check=True,capture_output=True)
    state_backup=node.STATE/('update-backup-'+str(time.time_ns()))
    switched=False
    try:
        for service in reversed(active_services):node.run(['systemctl','stop',service])
        backup_state(state_backup)
        if backup.exists():shutil.rmtree(backup)
        os.replace(INSTALL,backup);switched=True;os.replace(stage,INSTALL)
        for service in active_services:node.run(['systemctl','start',service])
        health(role,new_version)
        launcher=Path('/usr/local/bin/gw-panel')
        launcher.write_text('#!/bin/sh\nexec /bin/bash /opt/gw/install.sh "$@"\n')
        launcher.chmod(0o755)
    except BaseException:
        if switched:
            for service in reversed(active_services):subprocess.run(['systemctl','stop',service],capture_output=True)
            if INSTALL.exists():shutil.rmtree(INSTALL)
            os.replace(backup,INSTALL);restore_state(state_backup)
        for service in active_services:node.run(['systemctl','start',service])
        raise
    print('管理程序更新成功：'+new_version+'；账号、2FA、节点凭据和代理配置已保留。')
    print('升级前数据备份：'+str(state_backup))

def update(wanted=None,local=None):
    with open(node.STATE/'update.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if local:
            source=Path(local).resolve();new=(source/'VERSION').read_text().strip()
            install_package(source,new);return
        repo=repository()
        with tempfile.TemporaryDirectory(prefix='gw-release-') as td:
            source,new=download(repo,td,wanted)
            installed=(INSTALL/'VERSION').read_text().strip()
            if semver(new)<=semver(installed):print('当前已经是该版本或更新版本：'+installed);return
            install_package(source,new)
