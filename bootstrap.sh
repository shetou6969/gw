#!/bin/bash
# Public, single-command entry point. The installer itself comes from a verified Release.
set -euo pipefail
umask 077
REPOSITORY=shetou6969/gw
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo '请在 Linux 服务器使用 sudo bash 运行';exit 1; }
if ! command -v python3 >/dev/null; then
    command -v apt-get >/dev/null || { echo '需要 Debian/Ubuntu 的 Python 3';exit 1; }
    apt-get update
    apt-get install -y python3 ca-certificates
fi
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
python3 - "$REPOSITORY" "$TEMP_DIR" <<'PY'
import hashlib,json,pathlib,re,shutil,sys,tarfile,urllib.request
repo,directory=sys.argv[1:];root=pathlib.Path(directory);limit=32*1024*1024
def fetch(url):
    if not url.startswith(('https://api.github.com/','https://github.com/')):raise ValueError('非指定 GitHub 地址')
    request=urllib.request.Request(url,headers={'User-Agent':'GW-Panel-Bootstrap','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(request,timeout=120) as response:data=response.read(limit+1)
    if len(data)>limit:raise ValueError('下载超过大小限制')
    return data
meta=json.loads(fetch('https://api.github.com/repos/'+repo+'/releases/latest'))
tag=meta['tag_name']
if meta.get('draft') or meta.get('prerelease') or not re.fullmatch(r'v\d+\.\d+\.\d+',tag):raise ValueError('需要正式语义版本 Release')
assets={a['name']:a for a in meta['assets']}
prefix='https://github.com/'+repo+'/releases/download/'+tag+'/'
def asset(name):
    item=assets[name]
    if item['browser_download_url']!=prefix+name:raise ValueError('发行资源地址不符')
    return fetch(item['browser_download_url']),item
archive,item=asset('gw-panel.tar.gz');checks,_=asset('SHA256SUMS')
digest=hashlib.sha256(archive).hexdigest()
lines=[line.split() for line in checks.decode().splitlines()]
expected=next((x[0] for x in lines if len(x)==2 and x[1].lstrip('*')=='gw-panel.tar.gz'),None)
if not expected or not re.fullmatch('[0-9a-f]{64}',expected) or digest!=expected:raise ValueError('发行包 SHA256 不匹配')
if item.get('digest') and item['digest']!='sha256:'+digest:raise ValueError('GitHub 资源摘要不匹配')
archive_path=root/'release.tar.gz';archive_path.write_bytes(archive)
with tarfile.open(archive_path,'r:gz') as tar:
    seen=set();total=0
    for member in tar.getmembers():
        p=pathlib.PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or p.parts[0]!='gw-panel' or member.name in seen or not (member.isfile() or member.isdir()):raise ValueError('发行包包含不安全路径或链接')
        seen.add(member.name);total+=member.size
        if total>limit:raise ValueError('解压大小超限')
        dest=root/member.name
        if member.isdir():dest.mkdir(parents=True,exist_ok=True,mode=0o700)
        else:
            dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with tar.extractfile(member) as src,dest.open('wb') as dst:shutil.copyfileobj(src,dst)
            dest.chmod(0o700 if dest.suffix=='.sh' else 0o600)
package=root/'gw-panel'
if (package/'VERSION').read_text().strip()!=tag[1:]:raise ValueError('包内版本不符')
if json.loads((package/'REPOSITORY.json').read_text())['repository']!=repo:raise ValueError('包内仓库不符')
if not (package/'install.sh').is_file():raise ValueError('安装入口缺失')
print('已验证 GW Panel '+tag+'；开始安装。',flush=True)
PY
bash "$TEMP_DIR/gw-panel/install.sh" "$@"
