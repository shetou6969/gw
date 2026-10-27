#!/usr/bin/env python3
"""Service entry points only. All management is performed in the web panel."""
import json
import os
from pathlib import Path
import sys
from gwlib import node

def main():
    command=sys.argv[1] if len(sys.argv)>1 else ''
    if command=='controller':
        from gwlib.control import serve
        serve()
    elif command=='agent':
        from gwlib.agent import loop
        loop()
    elif command=='download':
        from gwlib.download import install
        print(install('core',sys.argv[2] if len(sys.argv)>2 else '1.14.4'))
    elif command=='init-node':node.initialize()
    elif command=='update':
        from gwlib.updater import update
        if os.geteuid()!=0:raise PermissionError('更新需要 root 权限')
        update(local=sys.argv[2] if len(sys.argv)>2 else None)
    elif command=='configure':
        if os.geteuid()!=0:raise PermissionError('修改安装参数需要 root 权限')
        from setup import configure
        configure()
    elif command=='version':
        from gwlib.version import current
        print(current())
    else:print('GW Panel：请通过 Web 面板管理。安装入口：sudo bash install.sh')

if __name__=='__main__':
    os.umask(0o077)
    try:main()
    except KeyboardInterrupt:sys.exit(130)
    except Exception as e:sys.exit('GW 运行失败：'+str(e))
