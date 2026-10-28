#!/usr/bin/env python3
import getpass
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
from gwlib import node,model,control,agent,protocols

def ask(label,default=''):
    return input(label+(f' [{default}]' if default else '')+'：').strip() or default

def setup_controller():
    host=protocols.host(ask('主控公网 IP 或域名（供 Web 和节点连接）'))
    web=node.port(ask('Web HTTPS 端口','8443'));port=node.port(ask('节点上线 HTTPS 端口','9443'))
    if web==port:raise ValueError('Web 端口与节点上线端口必须不同')
    username=ask('管理员账号','admin');password=getpass.getpass('管理员密码（至少 12 位）：')
    if password!=getpass.getpass('再次输入密码：'):raise ValueError('密码不一致')
    if len(password)<12:raise ValueError('密码至少 12 位')
    node.STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    cert=ask('已有证书完整路径（留空生成自签证书）')
    if cert:
        key=ask('证书私钥路径')
        import shutil
        shutil.copyfile(cert,node.STATE/'tls.crt');shutil.copyfile(key,node.STATE/'tls.key')
    else:
        try:ipaddress.ip_address(host);san='IP:'+host
        except ValueError:san='DNS:'+host
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','365','-keyout',str(node.STATE/'tls.key'),'-out',str(node.STATE/'tls.crt'),'-subj','/CN=GW Panel','-addext','subjectAltName='+san],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    ctx=__import__('ssl').SSLContext(__import__('ssl').PROTOCOL_TLS_SERVER);ctx.load_cert_chain(node.STATE/'tls.crt',node.STATE/'tls.key')
    node.atomic(control.SETTINGS,{'public_host':host,'web_port':web,'agent_port':port,'bind':'0.0.0.0','cert':str(node.STATE/'tls.crt'),'key':str(node.STATE/'tls.key')})
    control.set_password(username,password);model.init()
    addr=f'[{host}]' if ':' in host else host
    print(f'面板地址：https://{addr}:{web}\n节点上线端口：{port}\n账号：{username}')
    print('自签证书需在浏览器中正确安装信任；节点会验证面板接入码内的证书指纹。')

def setup_node(local=False):
    if (node.STATE/'enrollment-pending.json').exists():
        pending=json.loads((node.STATE/'enrollment-pending.json').read_text());agent.finish_enrollment(pending['config'],pending['secret'])
    if (node.STATE/'agent.json').exists():
        cfg=json.loads((node.STATE/'agent.json').read_text())
        result=agent.request(cfg,'/agent/poll',{'id':cfg['id'],'applied':0,'command_ack':0,'status':'恢复安装','info':{}})
        if result.get('purge') or result.get('terminate'):raise ValueError('该节点已进入清理流程，不能恢复安装')
        print('已有接入凭据通过主控认证，继续未完成的安装。');return
    if local:
        print('本机主控：请先在 Web 添加服务器，公网 IP 填本机地址，接入验证来源 IP 填 127.0.0.1。')
        controller=json.loads((node.STATE/'controller.json').read_text())
    host=protocols.host(ask('主控 IP 或域名','127.0.0.1' if local else ''))
    port=node.port(ask('主控节点上线端口',str(controller['agent_port']) if local else '9443'))
    code=getpass.getpass('粘贴 Web 面板生成的接入码（不回显）：')
    agent.join(host,port,code);print('主控已验证预登记 IP 和一次性密钥，开始安装节点服务。')

def configure():
    """Change installed parameters without replacing credentials or node state."""
    role=(node.STATE/'role').read_text().strip()
    if role=='both':
        target=ask('修改 1) 主控  2) 节点')
        role={'1':'controller','2':'node'}.get(target)
        if not role:raise ValueError('无效选择')
    if role=='controller':
        cfg=json.loads(control.SETTINGS.read_text())
        print('1) 修改管理员账号/密码  2) 修改 Web 地址/端口  3) 修改节点接入端口')
        choice=ask('请选择')
        if choice=='1':
            account=json.loads((node.STATE/'account.json').read_text())
            current=getpass.getpass('当前密码：')
            if not control.verify(account['username'],current):raise PermissionError('当前密码错误')
            with model.connect() as c:
                model.begin(c)
                from gwlib import security
                security.consume(c,ask('2FA 动态码或恢复码（未启用可留空）'))
                username=ask('新账号',account['username'])
                password=getpass.getpass('新密码（至少 12 位）：')
                if password!=getpass.getpass('再次输入新密码：'):raise ValueError('密码不一致')
                control.set_password(username,password)
                c.execute('DELETE FROM sessions')
                model.audit(c,'命令行修改管理员凭据','local')
            print('管理员凭据已修改，Web 会话已退出。')
            return
        if choice not in ('2','3'):raise ValueError('无效选择')
        old=dict(cfg)
        if choice=='2':
            cfg['public_host']=protocols.host(ask('主控公网 IP 或域名',cfg['public_host']))
            cfg['web_port']=node.port(ask('Web HTTPS 端口',str(cfg['web_port'])))
        else:
            with model.connect() as c:
                if c.execute("SELECT 1 FROM nodes WHERE phase='active' LIMIT 1").fetchone():
                    raise ValueError('已有接入节点，不能直接改变节点接入端口；请先迁移节点连接')
            cfg['agent_port']=node.port(ask('节点接入 HTTPS 端口',str(cfg['agent_port'])))
        if cfg['web_port']==cfg['agent_port']:raise ValueError('Web 与节点接入端口不能相同')
        node.atomic(control.SETTINGS,cfg)
        result=subprocess.run(['systemctl','restart','gw-controller'],capture_output=True,text=True)
        if result.returncode:
            node.atomic(control.SETTINGS,old)
            subprocess.run(['systemctl','restart','gw-controller'],check=False)
            raise RuntimeError('新参数启动失败，已恢复旧参数：'+result.stderr[-500:])
        print('主控参数已更新；请确认防火墙与证书涵盖新的地址。')
    elif role=='node':
        cfg=json.loads((node.STATE/'agent.json').read_text())
        changed=dict(cfg)
        changed['host']=protocols.host(ask('主控 IP 或域名',cfg['host']))
        changed['port']=node.port(ask('主控节点接入端口',str(cfg['port'])))
        # The existing certificate fingerprint remains pinned while testing the new endpoint.
        agent.request(changed,'/agent/poll',{'id':cfg['id'],'applied':0,'command_ack':0,'status':'验证新主控地址','info':{}})
        node.atomic(node.STATE/'agent.json',changed)
        result=subprocess.run(['systemctl','restart','gw-agent'],capture_output=True,text=True)
        if result.returncode:
            node.atomic(node.STATE/'agent.json',cfg)
            subprocess.run(['systemctl','restart','gw-agent'],check=False)
            raise RuntimeError('Agent 启动失败，已恢复旧地址：'+result.stderr[-500:])
        print('节点主控地址已更新，证书指纹和接入凭据保持不变。')
    else:raise ValueError('未识别本机安装角色')

if __name__=='__main__':
    os.umask(0o077)
    try:
        if sys.argv[1]=='controller':setup_controller()
        elif sys.argv[1]=='node':setup_node()
        elif sys.argv[1]=='node-local':setup_node(local=True)
        elif sys.argv[1]=='configure':configure()
        else:raise ValueError('无效安装角色')
    except (Exception,KeyboardInterrupt) as e:sys.exit('安装停止：'+str(e))
