#!/bin/bash
set -euo pipefail
umask 077
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ${1:-} == --version ]]; then
    [[ -f /opt/gw/VERSION ]] || { echo '尚未安装 GW Panel';exit 1; }
    cat /opt/gw/VERSION
    exit 0
fi
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo '请在 Linux 服务器执行 sudo bash install.sh'; exit 1; }
command -v apt-get >/dev/null || { echo '当前支持 Debian 11+/Ubuntu 22.04+（systemd）';exit 1; }
command -v systemctl >/dev/null
# No third-party software repository is added.
if ! command -v python3 >/dev/null; then apt-get update;apt-get install -y python3 ca-certificates;fi
case ${1:-} in
    --update)
        [[ -f /etc/gw/role && -f /opt/gw/VERSION ]] || { echo '未找到已安装的 GW Panel';exit 1; }
        if [[ $HERE == /opt/gw ]]; then python3 /opt/gw/gw.py update;else python3 "$HERE/gw.py" update "$HERE";fi
        exit 0;;
    --configure)
        [[ -f /etc/gw/role ]] || { echo '请先安装 GW Panel';exit 1; }
        python3 /opt/gw/gw.py configure;exit 0;;
    '') ;;
    *) echo '用法：sudo bash install.sh [--update|--configure|--version]';exit 2;;
esac
if [[ -d /opt/gw && ! -f /opt/gw/VERSION ]]; then echo '检测到旧版管理程序，请使用干净环境测试本版本。';exit 1;fi
if [[ -f /etc/gw/role ]]; then
    role=$(cat /etc/gw/role)
    [[ ! -f /etc/gw/install-complete ]] || { echo '本机已安装；使用 gw-panel --update 或 gw-panel --configure。';exit 1; }
    echo "继续未完成安装：$role"
else
    echo '1) 安装主控（Web + 数据库）    2) 安装节点'
    read -r -p '请选择 [1/2]：' selected
    case $selected in 1) role=controller;;2) role=node;;*)exit 1;;esac
fi
# Enrollment runs from the local package before installing a node core or creating services.
# A rejected / missing registration ends the installer here.
if [[ $role == node ]]; then
    python3 "$HERE/setup.py" node
else
    apt-get update;apt-get install -y python3 ca-certificates openssl
    [[ -f /etc/gw/controller.json ]] || python3 "$HERE/setup.py" controller
fi
mkdir -p /opt/gw /etc/gw
chmod 700 /etc/gw
printf '%s\n' "$role" >/etc/gw/role
if [[ $HERE != /opt/gw ]]; then cp -a "$HERE/gw.py" "$HERE/setup.py" "$HERE/gwlib" "$HERE/install.sh" "$HERE/LICENSE" "$HERE/NOTICE.md" "$HERE/README.md" "$HERE/VERSION" "$HERE/REPOSITORY.json" /opt/gw/;fi
apt-get update
apt-get install -y python3 ca-certificates openssl curl procps iproute2 kmod qrencode
# Same official core is installed on the controller to generate keys and validate configs.
[[ -x /opt/gw/bin/sing-box ]] || python3 /opt/gw/gw.py download 1.14.4
if [[ $role == controller ]]; then
    cat >/etc/systemd/system/gw-controller.service <<'EOF'
[Unit]
Description=GW Panel controller
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/gw/gw.py controller
WorkingDirectory=/etc/gw
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/gw
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload;systemctl enable --now gw-controller
    sleep 1
    systemctl is-active --quiet gw-controller
else
    python3 /opt/gw/gw.py init-node
    cat >/etc/systemd/system/gw-proxy.service <<'EOF'
[Unit]
Description=GW managed proxy
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/opt/gw/bin/sing-box -D /var/lib/gw-node run -c /var/lib/gw-node/config.json -C /var/lib/gw-node/conf
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
    cat >/etc/systemd/system/gw-agent.service <<'EOF'
[Unit]
Description=GW node agent
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/gw/gw.py agent
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload;systemctl enable --now gw-proxy gw-agent
    sleep 1
    systemctl is-active --quiet gw-proxy
    systemctl is-active --quiet gw-agent
fi
touch /etc/gw/install-complete
cat >/usr/local/bin/gw-panel <<'EOF'
#!/bin/sh
exec /bin/bash /opt/gw/install.sh "$@"
EOF
chmod 755 /usr/local/bin/gw-panel
echo '安装完成。此后所有协议创建、出口及清理操作均在 Web 面板执行。'
echo '请在云安全组/防火墙放行主控所选端口及面板显示的协议/内部转发端口。'
