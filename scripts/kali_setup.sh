#!/usr/bin/env bash
# LiteWAF 综设 · Kali 环境初始化（2026.3 适配版，合并了共享盘挂载与 MariaDB）
# 只改虚拟机内部，不碰 Windows。可重复执行（幂等）。
# 用法：sudo bash kali_setup.sh
set -u

log() { printf '\n==> %s\n' "$*"; }
ok()  { echo "    [OK] $*"; }
die() { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "请用 sudo 运行：sudo bash kali_setup.sh"

log "0/8 强制 apt 走 IPv4"
# Kali NAT 没有 IPv6 出口，apt 若解析到 IPv6 地址会报 connect (101) 网络不可达
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

log "1/8 apt 更新"
apt-get update -y || die "apt update 失败：先 curl -I --max-time 8 https://mirrors.kali.org 看网络，或换源"

log "2/8 安装编译、运行与虚拟化依赖"
# Kali rolling 的 JDK 版本随源变化：25 / 21 / 17 / default 依次尝试
JDK_PKG=""
for p in openjdk-25-jdk-headless openjdk-21-jdk-headless openjdk-17-jdk-headless default-jdk-headless; do
  if apt-cache show "$p" >/dev/null 2>&1; then JDK_PKG="$p"; break; fi
done
[[ -n "$JDK_PKG" ]] || die "源里找不到任何 JDK 包（openjdk-25/21/17/default），先跑 apt-cache search openjdk 看看"
echo "使用 JDK 包：${JDK_PKG}"
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential libpcre2-dev zlib1g-dev libssl-dev perl git curl ca-certificates \
  "${JDK_PKG}" maven python3 python3-venv sqlite3 jq chrony rsync vim-tiny \
  open-vm-tools mariadb-server \
  || die "apt install 失败（看上面报错，常见：源不通、磁盘满）"

log "3/8 停用 apache2（避免占用 80 端口）"
if systemctl list-unit-files 2>/dev/null | grep -q '^apache2\.service'; then
  systemctl disable --now apache2 >/dev/null 2>&1 || true
  ok "apache2 已停用"
else
  ok "没有 apache2，跳过"
fi

log "4/8 开启 ssh"
systemctl enable --now ssh >/dev/null 2>&1 || die "sshd 启动失败（sudo apt install openssh-server 后重试）"
ok "sshd 已启用"

log "5/8 建目录"
OWNER=kali
id -u kali >/dev/null 2>&1 || OWNER="$(logname 2>/dev/null || echo root)"
mkdir -p /opt/litewaf /opt/src
chown -R "${OWNER}:${OWNER}" /opt/litewaf /opt/src
ok "/opt/litewaf /opt/src 归 ${OWNER} 所有"

log "6/8 共享文件夹永久挂载"
command -v vmhgfs-fuse >/dev/null 2>&1 || die "找不到 vmhgfs-fuse（open-vm-tools 未装，先 sudo apt install open-vm-tools）"
mkdir -p /mnt/hgfs
if grep -q '^user_allow_other' /etc/fuse.conf 2>/dev/null; then
  ok "fuse.conf 已允许 user_allow_other"
else
  echo 'user_allow_other' >> /etc/fuse.conf
  ok "已写入 fuse.conf: user_allow_other"
fi
if grep -q '^\.host:.*[[:space:]]/mnt/hgfs[[:space:]]' /etc/fstab 2>/dev/null; then
  ok "fstab 已有挂载项"
else
  echo '.host:/ /mnt/hgfs fuse.vmhgfs-fuse allow_other,defaults 0 0' >> /etc/fstab
  ok "已写入 /etc/fstab"
fi
if mountpoint -q /mnt/hgfs; then
  ok "/mnt/hgfs 已挂载"
else
  mount -a || die "mount -a 失败（VMware 设置里共享文件夹是否启用？）"
  ok "已挂载"
fi
if ls /mnt/hgfs/share >/dev/null 2>&1; then
  ok "共享目录可见：$(ls /mnt/hgfs/share 2>/dev/null | head -3 | tr '\n' ' ')"
else
  echo "    !! 看不到 /mnt/hgfs/share：VMware 虚拟机设置 → 选项 → 共享文件夹 里要有 share → D:\\网安综设 且选「总是启用」"
fi

log "7/8 MariaDB 启动与建库"
systemctl enable --now mariadb >/dev/null 2>&1 || service mariadb start >/dev/null 2>&1
ready=0
for _ in $(seq 1 20); do
  if mysqladmin ping >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ $ready -eq 1 ]] || die "MariaDB 没起来。排查：journalctl -u mariadb -n 50 --no-pager"
mysql --protocol=socket -uroot <<'SQL' || die "建库 SQL 执行失败"
CREATE DATABASE IF NOT EXISTS litewaf CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER IF NOT EXISTS 'litewaf'@'127.0.0.1' IDENTIFIED BY 'LiteWaf@2026';
CREATE USER IF NOT EXISTS 'litewaf'@'localhost' IDENTIFIED BY 'LiteWaf@2026';
GRANT ALL PRIVILEGES ON litewaf.* TO 'litewaf'@'127.0.0.1';
GRANT ALL PRIVILEGES ON litewaf.* TO 'litewaf'@'localhost';
FLUSH PRIVILEGES;
SQL
if mysql -h127.0.0.1 -ulitewaf -p'LiteWaf@2026' -N -e 'SELECT 1;' litewaf 2>/dev/null | grep -q 1; then
  ok "库 litewaf / 用户 litewaf 就绪（密码 LiteWaf@2026）"
else
  die "litewaf 账号 127.0.0.1 连接失败（检查 bind-address 与账号）"
fi

log "8/8 时区、时间同步与自检"
timedatectl set-timezone Asia/Shanghai || true
# Kali 2026.3 默认用 systemd-timesyncd，先停掉再启用 chrony，避免两者抢时间源
systemctl disable --now systemd-timesyncd >/dev/null 2>&1 || true
systemctl enable --now chrony >/dev/null 2>&1 || true
timedatectl set-ntp true >/dev/null 2>&1 || true
echo "--- pcre2 版本 ---"; pcre2-config --version || echo "!! 缺 pcre2-config"
echo "--- gcc ---"; gcc --version | head -1
echo "--- make ---"; make --version | head -1
echo "--- java ---"; java -version 2>&1 | head -1
echo "--- mvn ---"; mvn -v 2>/dev/null | head -1 || echo "!! 缺 mvn"
echo "--- python3 ---"; python3 -V
echo "--- sqlite3 ---"; sqlite3 --version
echo "--- mariadb ---"; mariadb --version 2>/dev/null | head -1; systemctl is-active mariadb 2>/dev/null
echo "--- 端口 22/3306 ---"; ss -lntp 2>/dev/null | grep -E ':(22|3306)\b' || echo "（22 应该有 sshd）"
echo "--- 磁盘 ---"; df -h / | tail -1
echo "--- 共享盘 ---"; ls /mnt/hgfs/share 2>/dev/null | head -5 || echo "!! 共享盘不可见"

log "完成。下一步：sudo bash /mnt/hgfs/share/scripts/s0_build.sh"
