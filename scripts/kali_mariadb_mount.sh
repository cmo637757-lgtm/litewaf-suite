#!/usr/bin/env bash
# kali_mariadb_mount.sh — Kali 收尾：共享文件夹永久挂载 + MariaDB 安装与建库
# 用法：sudo bash /mnt/hgfs/share/scripts/kali_mariadb_mount.sh
# 幂等：可重复执行
set -uo pipefail

die(){ echo "[FAIL] $*" >&2; exit 1; }
log(){ echo; echo "==> $*"; }
ok(){ echo "    [OK] $*"; }

[[ ${EUID} -eq 0 ]] || die "请用 sudo 运行：sudo bash $0"

# ---------- 1/6 共享文件夹永久挂载 ----------
log "1/6 共享文件夹永久挂载"
command -v vmhgfs-fuse >/dev/null 2>&1 || die "找不到 vmhgfs-fuse（open-vm-tools 未装，先 apt install open-vm-tools）"

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
  mount -a || die "mount -a 失败"
  ok "已挂载"
fi

ls /mnt/hgfs/share >/dev/null 2>&1 || die "看不到 /mnt/hgfs/share（VM 设置里共享文件夹是否启用？名称是否叫 share？）"
ok "共享目录可见：$(ls /mnt/hgfs/share 2>/dev/null | head -3 | tr '\n' ' ')"

# ---------- 2/6 安装 MariaDB ----------
log "2/6 安装 MariaDB"
if dpkg -s mariadb-server >/dev/null 2>&1; then
  ok "MariaDB 已安装"
else
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends mariadb-server \
    || die "apt install mariadb-server 失败（看上面报错）"
  ok "安装完成"
fi

# ---------- 3/6 启动 ----------
log "3/6 启动 MariaDB"
systemctl enable --now mariadb >/dev/null 2>&1 || service mariadb start >/dev/null 2>&1
ready=0
for _ in $(seq 1 20); do
  if mysqladmin ping >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ $ready -eq 1 ]] || die "MariaDB 没起来。排查：journalctl -u mariadb -n 50 --no-pager"
ok "MariaDB 运行中"

# ---------- 4/6 建库 / 用户 ----------
log "4/6 建库与用户"
DB=litewaf
DB_USER=litewaf
DB_PASS='LiteWaf@2026'

mysql --protocol=socket -uroot <<SQL || die "建库 SQL 执行失败"
CREATE DATABASE IF NOT EXISTS ${DB} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB}.* TO '${DB_USER}'@'127.0.0.1';
GRANT ALL PRIVILEGES ON ${DB}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
ok "库 litewaf / 用户 litewaf 就绪（密码 LiteWaf@2026）"

if mysql -h127.0.0.1 -u"${DB_USER}" -p"${DB_PASS}" -N -e "SELECT 1;" "${DB}" 2>/dev/null | grep -q 1; then
  ok "127.0.0.1 账号密码连接通过"
else
  die "127.0.0.1 连接失败（检查 bind-address 与账号）"
fi

# ---------- 5/6 自检 ----------
log "5/6 自检"
echo "    版本     : $(mariadb --version 2>/dev/null | head -1)"
echo "    服务状态 : $(systemctl is-active mariadb 2>/dev/null)"
echo "    监听     : $(ss -lntp 2>/dev/null | grep -E ':3306' | head -1 || echo '未见 3306（绑定本地 socket 也可用）')"
echo "    数据库   : $(mysql -N -e 'SHOW DATABASES;' 2>/dev/null | tr '\n' ' ')"
echo "    数据目录 : $(mysql -N -e 'SELECT @@datadir;' 2>/dev/null)"

# ---------- 6/6 收尾 ----------
log "6/6 完成"
cat <<'EOF'
下一步（手动，二选一）：
  A. 现在就能用：共享文件夹已挂、MariaDB 已建库，可以直接进 S0（编译 nginx）。
  B. 想调内存：关机 → VMware 设置 → 内存改 6GB → 开机后跑 ls /mnt/hgfs/share 验证自动挂载。
连接串（后端用）：
  jdbc:mysql://127.0.0.1:3306/litewaf?useUnicode=true&characterEncoding=utf8&serverTimezone=UTC
  用户 litewaf / 密码 LiteWaf@2026
EOF
