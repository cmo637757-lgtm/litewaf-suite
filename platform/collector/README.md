# LiteWAF 日志采集器（S2）

全平台**唯一**的日志 tail 承担者：WAF 审计日志与 nginx 访问日志都只由它读一次，写进 MariaDB；
后台看板、事件检索、告警、导出全部读数据库，不再各自读文件。

## 文件

| 文件 | 说明 |
|---|---|
| `schema.sql` | 5 张表：`ingest_sources`、`ingest_cursors`、`requests`、`waf_events`、`ingest_errors` |
| `lwaf_collect.py` | 主程序（Python 3 + `python3-pymysql`，无 pip 依赖） |
| `config.ini` | 生产配置示例（两个来源） |
| `config.fixture.ini` | 用冻结 F20 数据集验证用 |
| `lwaf-collector.service` | systemd 单元 |

## 一次性初始化

```bash
# 1. 建表（root 跑一次；MariaDB 11.8 客户端默认走 TLS，本机 socket 连接要 --skip-ssl）
sudo bash -c 'mariadb --skip-ssl < /opt/litewaf/platform/collector/schema.sql'

# 2. 建系统用户（采集器只需要「读日志 + 写库」）
sudo useradd --system --no-create-home --shell /usr/sbin/nologin litewaf 2>/dev/null || true

# 3. 装服务
sudo cp /opt/litewaf/platform/collector/lwaf-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lwaf-collector
sudo systemctl status lwaf-collector --no-pager
journalctl -u lwaf-collector -n 20 --no-pager
```

## 验证（对着冻结数据集，可重复）

```bash
cd /opt/litewaf/platform/collector
python3 lwaf_collect.py --config config.fixture.ini --once --verbose   # 期望 25 行（20 access + 5 reject）

# 幂等：再跑一次必须是 0 行
python3 lwaf_collect.py --config config.fixture.ini --once

# 追加与轮转（demo）
cat /opt/litewaf/platform/fixtures/f20/append2.log >> /opt/litewaf/platform/fixtures/f20/access.log
python3 lwaf_collect.py --config config.fixture.ini --once      # +2
mv access.log access.log.1 && cp rename_new.log access.log
python3 lwaf_collect.py --config config.fixture.ini --once      # +1，游标自动开新代次
```

期望结果：`requests=23`、`waf_events=5`、`ingest_errors=0`，`ingest_cursors` 里同一来源出现两个
`file_identity`（旧文件与 rename 后的新文件各一条）。

## 关键口径

- **去重键**：来源 + `file_identity`（`st_dev:st_ino`）+ 代次 + 字节偏移。同一文件重扫、重启、
  崩溃恢复都不会重复；`mv` 轮转后 inode 变化 → 自动开新代次，旧文件尾部也能读完。
- **事务边界**：数据行 + 错误行 + 游标推进在同一个事务里，提交失败整批回滚、游标不前进，
  退避 1/2/5/10/30 秒重试。
- **坏行不阻塞**：单行 JSON 解析失败进 `ingest_errors`（原样保留 `raw_line`），同批其它行照常入库。
- **只处理完整行**：读到最后一个 `\n` 为止，尾部半行留给下一轮（文件可能正写到一半）。
- **不支持 copytruncate**：文件被截断时开新代次从头读，旧代次记录保留以便核对。
- **时间**：统一存 UTC epoch 毫秒；展示层按 Asia/Shanghai 渲染。
- **展示映射在适配层**：源日志 `category` 原值不动（`SQL`/`XSS`/`SCAN`…），
  入库时另存 `category_display`（`SQLi`/`XSS`/`Scanner`…），`reason=dynamic_block` → `CC`，
  `reason=blacklist` → `ACL`。
- **磁盘水位**：85% 告警、95% 停止采集；两者都不删数据。

## 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `TLS/SSL error: tlsv1 alert internal error` | MariaDB 11.8 客户端默认尝试 TLS，本机 socket 与自签证书不匹配 | 命令加 `--skip-ssl` |
| `Table 'litewaf.requests' doesn't exist` | 没跑 `schema.sql` | 先建表 |
| 日志一直不进库 | 源配置写的是相对路径或文件名不对 | `sources` 必须是绝对路径，`ls -l` 确认文件存在 |
| 解析失败全红 | 日志不是 JSON Lines（例如还是 nginx 默认 combined 格式） | 检查 nginx `log_format` 已改成 JSON 转义格式 |
