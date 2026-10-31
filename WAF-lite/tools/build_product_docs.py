#!/usr/bin/env python3
"""Build LiteWAF-NGX product implementation documents.

The generated DOCX files are derived from the current repository structure and
the implementation checklist in ``docs/功能实现清单.md``.  The script keeps the
style deterministic so the documents can be regenerated after code changes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
OUT_03 = ROOT / "03_产品实现说明_LiteWAF-NGX.docx"
OUT_04 = ROOT / "04_产品功能说明_LiteWAF-NGX.docx"
OUT_05 = ROOT / "05_产品测试说明_LiteWAF-NGX.docx"
OUT_06 = ROOT / "06_测试用例说明_LiteWAF-NGX.docx"
OUT_07 = ROOT / "07_项目报告_LiteWAF-NGX.docx"
OUT_08 = ROOT / "08_文档汇总_LiteWAF-NGX.docx"

BLUE = RGBColor(0x2E, 0x74, 0xB5)
DARK_BLUE = RGBColor(0x1F, 0x4D, 0x78)
HEADER_FILL = "F2F4F7"


def _set_cell_shading(cell, fill: str) -> None:
    """Apply a solid fill color to a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def _set_cell_margin(cell, margin: int = 120) -> None:
    """Set compact but readable cell margins in twentieths of a point."""
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for side in ("top", "start", "bottom", "end"):
        node = tc_mar.find(qn(f"w:{side}"))
        if node is None:
            node = OxmlElement(f"w:{side}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(80 if side in {"top", "bottom"} else margin))
        node.set(qn("w:type"), "dxa")


def _style_document(doc: Document) -> None:
    """Apply the standard business brief preset used by product documents."""
    section = doc.sections[0]
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)

    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    normal.font.size = Pt(11)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.1

    for name, size, color, before, after in (
        ("Heading 1", 16, BLUE, 16, 8),
        ("Heading 2", 13, BLUE, 12, 6),
        ("Heading 3", 12, DARK_BLUE, 8, 4),
    ):
        style = doc.styles[name]
        style.font.name = "Calibri"
        style._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
        style.font.size = Pt(size)
        style.font.color.rgb = color
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)


def _add_header(doc: Document, title: str, subtitle: str) -> None:
    """Add a memo-style masthead with title, project, and date."""
    header = doc.sections[0].header
    table = header.add_table(rows=3, cols=2, width=Inches(6.5))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    rows = [
        ("文档", title),
        ("项目", "LiteWAF-NGX"),
        ("日期", "2026-06-30"),
    ]
    for row, (label, value) in zip(table.rows, rows):
        row.cells[0].text = label
        row.cells[1].text = value if label != "文档" else f"{value} - {subtitle}"
        for cell in row.cells:
            _set_cell_margin(cell)
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    run.font.size = Pt(8)


def _add_title(doc: Document, title: str, subtitle: str) -> None:
    """Add a centered title block."""
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run(title)
    run.bold = True
    run.font.size = Pt(18)
    run.font.color.rgb = BLUE

    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run(subtitle)
    run.font.size = Pt(11)
    run.font.color.rgb = DARK_BLUE


def _add_bullets(doc: Document, items: Iterable[str]) -> None:
    """Add a sequence of bullet paragraphs."""
    for item in items:
        doc.add_paragraph(item, style="List Bullet")


def _add_numbered(doc: Document, items: Iterable[str]) -> None:
    """Add a sequence of numbered paragraphs."""
    for item in items:
        doc.add_paragraph(item, style="List Number")


def _add_table(doc: Document, headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    """Add a compact implementation table."""
    table = doc.add_table(rows=1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    hdr = table.rows[0].cells
    for idx, text in enumerate(headers):
        hdr[idx].text = text
        _set_cell_shading(hdr[idx], HEADER_FILL)
        _set_cell_margin(hdr[idx])
        hdr[idx].vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        for paragraph in hdr[idx].paragraphs:
            for run in paragraph.runs:
                run.bold = True
    for row_data in rows:
        cells = table.add_row().cells
        for idx, text in enumerate(row_data):
            cells[idx].text = text
            _set_cell_margin(cells[idx])
            cells[idx].vertical_alignment = WD_ALIGN_VERTICAL.TOP


def _new_doc(title: str, subtitle: str) -> Document:
    """Create a styled document with a title and memo header."""
    doc = Document()
    _style_document(doc)
    _add_header(doc, title, subtitle)
    _add_title(doc, title, subtitle)
    return doc


def build_implementation_doc() -> None:
    """Generate 03_产品实现说明_LiteWAF-NGX.docx."""
    doc = _new_doc("03_产品实现说明", "从项目结构到具体实现模块")

    doc.add_heading("1. 实现范围概述", level=1)
    doc.add_paragraph(
        "LiteWAF-NGX 当前代码实现的是一个可编译、可接入 Nginx ACCESS_PHASE 的轻量级 Web 应用防火墙 MVP。"
        "实现重点是将 A 负责的 Nginx 模块接入、B 负责的规则引擎、C 负责的动态封禁与日志统计整合为一条可运行链路。"
    )
    _add_bullets(doc, [
        "入口模块位于 ngx_http_lite_waf_module/，负责配置解析、请求字段抽取、执行顺序编排和审计日志。",
        "规则引擎位于 include/ 与 src/，不依赖 Nginx 类型，可独立编译测试。",
        "规则与测试资源位于 conf/、tests/、scripts/，用于回归检测和指标计算。",
        "文档与成员 C 过程材料位于 docs/，本说明按当前全量代码状态描述实现，不把未落地扩展写入已实现项。",
    ])

    doc.add_heading("2. 项目结构", level=1)
    _add_table(doc, ["路径", "职责", "关键内容"], [
        ("ngx_http_lite_waf_module/", "Nginx 动态模块源码", "config 构建配置；ngx_http_lite_waf_module.c 实现配置指令、访问阶段处理、日志和动态封禁。"),
        ("include/", "公共 C API", "lwaf_rule_engine.h 定义规则、请求上下文、匹配结果、阈值和对外函数。"),
        ("src/", "B 规则引擎实现", "规则解析、URL 解码、大小写规范化、PCRE2 编译与匹配、分类计分和最终阻断判定。"),
        ("conf/", "默认运行配置", "litewaf_rules.conf 提供 21 条 MVP 检测规则。"),
        ("tests/", "单元测试", "test_rule_engine.c 校验规则加载、样本匹配和评分链路。"),
        ("tools/", "开发工具", "lwaf_eval.c 命令行评估；build_product_docs.py 生成 03/04 文档。"),
        ("scripts/", "端到端与指标脚本", "run_waf_tests.sh 发送测试流量，其中目录穿越样本使用 --path-as-is；calc_metrics.py 计算检测率、误报率和准确率。"),
        ("docs/", "说明与清单", "成员 C 需求/测试材料、功能实现清单。"),
    ])

    doc.add_heading("3. 构建与加载实现", level=1)
    doc.add_paragraph(
        "Nginx 模块使用标准 addon 方式构建。ngx_http_lite_waf_module/config 将模块源码与 B 规则引擎源码一并加入编译，"
        "并链接 PCRE2 库以支持正则规则。Makefile 负责独立测试 B 规则引擎，不要求启动 Nginx。"
    )
    _add_numbered(doc, [
        "开发阶段先运行 make test，确保规则解析和评分逻辑在普通 C 程序中通过。",
        "Nginx 阶段使用 --add-module 指向 ngx_http_lite_waf_module/，构建后通过 nginx -t 校验配置语法。",
        "运行阶段在 nginx.conf 的 http、server 或 location 作用域配置 lite_waf 系列指令。",
    ])

    doc.add_heading("4. Nginx 模块实现", level=1)
    doc.add_heading("4.1 生命周期与配置合并", level=2)
    doc.add_paragraph(
        "模块创建 location 配置时将开关、阈值、动态封禁参数、日志路径和规则指针初始化为未设置状态。"
        "合并配置时提供默认值：WAF 默认开启，可信代理默认关闭，拒绝状态码为 403，动态封禁默认开启，"
        "默认窗口为 10 秒，默认阈值覆盖 SQL、XSS、RFI、TRAVERSAL、EVADE、UPLOAD、SCAN 与 TOTAL。"
    )
    doc.add_heading("4.2 访问阶段处理顺序", level=2)
    _add_numbered(doc, [
        "若 lite_waf 关闭或请求为 Nginx 内部跳转，则直接放行，避免 try_files 等内部请求被重复计数。",
        "根据连接地址或 X-Forwarded-For 解析客户端 IPv4。",
        "先匹配白名单，命中后直接放行。",
        "再匹配黑名单，命中后写入审计日志并返回拒绝状态码。",
        "执行动态封禁计数，超过阈值或仍处于封禁期时拒绝。",
        "构造 B 规则引擎请求上下文，执行规则匹配与评分。",
        "若规则引擎给出阻断结果，记录首个关键命中并拒绝；否则放行给后续 Nginx 阶段。",
    ])
    doc.add_heading("4.3 配置指令", level=2)
    _add_table(doc, ["指令", "类型", "实现效果"], [
        ("lite_waf", "flag", "总开关，控制当前作用域是否执行 WAF 逻辑。"),
        ("lite_waf_trust_proxy", "flag", "启用后优先读取 X-Forwarded-For 首个有效 IPv4。"),
        ("lite_waf_deny_status", "uint", "配置黑名单、动态封禁、规则阻断返回的 HTTP 状态码。"),
        ("lite_waf_blacklist / lite_waf_whitelist", "CIDR", "向当前作用域追加 IPv4 CIDR 黑名单或白名单。"),
        ("lite_waf_rule_file", "path", "加载并编译 B 规则文件，失败时使 nginx -t 失败。"),
        ("lite_waf_score_threshold", "category uint", "配置分类或总分阈值。"),
        ("lite_waf_dynamic_block", "flag", "启用或关闭漏桶动态封禁。"),
        ("lite_waf_max_requests / lite_waf_window / lite_waf_block_duration", "uint", "配置漏桶容量、满桶泄漏周期和封禁时长。"),
        ("lite_waf_log_path", "path", "配置 JSON Lines 审计日志输出路径。"),
    ])

    doc.add_heading("5. B 规则引擎实现", level=1)
    doc.add_paragraph(
        "B 模块以 include/lwaf_rule_engine.h 为边界，不包含 Nginx 头文件，因此既可被模块调用，也可在命令行和单元测试中独立验证。"
    )
    doc.add_heading("5.1 规则文件与解析", level=2)
    doc.add_paragraph(
        "规则语法采用单行键值形式：lwaf_rule id=... name=\"...\" type=str|rx pattern=\"...\" zones=... score=CATEGORY:VALUE action=...。"
        "解析器会校验 ID、匹配类型、检测区域、分类名、分值和动作；正则规则在加载阶段编译，错误会返回到 Nginx 配置阶段。"
    )
    doc.add_heading("5.2 请求规范化", level=2)
    _add_bullets(doc, [
        "URL、ARGS、COOKIE、HEADERS、BODY 会进行一次 URL 解码并转为小写，降低简单编码绕过影响。",
        "ARGS 和 BODY 中的 + 会按表单语义转换为空格。",
        "FILE_EXT 从 URI 后缀提取并转小写，用于危险上传扩展名检测。",
        "所有规范化结果写入固定长度缓冲区，超长输入会被安全截断。",
    ])
    doc.add_heading("5.3 匹配、评分与决策", level=2)
    doc.add_paragraph(
        "规则引擎按规则顺序遍历检测区域。str 规则执行大小写不敏感子串匹配；rx 规则调用 PCRE2。"
        "action=block 会立即设置阻断结果；action=score 会累加分类分和总分，遍历结束后与阈值比较；action=log 只记录命中。"
        "匹配明细最多保留 64 条，供审计日志输出。"
    )

    doc.add_heading("6. C 动态封禁与日志实现", level=1)
    doc.add_heading("6.1 动态封禁", level=2)
    doc.add_paragraph(
        "动态封禁采用 Nginx shared memory zone 保存漏桶状态表。每个客户端 IP 记录最近泄漏时间、当前桶水位和封禁到期时间。"
        "每次请求向桶中加入固定水量，桶按 lite_waf_window 推导出的速率持续泄漏；水位超过 lite_waf_max_requests 对应容量后设置 block_expire，并在封禁期内持续返回拒绝状态码。多个 worker 通过共享内存和 slab pool 互斥锁访问同一份状态表，保证多进程状态一致。"
    )
    doc.add_heading("6.2 审计日志", level=2)
    doc.add_paragraph(
        "审计日志按 JSON Lines 写入配置路径。黑名单、动态封禁、规则立即阻断和阈值阻断都会生成事件，"
        "事件包含时间、IP、HTTP 方法、URI、原因、规则编号、规则名称、检测区域、分类、单条分值、总分、动作、状态码和微秒级处理耗时。"
        "当前版本吸收 member-c-json-log 分支的日志增强，对 method、uri、reason、rule_name、zone、category、action 等字符串字段执行 JSON 转义，"
        "可处理引号、反斜杠和控制字符，保证每一行都能作为独立 JSON 对象解析。"
    )

    doc.add_heading("7. 验证状态", level=1)
    _add_table(doc, ["验证项", "结果", "说明"], [
        ("make test", "通过", "B 规则引擎加载 21 条规则并命中样本流量。"),
        ("Nginx 模块增量编译", "通过", "临时 Nginx 1.31.1 源码树 make -j2 通过，仅保留 PCRE2 重复链接的非致命警告。"),
        ("nginx -t", "通过", "临时运行目录配置语法校验成功。"),
        ("端到端 HTTP 回归", "通过", "run_waf_tests.sh 全部 65 个样本通过；覆盖 20 条规则攻击、20 条正常请求和 25 次动态封禁。"),
        ("真实 POST BODY 回归", "通过", "run_waf_post_body_tests.sh 全部 8 个样本通过；覆盖表单和 JSON body。"),
        ("多 worker 共享封禁", "通过", "run_waf_multiworker_tests.sh 全部 10 个样本通过；4 worker 共享同一 IP 计数。"),
        ("漏桶算法回归", "通过", "run_waf_leaky_bucket_tests.sh 全部 8 个样本通过；验证泄漏恢复而非固定窗口累计。"),
        ("指标统计", "通过", "logs/test_results.csv 统计 TP=25、TN=40、FP=0、FN=0，检测率 100%，误报率 0%。"),
        ("JSON 日志解析", "通过", "基础审计日志 25 行、压测审计日志 1212 行、多 worker 审计日志 4 行均可被 Python 标准 json 模块解析。"),
        ("Docker/CI", "通过", "Dockerfile、docker-compose 与 GitHub Actions 已提供；docker compose build 与容器最终验收通过。"),
    ])

    doc.add_heading("8. 工程边界与后续增强", level=1)
    _add_bullets(doc, [
        "真实 POST body 已通过 Nginx 请求体回调接入，当前按固定上限拷贝请求体前缀，生产环境可继续按内容类型扩展 multipart 等复杂场景。",
        "动态封禁已迁移到 shared memory，后续可增加运行期观测接口展示当前 IP 计数和封禁到期时间。",
        "审计日志为同步追加写入，生产高并发场景可升级为缓冲或异步写入，并适配日志轮转。",
        "规则 reload 行为已通过自动化测试覆盖；长期高频 reload 下的资源生命周期观测可继续细化。",
    ])

    doc.save(OUT_03)


def build_function_doc() -> None:
    """Generate 04_产品功能说明_LiteWAF-NGX.docx."""
    doc = _new_doc("04_产品功能说明", "基于实现清单的用户功能说明")

    doc.add_heading("1. 产品定位", level=1)
    doc.add_paragraph(
        "LiteWAF-NGX 是一个面向课程/实验场景的轻量级 Nginx WAF 模块。"
        "它通过黑白名单、规则评分、立即阻断、动态封禁和审计日志，为 Web 服务提供基础入站防护能力。"
    )

    doc.add_heading("2. 已实现功能总览", level=1)
    _add_table(doc, ["功能域", "用户可见能力", "当前状态"], [
        ("接入方式", "作为 Nginx HTTP 模块在 ACCESS_PHASE 执行。", "已实现"),
        ("访问控制", "IPv4 CIDR 白名单优先放行，黑名单命中拒绝。", "已实现"),
        ("代理识别", "可启用 X-Forwarded-For 客户端 IP 识别。", "已实现"),
        ("攻击检测", "支持 SQLi、XSS、RFI、目录穿越、编码绕过、危险上传扩展名和扫描器 UA。", "已实现"),
        ("规则策略", "支持字符串、正则、分类计分、阈值阻断、立即阻断、仅记录动作。", "已实现"),
        ("动态封禁", "对同一 IP 使用共享漏桶算法治理高频请求。", "已实现"),
        ("审计记录", "输出带字符串转义的 JSON Lines 日志，便于脚本统计和问题追踪。", "已实现"),
        ("测试统计", "提供回归脚本和指标计算脚本。", "已实现"),
    ])

    doc.add_heading("3. 典型配置", level=1)
    doc.add_paragraph("Nginx 配置中可以在 http、server 或 location 作用域启用模块。示例：")
    code = doc.add_paragraph()
    code.style = "Normal"
    run = code.add_run(
        "lite_waf on;\n"
        "lite_waf_trust_proxy off;\n"
        "lite_waf_deny_status 403;\n"
        "lite_waf_rule_file /absolute/path/conf/litewaf_rules.conf;\n"
        "lite_waf_score_threshold SQL 8;\n"
        "lite_waf_score_threshold XSS 8;\n"
        "lite_waf_score_threshold TOTAL 12;\n"
        "lite_waf_dynamic_block on;\n"
        "lite_waf_max_requests 20;\n"
        "lite_waf_window 10;\n"
        "lite_waf_block_duration 60;\n"
        "lite_waf_log_path logs/litewaf_audit.jsonl;"
    )
    run.font.name = "Courier New"
    run._element.rPr.rFonts.set(qn("w:eastAsia"), "Courier New")
    run.font.size = Pt(9)

    doc.add_heading("4. 功能说明", level=1)
    doc.add_heading("4.1 黑白名单", level=2)
    doc.add_paragraph(
        "白名单用于放行可信来源，黑名单用于拒绝高风险来源。两者都使用 IPv4 CIDR 表达，例如 192.168.1.0/24。"
        "请求处理时白名单先于黑名单执行。"
    )
    doc.add_heading("4.2 规则检测", level=2)
    doc.add_paragraph(
        "默认规则覆盖常见 Web 攻击特征。规则可以绑定多个检测区域，并配置 score、block 或 log 动作。"
        "score 动作进入分类累计和阈值判断；block 动作命中即拒绝；log 动作用于观察命中情况。"
    )
    doc.add_heading("4.3 评分阈值", level=2)
    doc.add_paragraph(
        "阈值按分类配置，支持 SQL、XSS、RFI、TRAVERSAL、EVADE、UPLOAD、SCAN 和 TOTAL。"
        "任一分类或总分达到阈值时，模块返回配置的拒绝状态码。"
    )
    doc.add_heading("4.4 动态封禁", level=2)
    doc.add_paragraph(
        "动态封禁用于限制单个客户端在短时间内的异常高频访问。"
        "默认策略为桶容量 20、满桶泄漏周期 10 秒、封禁 60 秒；当请求积压超过桶容量时进入封禁期，实际数值可通过配置修改。"
    )
    doc.add_heading("4.5 审计日志与统计", level=2)
    doc.add_paragraph(
        "模块会在拒绝请求时写入 JSON Lines 审计日志，并对字符串字段进行 JSON 转义。"
        "测试脚本生成的 CSV 可交给 calc_metrics.py 计算 TP、TN、FP、FN、检测率、误报率和准确率。"
    )

    doc.add_heading("5. 操作与验收", level=1)
    _add_numbered(doc, [
        "运行 make test，确认 B 规则引擎测试通过。",
        "在 Nginx 源码树中以 --add-module 构建模块，并执行 nginx -t。",
        "启动临时 Nginx 后执行 BASE_URL=http://127.0.0.1:端口 bash scripts/run_waf_tests.sh。",
        "执行 python3 scripts/calc_metrics.py logs/test_results.csv，确认误报和漏报符合预期。",
        "检查审计日志路径是否生成 JSON Lines 事件，并核对规则 ID、原因和状态码。",
    ])

    doc.add_heading("6. 清单结论", level=1)
    doc.add_paragraph(
        "根据 docs/功能实现清单.md，当前 MVP 预期范围内的核心功能已完成，下一步实现功能为无。"
        "未来可围绕共享状态观测、更细粒度请求体解析、外部访问控制文件、日志轮转/异步写入和更长周期兼容性矩阵继续增强。"
    )

    doc.add_heading("7. 当前验证结果", level=1)
    _add_table(doc, ["项目", "结论"], [
        ("B 规则引擎单元测试", "通过，加载 21 条规则并命中样本攻击。"),
        ("Nginx 模块编译与配置", "通过，本机临时 Nginx 源码树增量构建成功，nginx -t 成功。"),
        ("端到端指标", "65 个 HTTP 样本全部通过；TP=25、TN=40、FP=0、FN=0，检测率 100%，误报率 0%。"),
        ("JSON 日志", "基础审计日志 25 行、压测审计日志 1212 行、多 worker 日志 4 行全部通过标准 JSON 解析。"),
        ("Docker 验证", "docker compose build 与 docker compose run --rm litewaf-acceptance 通过。"),
    ])

    doc.save(OUT_04)


def build_test_doc() -> None:
    """Generate 05_产品测试说明_LiteWAF-NGX.docx."""
    doc = _new_doc("05_产品测试说明", "测试准备、平台、数据与验收操作")

    doc.add_heading("1. 测试目标与依据", level=1)
    doc.add_paragraph(
        "本测试说明依据 01 产品总体设计文档和 02 产品设计文档中的验收要求编写。"
        "测试目标是验证 LiteWAF-NGX 在 Nginx ACCESS_PHASE 中对正常流量放行、对攻击流量阻断、对高频访问动态封禁，"
        "并生成可统计、可解释、可追溯的 JSON Lines 审计日志。"
    )
    _add_bullets(doc, [
        "功能验收：SQL 注入、XSS、目录穿越、RFI、扫描器 UA、高频访问应返回 403；正常请求应返回 200。",
        "配置验收：规则文件、阈值、黑白名单、动态封禁参数和日志路径应通过 Nginx 配置或外部文件调整。",
        "日志验收：每次拦截应记录 rule_id、rule_name、client_ip、uri、zone、score、action、status 等字段。",
        "指标验收：至少 20 条攻击样本和 20 条正常样本，计算 TP、TN、FP、FN、检出率、误报率和准确率。",
    ])

    doc.add_heading("2. 测试范围", level=1)
    _add_table(doc, ["测试类型", "覆盖内容", "工具/入口"], [
        ("单元测试", "规则文件加载、规则解析、请求规范化、str/rx 匹配、评分判定。", "make test；tests/test_rule_engine.c"),
        ("配置测试", "模块编译、Nginx 配置语法、规则文件路径、日志路径、动态封禁配置。", "make -j2；nginx -t"),
        ("功能测试", "20 条攻击样本、20 条正常样本、25 次动态封禁请求。", "scripts/run_waf_tests.sh"),
        ("真实 POST BODY", "表单和 JSON 请求体正常/攻击样本共 8 条。", "scripts/run_waf_post_body_tests.sh"),
        ("多 worker 封禁", "4 worker 配置下同一 IP 共享动态封禁状态，共 10 条样本。", "scripts/run_waf_multiworker_tests.sh"),
        ("漏桶算法", "填满桶、等待泄漏、继续请求和溢出封禁，共 8 条样本。", "scripts/run_waf_leaky_bucket_tests.sh"),
        ("指标测试", "TP/TN/FP/FN、检出率、误报率、准确率。", "scripts/calc_metrics.py"),
        ("批量回归", "20 条攻击模板和 20 条正常模板重复 10 轮，共 400 条请求。", "scripts/run_waf_volume_tests.py"),
        ("规则 reload", "规则新增后 reload 生效，规则移除后 reload 回退。", "scripts/run_waf_reload_tests.sh"),
        ("并发压测", "正常流量 5000 请求并发 50；规则命中流量 1000 请求并发 20。", "scripts/run_waf_load_tests.sh；ApacheBench"),
        ("长稳混合流量", "30 秒、12 并发、约 80 RPS，正常/攻击混合 2400 条。", "scripts/run_waf_soak_tests.py"),
        ("Docker/CI", "容器内自动构建 Nginx 并运行最终验收；GitHub Actions 执行同一入口。", "Dockerfile；docker-compose.yml；.github/workflows/ci.yml"),
        ("最终验收", "串联工具检查、运行目录准备、基础回归、reload、批量回归、POST BODY、多 worker、漏桶、压测、soak 和日志解析。", "scripts/run_final_acceptance.sh"),
        ("日志测试", "JSON Lines 格式、字段完整性、字符串转义、可解析性。", "Python json 模块；waf_audit.log"),
        ("回归测试", "每次合并或修改 C 日志/动态封禁、B 规则、A 接入后重复执行。", "本说明第 7 节操作流程"),
    ])

    doc.add_heading("3. 测试平台", level=1)
    _add_table(doc, ["项目", "当前验证平台", "说明"], [
        ("操作系统", "Darwin arm64，内核 25.2.0", "本机 Codex 工作区验证环境；课程 Linux 环境也可按同样流程执行。"),
        ("Nginx", "nginx/1.31.1 临时源码树", "通过 --add-module 加载 ngx_http_lite_waf_module。"),
        ("编译器", "clang 21.0.0", "Nginx 模块编译使用本机 clang。"),
        ("PCRE2", "/Volumes/MSD/opt/homebrew/opt/pcre2", "规则引擎正则匹配依赖 PCRE2。"),
        ("Docker", "Docker 29.5.3", "docker compose build 与容器最终验收通过。"),
        ("ApacheBench", "Version 2.3", "本机已安装 ab，用于并发压测，无需新增 brew 依赖。"),
        ("脚本工具", "bash、curl、python3", "curl 发送 HTTP 样本；Python 计算指标和解析日志。"),
    ])

    doc.add_heading("4. 测试准备", level=1)
    _add_numbered(doc, [
        "确认当前分支为 dev，并执行 git status 确认工作区状态。",
        "确认 conf/litewaf_rules.conf 存在，且包含 SQL、RFI、Traversal、XSS、Evade、Upload、Scanner 等规则。",
        "执行 make test，先验证 B 规则引擎可独立运行。",
        "在 Nginx 源码树中以 --add-module 指向 ngx_http_lite_waf_module 编译模块。",
        "准备临时 Nginx 运行目录，配置 lite_waf on、lite_waf_rule_file、lite_waf_score_threshold、lite_waf_dynamic_block 和 lite_waf_log_path。",
        "执行 nginx -t，确认配置文件语法正确后启动临时 Nginx。",
        "执行 BASE_URL=http://127.0.0.1:18010 bash scripts/run_waf_tests.sh 生成 logs/test_results.csv。",
        "执行 python3 scripts/calc_metrics.py logs/test_results.csv 输出统计指标。",
        "启动 18011 独立压测配置后，执行 run_waf_volume_tests.py 和 run_waf_load_tests.sh 生成批量回归与 ApacheBench 报告。",
        "执行 run_waf_reload_tests.sh 验证规则新增、reload 生效和移除回退。",
        "执行 run_waf_soak_tests.py 生成 30 秒正常/攻击混合流量报告。",
        "执行 docker compose build 和 docker compose run --rm litewaf-acceptance 验证 Linux 容器自动化。",
        "最终提交前执行 bash scripts/run_final_acceptance.sh，确认输出 FINAL ACCEPTANCE PASSED。",
    ])

    doc.add_heading("5. 测试数据", level=1)
    doc.add_heading("5.1 攻击样本", level=2)
    _add_table(doc, ["类别", "数量", "代表样本", "预期"], [
        ("SQL 注入", "5", "OR 1=1、UNION SELECT、--、drop table、0xdeadbeef", "403"),
        ("RFI", "2", "http://evil.example、php://filter", "403"),
        ("目录穿越", "3", "../../etc/passwd、cmd.exe、powershell.exe", "403"),
        ("XSS", "4", "<script>、javascript:、onerror=、svg onload", "403"),
        ("编码绕过", "1", "%u003c 与 HTML entity 组合", "403"),
        ("危险上传扩展名", "1", "shell.php", "403"),
        ("扫描器 UA", "4", "Nikto、sqlmap、python-requests、Wget", "403"),
    ])
    doc.add_heading("5.2 正常样本", level=2)
    doc.add_paragraph(
        "正常样本共 20 条，覆盖首页、静态资源、普通页面、普通查询参数、下载参数、健康检查、分页参数和安全上传文件名。"
        "所有正常样本使用 LiteWAF-Test/1.0 User-Agent，预期状态码均为 200。"
    )
    doc.add_heading("5.3 动态封禁样本", level=2)
    doc.add_paragraph(
        "动态封禁样本向 /login 连续发送 25 次请求。默认桶容量为 20，快速连续请求时前 20 次应返回 200，第 21 至第 25 次应返回 403，"
        "用于验证 max_requests=20、window=10、block_duration=60 的漏桶策略。"
    )

    doc.add_heading("6. 指标口径", level=1)
    _add_table(doc, ["指标", "定义", "当前结果"], [
        ("TP", "攻击样本被 WAF 拦截。", "基础 25；批量 200"),
        ("TN", "正常样本被 WAF 放行。", "基础 40；批量 200"),
        ("FP", "正常样本被 WAF 拦截，即误报。", "0"),
        ("FN", "攻击样本被 WAF 放行，即漏报。", "0"),
        ("检出率", "TP / (TP + FN)", "100.00%"),
        ("误报率", "FP / (FP + TN)", "0.00%"),
        ("准确率", "(TP + TN) / (TP + TN + FP + FN)", "100.00%"),
    ])

    doc.add_heading("7. 操作流程", level=1)
    _add_numbered(doc, [
        "执行 make test，若失败则先修复规则解析或评分逻辑。",
        "执行 Nginx 模块编译，确认没有编译错误；PCRE2 重复链接警告不影响运行。",
        "执行 nginx -t，若失败则检查 lite_waf_rule_file、lite_waf_log_path 和模块指令拼写。",
        "启动临时 Nginx 后运行 scripts/run_waf_tests.sh。",
        "查看 logs/test_results.csv，确认 passed 字段全部为 yes。",
        "运行 scripts/calc_metrics.py，确认检出率、误报率、准确率符合验收要求。",
        "用 Python json 模块逐行解析 waf_audit.log，确认日志为合法 JSON Lines。",
        "执行批量回归、POST BODY、多 worker、reload、soak 和 ApacheBench 压测，确认 400 条批量样本、8 条 POST BODY 样本、10 条多 worker 样本、3 条 reload 样本、2400 条混合流量全部通过，压测失败数为 0。",
        "执行 scripts/run_final_acceptance.sh，将以上步骤串联为最终验收。",
        "测试结束后停止临时 Nginx，避免端口占用和动态封禁状态影响下一轮测试。",
    ])

    doc.add_heading("8. 验收结论", level=1)
    doc.add_paragraph(
        "当前 dev_2 分支已满足 01/02 中对测试的核心要求：攻击样本和正常样本数量达标，真实 POST BODY 可检测，多 worker 动态封禁可复现，"
        "指标脚本可输出 TP/TN/FP/FN 和三项比率，审计日志可被标准 JSON 解析。"
        "本轮实测 65 条基础样本全部通过，3 条 reload 样本全部通过，400 条批量回归样本全部通过，8 条 POST BODY 样本全部通过，10 条多 worker 样本全部通过，6000 次 ApacheBench 并发请求无失败，2400 条混合流量无失败，"
        "测试结果可作为课程答辩和后续回归基线。"
    )

    doc.save(OUT_05)


def build_test_case_doc() -> None:
    """Generate 06_测试用例说明_LiteWAF-NGX.docx."""
    doc = _new_doc("06_测试用例说明", "接口路径、功能、安全、日志与性能用例")

    doc.add_heading("0. 文档介绍", level=1)
    doc.add_heading("0.1 文档目的", level=2)
    doc.add_paragraph(
        "本文档综合参考用户提供的两份测试用例报告文档结构，面向 LiteWAF-NGX 形成可验收、可复用、可扩展的测试用例说明。"
        "文档覆盖接口路径、功能、安全健壮性、动态封禁、日志审计和性能压测。"
    )
    doc.add_heading("0.2 文档范围", level=2)
    _add_bullets(doc, [
        "覆盖当前 dev_2 分支已实现的 Nginx 模块接入、规则引擎、真实 POST BODY、共享动态封禁和 JSON 审计日志。",
        "覆盖 65 条基础端到端样本、3 条规则 reload 样本、400 条批量回归样本、8 条 POST BODY 样本、10 条多 worker 样本、6000 次 ApacheBench 并发请求和 2400 条混合流量。",
        "管理端 UI 属于增强项，不作为当前验收阻断项。",
    ])
    doc.add_heading("0.3 读者对象", level=2)
    doc.add_paragraph("项目开发人员、测试人员、课程验收评审人员和后续维护者。")
    doc.add_heading("0.4 术语与缩写", level=2)
    _add_table(doc, ["术语", "解释"], [
        ("WAF", "Web Application Firewall，Web 应用防火墙。"),
        ("ACCESS_PHASE", "Nginx HTTP 访问控制阶段，LiteWAF-NGX 在此阶段执行拦截。"),
        ("TP/TN/FP/FN", "攻击拦截、正常放行、误报、漏报四类统计口径。"),
        ("JSON Lines", "每行一个独立 JSON 对象的日志格式。"),
        ("动态封禁", "按客户端 IP 使用漏桶水位统计请求积压，超过容量后短期封禁。"),
    ])

    doc.add_heading("1. 接口与路径测试用例", level=1)
    doc.add_paragraph(
        "被测试对象为 ngx_http_lite_waf_module 的请求处理链路。路径覆盖配置读取、客户端 IP 获取、白名单、黑名单、"
        "动态封禁、规则引擎检测、评分判定和审计日志写入。"
    )
    _add_table(doc, ["路径节点", "输入条件", "预期结果"], [
        ("模块开关", "lite_waf off / on", "off 放行；on 进入 WAF 链路。"),
        ("客户端 IP", "连接 IP 或 X-Forwarded-For", "按配置取源地址。"),
        ("白名单", "命中 CIDR 白名单", "优先放行。"),
        ("黑名单", "命中 CIDR 黑名单", "返回 403 并写日志。"),
        ("动态封禁", "同一 IP 第 21 次 /login", "返回 403，reason=dynamic_block。"),
        ("规则引擎", "SQLi/XSS/RFI/Traversal 等 payload", "命中规则或阈值后返回 403。"),
        ("日志", "拦截事件", "写入合法 JSON Lines。"),
    ])

    doc.add_heading("2. 功能测试用例", level=1)
    _add_table(doc, ["用例组", "数量", "输入", "预期"], [
        ("A001-A020", "20", "SQLi、RFI、Traversal、XSS、Evade、Upload、Scanner", "全部 403"),
        ("N001-N020", "20", "首页、静态资源、普通查询、健康检查、安全文件名", "全部 200"),
        ("D001-D020", "20", "同一 IP 连续访问 /login 前 20 次", "全部 200"),
        ("D021-D025", "5", "同一 IP 连续访问 /login 第 21-25 次", "全部 403"),
        ("RL reload", "3", "规则新增、reload 生效、规则移除回退", "全部通过"),
        ("VA/VN 批量回归", "400", "20 攻击模板 + 20 正常模板重复 10 轮", "全部通过"),
        ("LEAKY 漏桶回归", "8", "填满桶、等待泄漏、继续请求、再次溢出", "全部通过"),
        ("SOAK 混合流量", "2400", "30 秒正常/攻击混合流量", "全部通过"),
    ])
    doc.add_paragraph("当前基础端到端实测 65/65 通过，reload 3/3 通过，批量回归 400/400 通过，POST BODY 8/8 通过，多 worker 10/10 通过，漏桶回归 8/8 通过，混合流量 2400/2400 通过。")

    doc.add_heading("3. 安全与健壮性测试用例", level=1)
    _add_table(doc, ["编号", "类别", "输入条件", "预期结果"], [
        ("R001", "URL 编码", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "解码后命中 Traversal，403。"),
        ("R002", "反斜杠路径", "..%5C..%5Cwindows%5Csystem32%5Ccmd.exe", "命中 Windows shell 特征，403。"),
        ("R003", "日志转义", "URI 或规则名包含引号、反斜杠、控制字符", "日志仍可被标准 JSON 解析。"),
        ("R004", "漏桶边界", "容量内请求和溢出请求", "容量内 200，溢出后 403。"),
        ("R005", "载荷保持", "shell.php 位于被检测值末尾", "批量脚本不追加破坏语义的后缀。"),
    ])

    doc.add_heading("4. 性能与负载测试用例", level=1)
    _add_table(doc, ["编号", "场景", "请求数", "并发", "当前结果"], [
        ("P001", "正常流量 /", "5000", "50", "0 失败；约 43644 req/s；平均 1.146 ms。"),
        ("P002", "SQLi 规则命中", "1000", "20", "0 失败；1000 个非 2xx 阻断；约 35312 req/s。"),
        ("P003", "POST BODY 回归", "8", "串行", "8/8 通过。"),
        ("P004", "多 worker 共享封禁", "10", "4 worker", "10/10 通过。"),
        ("P005", "漏桶算法回归", "8", "串行", "8/8 通过。"),
        ("P006", "最终验收脚本", "65+3+400+8+10+8+6000+2400", "自动", "输出 FINAL ACCEPTANCE PASSED。"),
    ])
    doc.add_paragraph(
        "压测使用 ApacheBench。若环境缺少 ab，可在代理环境下执行 brew install httpd。"
    )

    doc.add_heading("5. 日志审计测试用例", level=1)
    _add_table(doc, ["编号", "场景", "检查内容", "预期"], [
        ("L001", "规则拦截", "rule_id、rule_name、zone、category、score", "字段存在且可解释拦截原因。"),
        ("L002", "动态封禁", "reason=dynamic_block、status=403", "字段语义正确。"),
        ("L003", "JSON Lines", "逐行 json.loads", "无解析错误。"),
        ("L004", "批量压测日志", "volume waf_audit.log", "1212 行均可解析。"),
        ("L005", "多 worker 日志", "multiworker waf_audit.log", "4 行均可解析。"),
        ("L006", "混合流量日志", "soak waf_audit.log", "822 行均可解析。"),
        ("L007", "最终验收汇总", "run_final_acceptance.sh", "输出基础、压测、multiworker、soak 日志行数和 ab 摘要。"),
    ])

    doc.add_heading("6. 检查表", level=1)
    _add_table(doc, ["检查项", "当前结论"], [
        ("数据类型", "IP、分值、状态码使用明确类型，未发现类型混用问题。"),
        ("初始化", "location 配置创建和合并阶段均有默认值处理。"),
        ("逻辑判断", "白名单、黑名单、动态封禁、规则检测顺序符合设计。"),
        ("循环边界", "CIDR、规则、动态表遍历均有上界。"),
        ("文件 I/O", "规则配置期加载，日志追加写入，路径可配置。"),
        ("错误处理", "规则加载失败会使 nginx -t 失败；测试脚本输出失败样本。"),
    ])

    doc.add_heading("7. 验收结论", level=1)
    doc.add_paragraph(
        "当前测试量已从基础功能验证提升到 reload、批量回归、并发压测与混合流量组合：基础 65 条样本、reload 3 条、批量 400 条样本、"
        "ApacheBench 6000 次并发请求和 2400 条混合流量均通过，并已由 run_final_acceptance.sh 串联为一键最终验收。"
        "该用例集接近课程项目可承受的生产化测试强度，可作为后续回归基线。"
    )

    doc.save(OUT_06)


def build_project_report_doc() -> None:
    """Generate 07_项目报告_LiteWAF-NGX.docx."""
    doc = _new_doc("07_项目报告", "LiteWAF-NGX 软件项目总结报告")

    doc.add_heading("1. 引言", level=1)
    doc.add_heading("1.1 编写目的", level=2)
    doc.add_paragraph(
        "本项目报告用于总结 LiteWAF-NGX 从需求分析、总体设计、详细设计、模块实现、测试验证到最终交付的全过程。"
        "报告参考课程软件项目报告的组织方式，面向评审教师、开发成员、测试人员和后续维护者，说明项目目标、实现内容、测试结果、风险边界和改进方向。"
    )
    doc.add_heading("1.2 项目背景", level=2)
    doc.add_paragraph(
        "Web 应用常见攻击如 SQL 注入、跨站脚本、目录穿越和扫描器探测，会在请求进入后端应用前造成安全风险。"
        "LiteWAF-NGX 选择在 Nginx HTTP 模块中实现轻量级 WAF，利用 Nginx 前置网关位置完成访问控制、规则检测、动态封禁和日志审计。"
    )
    doc.add_heading("1.3 项目范围", level=2)
    _add_bullets(doc, [
        "实现 Nginx ACCESS_PHASE 模块，支持 location 级配置。",
        "实现 CIDR 黑白名单、X-Forwarded-For 取源地址、规则文件加载和评分阈值。",
        "实现 SQLi、RFI、Traversal、XSS、Evade、Upload、Scanner 等规则。",
        "实现共享漏桶动态封禁和 JSON Lines 审计日志。",
        "形成完整文档、测试脚本、测试用例、压测脚本和演示脚本。",
    ])

    doc.add_heading("2. 综合描述", level=1)
    doc.add_heading("2.1 产品定位", level=2)
    doc.add_paragraph(
        "LiteWAF-NGX 是课程设计级轻量 Web 应用防火墙。它不是商业 WAF 的完整替代，而是用于展示 WAF 核心机制的可运行系统："
        "规则可读、配置可调、日志可解释、测试可复现。"
    )
    doc.add_heading("2.2 用户与使用场景", level=2)
    _add_table(doc, ["用户类别", "主要需求", "使用方式"], [
        ("课程评审人员", "快速确认功能完整性和工程规范。", "阅读 01-08 文档，运行最终验收脚本，观看 1 分钟演示。"),
        ("开发人员", "理解模块边界、接口和实现细节。", "阅读 02/03 文档，查看 Nginx 模块与规则引擎代码。"),
        ("测试人员", "执行回归、指标统计和压测。", "阅读 05/06 文档，运行 run_final_acceptance.sh。"),
        ("后续维护者", "扩展规则、动态封禁和部署方式。", "阅读 08 文档汇总和未来增强清单。"),
    ])
    doc.add_heading("2.3 运行环境", level=2)
    _add_table(doc, ["项目", "当前验证环境"], [
        ("操作系统", "Darwin arm64，内核 25.2.0；课程 Linux 环境可按相同流程复现。"),
        ("Nginx", "nginx/1.31.1 源码树，使用 --add-module 静态编译 LiteWAF 模块。"),
        ("依赖", "PCRE2、clang/gcc、make、bash、curl、python3、ApacheBench、Docker。"),
        ("Docker", "Docker 29.5.3 已通过 compose 构建与容器最终验收。"),
    ])

    doc.add_heading("3. 需求与设计概要", level=1)
    _add_table(doc, ["需求类别", "设计响应", "实现状态"], [
        ("功能需求", "启用 WAF 后阻断 SQLi、XSS、RFI、Traversal、Scanner、高频访问。", "已实现并通过最终验收。"),
        ("配置需求", "规则、阈值、名单、动态封禁参数、日志路径通过 Nginx 配置控制。", "已实现。"),
        ("日志需求", "每次拦截写入 JSON Lines，记录规则、分值、状态码和耗时。", "已实现，并通过 JSON 解析验证。"),
        ("测试需求", "至少 20 攻击样本、20 正常样本，统计 TP/TN/FP/FN。", "已扩展至 65 基础样本、400 批量样本和 6000 次压测请求。"),
        ("工程需求", "提供 README、配置、规则、脚本、关键代码说明和答辩材料。", "已形成 01-08 文档与演示脚本。"),
    ])

    doc.add_heading("4. 系统实现总结", level=1)
    _add_table(doc, ["模块", "实现内容", "关键文件"], [
        ("Nginx 模块", "配置解析、ACCESS_PHASE 挂载、请求字段抽取、处理链路编排。", "ngx_http_lite_waf_module/ngx_http_lite_waf_module.c"),
        ("访问控制", "IPv4 CIDR 白名单优先、黑名单拦截、XFF 取源地址。", "ngx_http_lite_waf_module/ngx_http_lite_waf_module.c"),
        ("规则引擎", "规则解析、规范化、str/rx 匹配、分类评分和阈值决策。", "include/lwaf_rule_engine.h；src/lwaf_rule_engine.c"),
        ("动态封禁", "共享漏桶计数，默认容量 20、满桶 10 秒泄漏、溢出后封禁 60 秒。", "ngx_http_lite_waf_module/ngx_http_lite_waf_module.c"),
        ("审计日志", "JSON Lines 写入，字符串转义，记录规则和耗时。", "ngx_http_lite_waf_module/ngx_http_lite_waf_module.c"),
        ("测试工具", "基础回归、reload、批量回归、压测、soak、指标统计、一键最终验收。", "scripts/"),
    ])

    doc.add_heading("5. 测试与验收结果", level=1)
    _add_table(doc, ["测试项", "规模", "结果"], [
        ("规则引擎单元测试", "21 条规则加载与样本命中", "通过。"),
        ("基础端到端回归", "65 条样本", "65/65 通过；TP=25、TN=40、FP=0、FN=0。"),
        ("规则 reload", "3 条样本", "3/3 通过；TP=1、TN=2、FP=0、FN=0。"),
        ("批量回归", "400 条样本", "400/400 通过；TP=200、TN=200、FP=0、FN=0。"),
        ("真实 POST BODY", "8 条样本", "8/8 通过；TP=6、TN=2、FP=0、FN=0。"),
        ("多 worker 共享封禁", "10 条样本", "10/10 通过；TP=4、TN=6、FP=0、FN=0。"),
        ("漏桶算法回归", "8 条样本", "8/8 通过；验证等待泄漏后可继续放行。"),
        ("长稳混合流量", "2400 条样本", "2400/2400 通过；攻击 822、正常 1578。"),
        ("正常流量压测", "5000 请求，并发 50", "失败 0；约 43644 req/s；平均 1.146 ms。"),
        ("规则命中压测", "1000 请求，并发 20", "失败 0；1000 个非 2xx 阻断；约 35312 req/s。"),
        ("日志解析", "基础 25 行，压测 1212 行，多 worker 4 行", "全部可被 Python 标准 json 模块解析。"),
        ("最终验收", "run_final_acceptance.sh", "输出 FINAL ACCEPTANCE PASSED。"),
    ])

    doc.add_heading("6. 项目风险与边界", level=1)
    _add_table(doc, ["风险/边界", "说明", "处理策略"], [
        ("请求体捕获上限", "Nginx 模块按固定上限捕获 body 前缀，避免大上传消耗过多内存。", "后续可按内容类型做更细粒度解析。"),
        ("共享封禁观测不足", "shared memory 表已生效，但暂无运行期查看接口。", "后续增加状态导出或管理接口。"),
        ("日志同步写入", "高并发下可能增加 I/O 延迟。", "后续增加缓冲、异步写入和日志轮转适配。"),
        ("跨平台矩阵仍可拓展", "已通过 macOS arm64 与 Docker Linux/arm64；Linux/amd64 可由 CI 继续覆盖。", "后续增加更多平台与长周期压测。"),
    ])

    doc.add_heading("7. 结论与展望", level=1)
    doc.add_paragraph(
        "LiteWAF-NGX 已完成课程设计预期目标：系统可以编译、配置、运行、阻断攻击、放行正常请求、检测真实 POST BODY、在多 worker 间共享动态封禁状态、写入可解析审计日志，并通过最终验收脚本复现完整测试。"
        "后续可从更细粒度请求体解析、共享状态观测、跨架构矩阵、长周期观测和可视化报告方向继续增强。"
    )

    doc.save(OUT_07)


def build_document_summary_doc() -> None:
    """Generate 08_文档汇总_LiteWAF-NGX.docx."""
    doc = _new_doc("08_文档汇总", "LiteWAF-NGX 过程文档与交付物汇总")

    doc.add_heading("1. 文档目的", level=1)
    doc.add_paragraph(
        "本文档用于汇总 LiteWAF-NGX 项目从设计到实现、测试、报告和演示的全部过程文档，说明各文档之间的关系、阅读顺序、交付状态和维护建议。"
    )

    doc.add_heading("2. 文档范围", level=1)
    _add_bullets(doc, [
        "覆盖 01-08 正式 Word 文档。",
        "覆盖测试操作手册、测试用例说明、功能实现清单和演示视频脚本等 Markdown 支撑材料。",
        "覆盖核心代码、配置、规则、脚本和最终验收入口。",
    ])

    doc.add_heading("3. 正式文档清单", level=1)
    _add_table(doc, ["编号", "文档名称", "定位", "当前状态"], [
        ("01", "产品总体设计文档", "说明项目背景、目标、总体方案、分工和验收标准。", "已提供。"),
        ("02", "产品设计文档", "说明配置指令、规则文件、数据结构、算法、接口和测试设计。", "已提供。"),
        ("03", "产品实现说明", "从项目结构到模块实现，说明当前代码如何落地设计。", "已生成并更新。"),
        ("04", "产品功能说明", "面向使用者说明功能、配置、操作和验收方式。", "已生成并更新。"),
        ("05", "产品测试说明", "说明测试准备、平台、数据、流程、指标和最终验收。", "最终版已生成。"),
        ("06", "测试用例说明", "按测试报告格式列出接口路径、功能、安全、日志、性能用例。", "最终版已生成。"),
        ("07", "项目报告", "总结项目背景、设计、实现、测试、风险和结论。", "本次生成。"),
        ("08", "文档汇总", "汇总全部过程文档和交付物关系。", "本次生成。"),
    ])

    doc.add_heading("4. 支撑材料清单", level=1)
    _add_table(doc, ["类别", "文件", "用途"], [
        ("功能清单", "docs/功能实现清单.md", "标明已实现、下一步和未来可增强功能。"),
        ("测试操作", "docs/05_产品测试操作手册_LiteWAF-NGX.md", "提供可直接执行的测试命令和排错说明。"),
        ("测试用例", "docs/06_测试用例说明_LiteWAF-NGX.md", "提供 Markdown 版测试用例说明。"),
        ("演示脚本", "docs/演示视频脚本_1分钟_LiteWAF-NGX.md", "用于录制 1 分钟无字幕产品演示视频。"),
        ("成员 C 材料", "docs/member_c_requirements.md；docs/member_c_test_cases.md", "记录 C 模块需求和早期测试样本。"),
    ])

    doc.add_heading("5. 代码与运行交付物", level=1)
    _add_table(doc, ["类别", "路径", "说明"], [
        ("Nginx 模块", "ngx_http_lite_waf_module/", "核心 WAF 模块源码和 Nginx addon 配置。"),
        ("规则引擎", "include/；src/", "B 规则引擎公共 API 与实现。"),
        ("默认规则", "conf/litewaf_rules.conf", "21 条 MVP 规则。"),
        ("压测配置", "conf/nginx_litewaf_volume_test.conf", "18011 独立压测配置，关闭动态封禁。"),
        ("测试脚本", "scripts/run_waf_tests.sh；scripts/run_waf_post_body_tests.sh；scripts/run_waf_multiworker_tests.sh；scripts/run_waf_reload_tests.sh；scripts/run_waf_volume_tests.py；scripts/run_waf_load_tests.sh；scripts/run_waf_soak_tests.py", "基础回归、POST BODY、多 worker、reload、批量回归、压测和长稳混合流量。"),
        ("最终验收", "scripts/run_final_acceptance.sh", "一键执行最终验收。"),
        ("文档生成", "tools/build_product_docs.py", "生成 03-08 Word 文档。"),
    ])

    doc.add_heading("6. 推荐阅读顺序", level=1)
    _add_numbered(doc, [
        "先读 01，理解项目目标、背景和验收标准。",
        "再读 02，理解配置、规则、算法和模块接口。",
        "阅读 03，确认代码结构和具体实现。",
        "阅读 04，了解产品功能和使用方式。",
        "阅读 05/06，掌握测试准备、测试用例和最终验收流程。",
        "阅读 07，获得项目总结和风险边界。",
        "阅读本 08，核对文档与交付物是否齐全。",
    ])

    doc.add_heading("7. 交付检查表", level=1)
    _add_table(doc, ["检查项", "状态", "说明"], [
        ("代码", "完成", "A/B/C 代码整合到 dev，并推送 origin/dev。"),
        ("规则", "完成", "默认规则集覆盖主要攻击类别。"),
        ("测试", "完成", "run_final_acceptance.sh 通过最终验收。"),
        ("文档", "完成", "01-08 文档齐备。"),
        ("演示", "完成", "已提供 1 分钟无字幕演示视频脚本。"),
        ("边界说明", "完成", "POST BODY、shared memory 已转入已实现；新增运行期观测、multipart 解析等未来增强项。"),
    ])

    doc.add_heading("8. 维护建议", level=1)
    doc.add_paragraph(
        "后续每次修改规则、Nginx 模块、动态封禁或日志格式后，应先运行 scripts/run_final_acceptance.sh，再执行 tools/build_product_docs.py 更新 03-08 文档，"
        "并同步检查演示脚本是否仍符合当前功能和指标。"
    )

    doc.save(OUT_08)


def main() -> None:
    """Build all product documents."""
    build_implementation_doc()
    build_function_doc()
    build_test_doc()
    build_test_case_doc()
    build_project_report_doc()
    build_document_summary_doc()
    print(f"Generated {OUT_03}")
    print(f"Generated {OUT_04}")
    print(f"Generated {OUT_05}")
    print(f"Generated {OUT_06}")
    print(f"Generated {OUT_07}")
    print(f"Generated {OUT_08}")


if __name__ == "__main__":
    main()
