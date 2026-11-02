#!/usr/bin/env bash
# 验证三条改过的规则（1002/1016/1200）行为是否符合预期
set -uo pipefail
PW="${KALI_PWD:-kali}"
EV=/opt/litewaf/src/WAF-lite/build/lwaf_eval
RULES=/opt/litewaf/src/WAF-lite/conf/litewaf_rules.conf

echo "$PW" | sudo -S rsync -a /mnt/hgfs/share/WAF-lite/conf/litewaf_rules.conf "$RULES" 2>&1 | grep -v password || true

chk() { # chk <期望> <path> <args> <说明>
  local want="$1" path="$2" args="$3" desc="$4"
  local out rc
  out=$("$EV" "$RULES" "$path" "$args" "Mozilla/5.0" "" 2>&1); rc=$?
  if [ "$rc" = "2" ]; then got=block; else got=pass; fi
  if [ "$got" = "$want" ]; then echo "  OK   $desc  ($got)"; else
    echo "  BAD  $desc  期望 $want 实际 $got"
    echo "$out" | sed 's/^/       /' | head -4
  fi
}

echo "== 1002 注释标记：multipart 边界不该中，SQL 注释该中"
chk pass "/post" "" "multipart 空 body"
chk block "/" "id=1'-- " "SQL 注释 -- 结尾"

echo "== 1016 LIKE 恒真：英文 like 不该中，LIKE 数字该中"
chk pass "/" "q=dont match commands like bash python perl" "英文 like bash"
chk block "/" "q=1 or 1 like 1" "LIKE 1"

echo "== 1200 点穿越：目录名里的 .. 不该中，真穿越该中"
chk pass "/get/foo../1234" "" "foo../1234"
chk pass "/get/foo.../1234" "" "foo.../1234"
chk block "/get/../../etc/passwd" "" "真穿越 /../"
chk block "/" "file=..%2f..%2fetc%2fpasswd" "编码穿越"

echo "== libinjection 语义：结构型 SQLi 该中"
chk block "/" "id=1 AND 1=1" "1 AND 1=1"
chk block "/" "id=1 OR 2>1" "1 OR 2>1"
chk pass "/" "q=hello world" "普通文本"
