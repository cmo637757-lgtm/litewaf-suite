# -*- coding: utf-8 -*-
"""1016 的 pattern 里直接写了裸双引号，key=value 解析器会把它当成字符串结尾，
报 `malformed key=value token`。规则文件里双引号必须写成 \\"（反斜杠 + 引号）。
"""
import io

BS = chr(92)
BS2 = BS + BS
Q = BS + '"'          # 规则文件里的 \\"（转义的双引号）

p1016 = (
    '(?i)' + BS2 + 'b(and|or)' + BS2 + 's+true' + BS2 + 'b|'
    "['" + Q + ']?' + BS2 + "w+['" + Q + ']?' + BS2 + 's+like' + BS2 + 's+' + "['" + Q + ']?'
    '(' + BS2 + "d|['" + Q + "]%_])"
)

path = r'D:\网安综设\WAF-lite\conf\litewaf_rules.conf'
s = io.open(path, encoding='utf-8').read()
out, n = [], 0
for ln in s.split('\n'):
    if ln.startswith('lwaf_rule id=1016 '):
        ln = ('lwaf_rule id=1016 name="sql true like tautology" type=rx pattern="'
              + p1016 + '" zones=URL,ARGS,BODY,COOKIE score=SQL:8 action=score')
        n += 1
    out.append(ln)
io.open(path, 'w', encoding='utf-8', newline='\n').write('\n'.join(out))
print('rewrote', n)
print('1016 ->', p1016)
