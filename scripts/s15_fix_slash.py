# -*- coding: utf-8 -*-
"""修 1016 / 1200 的反斜杠转义：规则文件里必须写两个反斜杠，
引擎解析时会吃掉一层；只写一个的话 `\\.` 会变成 `.`（任意字符），
`/api/v1/products` 这种路径全被 1200 当成穿越拦掉。

用 chr(92) 拼接，绕开 Python 字符串和 shell 的多层转义。
"""
import io

BS = chr(92)          # 单个反斜杠
BS2 = BS + BS         # 规则文件里要写的两个反斜杠

# 1200: (?:^|[\\/])\\.\\.(?:[\\/]|$)
p1200 = '(?:^|[' + BS2 + '/])' + BS2 + '.' + BS2 + '.' + '(?:[' + BS2 + '/]|$)'

# 1016: (?i)\\b(and|or)\\s+true\\b|['"]?\\w+['"]?\\s+like\\s+['"]?(\\d|['"%_])
p1016 = (
    '(?i)' + BS2 + 'b(and|or)' + BS2 + 's+true' + BS2 + 'b|'
    "['" + '"]?' + BS2 + "w+['" + '"]?' + BS2 + 's+like' + BS2 + 's+' + "['" + '"]?'
    '(' + BS2 + "d|['" + '"]' + '%_])'
)

path = r'D:\网安综设\WAF-lite\conf\litewaf_rules.conf'
s = io.open(path, encoding='utf-8').read()
out = []
n = 0
for ln in s.split('\n'):
    if ln.startswith('lwaf_rule id=1200 '):
        ln = ('lwaf_rule id=1200 name="double dot traversal" type=rx pattern="'
              + p1200 + '" zones=URL,ARGS,BODY,COOKIE score=TRAVERSAL:8 action=score')
        n += 1
    elif ln.startswith('lwaf_rule id=1016 '):
        ln = ('lwaf_rule id=1016 name="sql true like tautology" type=rx pattern="'
              + p1016 + '" zones=URL,ARGS,BODY,COOKIE score=SQL:8 action=score')
        n += 1
    out.append(ln)

io.open(path, 'w', encoding='utf-8', newline='\n').write('\n'.join(out))
print('rewrote', n, 'rules')
print('1200 ->', p1200)
print('1016 ->', p1016)
