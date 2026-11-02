# -*- coding: utf-8 -*-
"""P3 路径穿越补强：
1) 1203/1204/1205/1206/1207 的 zones 加 USER_AGENT —— CRS 的 930 组把
   `cat /root/.ssh/id_rsa`、`/proc/net/tcp` 这类 payload 放进 UA（模拟日志注入），
   原 zones 只扫 URL/ARGS/BODY/COOKIE，整类漏掉。
2) 1205 敏感文件清单补 .aws / .docker / .kube / .npmrc / .git-credentials。
3) 1203 敏感目录补 /proc/net 与 /root/。
"""
import io

BS = chr(92)
BS2 = BS + BS

path = r'D:\网安综设\WAF-lite\conf\litewaf_rules.conf'
s = io.open(path, encoding='utf-8').read()

rules = {}

rules['1203'] = (
    'lwaf_rule id=1203 name="sensitive unix path" type=rx '
    'pattern="/(etc|proc|sys|var/log|root)/" '
    'zones=URL,ARGS,BODY,COOKIE,USER_AGENT score=TRAVERSAL:8 action=score'
)

rules['1204'] = (
    'lwaf_rule id=1204 name="windows system path" type=rx '
    'pattern="[a-z]:[' + BS2 + '/]|system32|winnt|boot' + BS2 + '.ini|win' + BS2 + '.ini'
    '|inetpub|wwwroot|metabase' + BS2 + '.xml" '
    'zones=URL,ARGS,BODY,COOKIE,USER_AGENT score=TRAVERSAL:8 action=score'
)

rules['1205'] = (
    'lwaf_rule id=1205 name="sensitive config file" type=rx '
    'pattern="web' + BS2 + '.config|' + BS2 + '.htaccess|' + BS2 + '.htpasswd'
    '|' + BS2 + '.bash_history|' + BS2 + '.bashrc|id_rsa|php' + BS2 + '.ini'
    '|' + BS2 + '.ssh/|' + BS2 + '.aws/|' + BS2 + '.docker/|' + BS2 + '.kube/'
    '|' + BS2 + '.git-credentials|' + BS2 + '.npmrc" '
    'zones=ARGS,BODY,COOKIE,USER_AGENT score=TRAVERSAL:8 action=score'
)

rules['1206'] = (
    'lwaf_rule id=1206 name="server log path" type=rx '
    'pattern="(apache2?|nginx|tomcat|jboss|weblogic)/logs?/|(access|error)_?log" '
    'zones=ARGS,BODY,COOKIE,USER_AGENT score=TRAVERSAL:8 action=score'
)

rules['1207'] = (
    'lwaf_rule id=1207 name="encoded traversal" type=rx '
    'pattern="%[2]e%[2]e|%[2]52e|%[0]0|%[cC]0%[aA]e" '
    'zones=URL,ARGS,BODY,COOKIE,USER_AGENT score=TRAVERSAL:6 action=score'
)

out, changed = [], 0
for ln in s.split('\n'):
    hit = None
    for rid, newline in rules.items():
        if ln.startswith('lwaf_rule id=' + rid + ' '):
            hit = newline
            break
    if hit is not None:
        out.append(hit)
        changed += 1
    else:
        out.append(ln)

io.open(path, 'w', encoding='utf-8', newline='\n').write('\n'.join(out))
print('replaced', changed)
