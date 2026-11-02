"""把 s8_eval.py 的样本导出成 s14_bulk_eval2.py 吃的 TSV，好用离线评估器跑千条级。

为什么走离线：1494 条走 HTTP 要 17 分钟（0.7 s/条防 CC 封禁），
而 lwaf_eval 直接调引擎，500 条/秒，3 秒跑完，而且不会因为封禁污染结论。
"""
import io

P = r"D:\网安综设\scripts\s8_eval.py"
OUT_ATTACK = r"D:\网安综设\samples\self_attack.tsv"
OUT_NORMAL = r"D:\网安综设\samples\self_normal.tsv"

src = io.open(P, encoding="utf-8").read()
head = src.split('if __name__')[0]
ns = {}
exec(compile(head, "x", "exec"), ns)


def split_url(u):
    """'/?id=1 UNION SELECT' -> ('/', 'id=1 UNION SELECT')"""
    if "?" not in u:
        return u, ""
    p, q = u.split("?", 1)
    return (p or "/"), q


def rows(items, cat):
    out = []
    for u in items:
        path, query = split_url(u)
        out.append((cat, "GET", path, query, "", "", "", ""))
    return out


def write(path, rows_):
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("category\tmethod\tpath\tquery\tua\tcookie\tbody\theaders\n")
        for r in rows_:
            f.write("\t".join(r) + "\n")


attack = rows(ns["SQLI"], "SQL") + rows(ns["XSS"], "XSS")
normal = rows(ns["NORMAL"], "NORMAL")
write(OUT_ATTACK, attack)
write(OUT_NORMAL, normal)
print(f"attack {len(attack)}（SQL {len(ns['SQLI'])} + XSS {len(ns['XSS'])}），normal {len(normal)}，合计 {len(attack)+len(normal)}")
