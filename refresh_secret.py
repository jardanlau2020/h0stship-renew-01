# -*- coding: utf-8 -*-
"""从 cookies.txt 取出 JEXACTYL_SESSION 的值，只输出值本身（供 gh secret set 使用）。

兼容两种格式：
  1) cookies.txt 实际格式：每行 `NAME=value`
  2) Netscape cookie 文件：tab 分隔 7 列，第 6 列是名字、第 7 列是值

找不到就退出码 1，不打印任何 cookie 内容。
"""
import re
import sys

NAMES = ("JEXACTYL_SESSION",)


def parse(path="cookies.txt"):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "\t" in s:
                p = [x.strip() for x in s.split("\t")]
                if len(p) >= 7 and p[5] in NAMES:
                    return p[6]
                continue
            for name in NAMES:
                if s.startswith(name + "="):
                    return s.split("=", 1)[1].strip()
            m = re.search(r"\bJEXACTYL_SESSION\b[=\t :]+([^\s;]+)", s)
            if m:
                return m.group(1).strip()
    return ""


def main():
    try:
        val = parse()
    except FileNotFoundError:
        print("cookies.txt 不存在", file=sys.stderr)
        sys.exit(1)
    if not val:
        print("cookies.txt 里没有 JEXACTYL_SESSION", file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(val)


if __name__ == "__main__":
    main()
