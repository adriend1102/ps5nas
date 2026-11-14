#!/usr/bin/env python3
"""Mete las traducciones de web/i18n/strings.py y web/i18n/runtime.js en
web/index.html (entre los marcadores I18N).  Con --check lista los textos de
la página que aún no tienen traducción.

    python3 tools/i18n.py            # actualiza web/index.html
    python3 tools/i18n.py --check    # textos sin traducir
"""
import json, os, re, sys, html as H

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "web", "i18n"))
from strings import STRINGS, PATTERNS  # noqa: E402

PAGE = os.path.join(ROOT, "web", "index.html")
BEGIN, END = "<!--I18N-BEGIN-->", "<!--I18N-END-->"


def data():
    d = {"en": {}, "de": {}, "pat": []}
    for es, en, de in STRINGS:
        if es in d["en"] and (d["en"][es] != en or d["de"][es] != de):
            sys.exit(f"traducción repetida con otro texto: {es!r}")
        d["en"][es], d["de"][es] = en, de
    d["pat"] = [list(p) for p in PATTERNS]
    for p in PATTERNS:
        re.compile(p[0])
    return d


def build():
    page = open(PAGE, encoding="utf-8").read()
    js = open(os.path.join(ROOT, "web", "i18n", "runtime.js"), encoding="utf-8").read()
    block = (BEGIN + "\n<script>\nconst I18N_DATA = " +
             json.dumps(data(), ensure_ascii=False, separators=(",", ":")) +
             ";\n" + js + "</script>\n" + END)
    if BEGIN in page:
        page = re.sub(re.escape(BEGIN) + ".*?" + re.escape(END), lambda m: block, page, flags=re.S)
    else:
        i = page.index("<script>")
        page = page[:i] + block + "\n\n" + page[i:]
    open(PAGE, "w", encoding="utf-8").write(page)
    print("web/index.html: %d textos y %d patrones" % (len(STRINGS), len(PATTERNS)))


def check():
    """Textos en español de la página sin traducción (aproximado)."""
    d = data()
    pats = [re.compile(p[0]) for p in PATTERNS]
    page = open(PAGE, encoding="utf-8").read()
    page = re.sub(re.escape(BEGIN) + ".*?" + re.escape(END), "", page, flags=re.S)
    i = page.index("<script>")
    markup, script = page[:i], page[i:]
    markup = re.sub(r"<style>.*?</style>|<svg.*?</svg>", "", markup, flags=re.S)
    cands = set()
    for m in re.finditer(r">([^<>]+)<", markup):
        cands.add(re.sub(r"\s+", " ", H.unescape(m.group(1))).strip())
    for m in re.finditer(r'(?:placeholder|title)="([^"]*)"', markup):
        cands.add(H.unescape(m.group(1)).strip())
    for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)"', script):
        s = m.group(1).strip()
        if " " in s and re.search(r"[a-záéíóúñ]{3}", s) and not re.match(r"^[#.\[]|^/api", s):
            cands.add(s)
    missing = sorted(c for c in cands if re.search(r"[A-Za-zÁÉÍÓÚáéíóúñ]{3}", c)
                     and c not in d["en"] and not any(p.match(c) for p in pats))
    for c in missing:
        print(repr(c))
    print(len(missing), "posibles textos sin traducir", file=sys.stderr)


if __name__ == "__main__":
    check() if "--check" in sys.argv else build()
