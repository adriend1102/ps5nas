#!/usr/bin/env python3
"""Convierte un archivo en una cabecera de C con un array.

    embed.py web/index.html src/webui.h                 (web_index_html)
    embed.py gateway/ps5nas-gateway.sh src/gwscript.h gateway_script
"""
import sys

src, dst = sys.argv[1], sys.argv[2]
name = sys.argv[3] if len(sys.argv) > 3 else "web_index_html"
data = open(src, "rb").read()
with open(dst, "w") as f:
    f.write("/* Generado por tools/embed.py a partir de %s. No editar. */\n" % src)
    f.write("#pragma once\n#include <stddef.h>\n")
    f.write("static const unsigned char %s[] = {\n" % name)
    for i in range(0, len(data), 16):
        f.write("  " + ",".join(str(b) for b in data[i:i+16]) + ",\n")
    f.write("};\n")
    f.write("static const size_t %s_len = %d;\n" % (name, len(data)))
