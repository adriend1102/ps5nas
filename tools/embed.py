#!/usr/bin/env python3
"""Convierte web/index.html en src/webui.h (array de C)."""
import sys

src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
with open(dst, "w") as f:
    f.write("/* Generado por tools/embed.py a partir de web/index.html. No editar. */\n")
    f.write("#pragma once\n#include <stddef.h>\n")
    f.write("static const unsigned char web_index_html[] = {\n")
    for i in range(0, len(data), 16):
        f.write("  " + ",".join(str(b) for b in data[i:i+16]) + ",\n")
    f.write("};\n")
    f.write("static const size_t web_index_html_len = %d;\n" % len(data))
