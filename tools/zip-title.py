#!/usr/bin/env python3
"""Empaqueta la carpeta de un título PS5 en un .zip con todas las entradas
en 0777: la consola no arranca apps cuyos archivos no son 777 (CE-107750-0)
y muchas herramientas respetan los permisos del zip al extraer."""
import os, sys, time, zipfile

src, dst = sys.argv[1].rstrip("/"), sys.argv[2]
top = os.path.basename(src)
stamp = (2026, 1, 1, 0, 0, 0)   # fecha fija: zip reproducible
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    entries = []
    for root, dirs, files in os.walk(src):
        dirs.sort()
        rel = os.path.relpath(root, src)
        base = top if rel == "." else f"{top}/{rel}"
        entries.append((base + "/", None))
        for f in sorted(files):
            entries.append((f"{base}/{f}", os.path.join(root, f)))
    for name, path in entries:
        info = zipfile.ZipInfo(name, stamp)
        info.create_system = 3
        if path is None:
            info.external_attr = (0o40777 << 16) | 0x10
            z.writestr(info, b"")
        else:
            info.external_attr = 0o100777 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(path, "rb") as fh:
                z.writestr(info, fh.read())
print(dst)
