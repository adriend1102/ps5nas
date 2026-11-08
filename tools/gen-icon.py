#!/usr/bin/env python3
"""Genera app/sce_sys/icon0.png (512x512): un servidor con candado y el
nombre PS5NAS.  Uso: python3 tools/gen-icon.py [salida.png]"""
import sys
from PIL import Image, ImageDraw, ImageFilter, ImageFont

S = 4                      # se dibuja a 4x y se reduce (bordes suaves)
W = 512 * S
out = sys.argv[1] if len(sys.argv) > 1 else "app/sce_sys/icon0.png"
FONT = "/usr/share/fonts/opentype/inter/InterDisplay-Black.otf"

img = Image.new("RGB", (W, W))
d = ImageDraw.Draw(img)
# fondo: degradado azul oscuro
for y in range(W):
    t = y / W
    c = (int(10 + 14 * t), int(24 + 20 * t), int(58 + 40 * t))
    d.line([(0, y), (W, y)], fill=c)
# halo suave detrás del servidor
glow = Image.new("L", (W, W), 0)
ImageDraw.Draw(glow).ellipse([W * .14, W * .04, W * .86, W * .72], fill=110)
glow = glow.filter(ImageFilter.GaussianBlur(60 * S))
img = Image.composite(Image.new("RGB", (W, W), (60, 120, 255)), img, glow)
d = ImageDraw.Draw(img)

def r(x0, y0, x1, y1, rad, fill):
    d.rounded_rectangle([x0 * S, y0 * S, x1 * S, y1 * S], radius=rad * S, fill=fill)

# servidor: tres unidades
units = [(70, (236, 242, 255)), (160, (214, 225, 250)), (250, (190, 206, 242))]
for y, col in units:
    r(96, y, 416, y + 76, 16, col)
    r(118, y + 22, 142, y + 54, 6, (34, 197, 94) if y != 250 else (250, 204, 21))   # LED
    for i in range(4):                                                             # bahías
        r(166 + i * 52, y + 20, 206 + i * 52, y + 56, 6, (120, 140, 190))
    r(392, y + 30, 400, y + 46, 3, (120, 140, 190))

# candado dorado sobre la esquina
cx, top = 372, 214
d.arc([(cx - 50) * S, (top - 4) * S, (cx + 50) * S, (top + 96) * S], 180, 360,
      fill=(255, 214, 102), width=22 * S)
d.line([((cx - 50) * S + 11 * S, (top + 46) * S), ((cx - 50) * S + 11 * S, (top + 86) * S)],
       fill=(255, 214, 102), width=22 * S)
d.line([((cx + 50) * S - 11 * S, (top + 46) * S), ((cx + 50) * S - 11 * S, (top + 86) * S)],
       fill=(255, 214, 102), width=22 * S)
r(cx - 76, top + 76, cx + 76, top + 196, 22, (8, 20, 48))           # borde
r(cx - 68, top + 84, cx + 68, top + 188, 18, (250, 191, 36))
r(cx - 68, top + 84, cx + 68, top + 112, 18, (255, 220, 120))
d.ellipse([(cx - 14) * S, (top + 118) * S, (cx + 14) * S, (top + 146) * S], fill=(92, 58, 0))
r(cx - 7, top + 136, cx + 7, top + 168, 5, (92, 58, 0))

# nombre
f = ImageFont.truetype(FONT, 104 * S)
text = "PS5NAS"
tw = d.textlength(text, font=f)
d.text(((W - tw) / 2, 372 * S), text, font=f, fill=(255, 255, 255))

img.resize((512, 512), Image.LANCZOS).save(out, optimize=True)
print("icono:", out)
