#!/bin/sh
# Compila el payload y la app de la pantalla de inicio, y prepara
# dist/<TITLEID>.zip (la carpeta del título, con permisos 0777 como pide
# la consola) listo para copiar a /data/homebrew o publicar.
#
#   export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
#   ./tools/build-app.sh
set -e
cd "$(dirname "$0")/.."

make -f Makefile.ps5
mkdir -p app/assets
cp ps5share.elf app/assets/ps5share.elf
make -C app app

TITLE=$(python3 -c "import json;print(json.load(open('app/sce_sys/param.json'))['titleId'])")
mkdir -p dist
python3 tools/zip-title.py "app/dist/$TITLE" "dist/$TITLE.zip"
echo "Listo: dist/$TITLE.zip"
