#!/bin/sh
# Compila la versión Linux, prepara datos de prueba y lanza las pruebas.
set -e
cd "$(dirname "$0")/.."
make -f Makefile.linux
T=$(mktemp -d)
mkdir -p "$T/share/movies/sub" "$T/share/inbox" "$T/secret"
echo "top secret" > "$T/secret/pw.txt"
head -c 3000000 /dev/urandom > "$T/share/movies/big.bin"
echo hola > "$T/share/movies/sub/a.txt"
ln -s "$T/secret" "$T/share/movies/escape"
./ps5share-linux -d "$T/conf" > "$T/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$T"' EXIT
sleep 1
python3 test/smoke_test.py 127.0.0.1 "$T"
