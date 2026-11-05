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
mkdir -p "$T/conf"
printf 'set\tftp_enabled\t1\n' > "$T/conf/users.conf"   # las pruebas cubren también FTP
./ps5share-linux -d "$T/conf" > "$T/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$T"' EXIT
# espera a que estén los tres servicios (la primera vez genera las claves SSH)
for i in $(seq 1 60); do
  python3 -c "import socket;[socket.create_connection(('127.0.0.1',p),1).close() for p in (8000,2121,2222)]" 2>/dev/null && break
  sleep 1
done
python3 test/smoke_test.py 127.0.0.1 "$T"
