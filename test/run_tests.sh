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
mkdir -p "$T/conf" "$T/ca"
# CA y certificado de pruebas para el servidor SMTP falso
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=ps5share test CA" \
  -keyout "$T/ca/ca.key" -out "$T/ca/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout "$T/ca/srv.key" \
  -out "$T/ca/srv.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\n' > "$T/ca/ext"
openssl x509 -req -in "$T/ca/srv.csr" -CA "$T/ca/ca.pem" -CAkey "$T/ca/ca.key" -CAcreateserial \
  -days 2 -extfile "$T/ca/ext" -out "$T/ca/srv.pem" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
  -keyout "$T/ca/self.key" -out "$T/ca/self.pem" 2>/dev/null
export PS5SHARE_TEST_CA="$T/ca/ca.pem"
printf 'set\tftp_enabled\t1\n' > "$T/conf/users.conf"   # las pruebas cubren también FTP
./ps5share-linux -d "$T/conf" > "$T/server.log" 2>&1 &
echo $! > "$T/server.pid"     # smoke_test.py lo reinicia para probar la persistencia
trap 'kill $(cat "$T/server.pid") 2>/dev/null; rm -rf "$T"' EXIT
# espera a que estén los tres servicios (la primera vez genera las claves SSH)
for i in $(seq 1 60); do
  python3 -c "import socket;[socket.create_connection(('127.0.0.1',p),1).close() for p in (8000,2121,2222,8443)]" 2>/dev/null && break
  sleep 1
done
python3 test/smoke_test.py 127.0.0.1 "$T"
# Gestor de contraseñas (API de Bitwarden por HTTPS + web).  Con BW_CLI=/ruta/a/bw
# se prueba además con la CLI oficial de Bitwarden.
python3 test/vault_test.py "$T/conf"
