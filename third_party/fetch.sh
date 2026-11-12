#!/bin/sh
# Descarga las versiones fijadas de wolfSSL y wolfSSH (GPLv3) usadas por el
# servidor SFTP de ps5share, y cJSON (MIT) para la API compatible con Bitwarden.
set -e
cd "$(dirname "$0")"
WOLFSSL_TAG=v5.9.4-stable
WOLFSSH_TAG=v1.6.0-stable
CJSON_TAG=v1.7.19
[ -d wolfssl ] || git -c advice.detachedHead=false clone -q --depth 1 -b $WOLFSSL_TAG https://github.com/wolfSSL/wolfssl
[ -d wolfssh ] || git -c advice.detachedHead=false clone -q --depth 1 -b $WOLFSSH_TAG https://github.com/wolfSSL/wolfssh
[ -d cjson ] || git -c advice.detachedHead=false clone -q --depth 1 -b $CJSON_TAG https://github.com/DaveGamble/cJSON cjson
echo "cJSON $CJSON_TAG"
echo "wolfSSL $WOLFSSL_TAG y wolfSSH $WOLFSSH_TAG listos en third_party/"
