/* ps5share - criptografía compatible con los clientes de Bitwarden
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Esquema de Bitwarden (KDF PBKDF2-SHA256):
     masterKey  = PBKDF2(contraseña, sal = correo en minúsculas, N iteraciones)
     hash       = PBKDF2(masterKey, sal = contraseña, 1 iteración)   (lo que se envía)
     stretched  = HKDF-Expand(masterKey, "enc") || HKDF-Expand(masterKey, "mac")
     userKey    = 64 bytes aleatorios (32 cifrado + 32 MAC)
     EncString  = "2." b64(iv) "|" b64(AES-256-CBC) "|" b64(HMAC-SHA256(iv||ct))  */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define BW_KDF_ITER   600000
#define BW_KEY_LEN    64

/* Base64 estándar con relleno.  Devuelve la longitud escrita o -1. */
int   bw_b64_enc(const uint8_t *in, size_t n, char *out, size_t outlen);
/* Acepta también base64url y sin relleno.  Devuelve bytes o -1. */
int   bw_b64_dec(const char *in, size_t inlen, uint8_t *out, size_t outlen);

void  bw_hmac256(const uint8_t *key, size_t klen, const void *msg, size_t mlen, uint8_t out[32]);
void  bw_pbkdf2(const uint8_t *pass, size_t plen, const uint8_t *salt, size_t slen,
                uint32_t iter, uint8_t out[32]);
void  bw_sha256(const void *msg, size_t len, uint8_t out[32]);

void  bw_master_key(const char *password, const char *email, uint32_t iter, uint8_t mk[32]);
/* Hash de la contraseña maestra en base64 (44 caracteres). */
void  bw_master_hash(const uint8_t mk[32], const char *password, char out[64]);
void  bw_stretch(const uint8_t mk[32], uint8_t key[BW_KEY_LEN]);

/* EncString tipo 2.  bw_enc devuelve memoria de malloc (o NULL). */
char *bw_enc(const uint8_t key[BW_KEY_LEN], const void *plain, size_t n);
char *bw_enc_str(const uint8_t key[BW_KEY_LEN], const char *s);
/* Descifra; *OUT (malloc, terminada en 0) y *OUTLEN.  0 o -1. */
int   bw_dec(const uint8_t key[BW_KEY_LEN], const char *enc, uint8_t **out, size_t *outlen);

/* Par RSA-2048: privada en PKCS#8 DER, pública SPKI en base64. */
int   bw_rsa_keypair(uint8_t **pkcs8, size_t *p8len, char **spki_b64);

void  bw_random(uint8_t *buf, size_t n);
void  bw_uuid(char out[37]);
/* Microsegundos desde 1970. */
long long bw_now_us(void);
/* "2026-11-12T21:46:00.123456Z" */
void  bw_iso(long long us, char out[40]);
/* Interpreta una fecha ISO 8601 (UTC).  -1 si no es válida. */
long long bw_parse_iso(const char *s);

/* JWT HS256. */
char *bw_jwt_sign(const uint8_t key[32], const char *payload_json);
/* Devuelve el JSON del payload (malloc) si la firma es válida. */
char *bw_jwt_verify(const uint8_t key[32], const char *jwt);

int   bw_consttime_eq(const void *a, const void *b, size_t n);
