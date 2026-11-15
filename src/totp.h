/* PS5NAS - verificación en dos pasos (TOTP, RFC 6238)
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE. */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define TOTP_SECRET_LEN 20      /* 160 bits, como Google Authenticator */
#define TOTP_B32_LEN    32      /* 20 bytes en base32 */
#define TOTP_PERIOD     30
#define TOTP_DIGITS     6

/* Código de 6 dígitos para el paso STEP (tiempo/30). */
uint32_t totp_code(const uint8_t *key, size_t keylen, uint64_t step);

/* Comprueba CODE (6 dígitos) con una tolerancia de ±1 paso.  Devuelve el
   paso que coincide (>0) o 0 si no vale.  Rechaza pasos <= LAST (evita que
   el mismo código se use dos veces). */
uint64_t totp_verify(const uint8_t *key, size_t keylen, const char *code, uint64_t now,
                     uint64_t last);

/* Base32 (RFC 4648, sin relleno). */
void base32_encode(const uint8_t *in, size_t n, char *out, size_t outlen);
int  base32_decode(const char *in, uint8_t *out, size_t outlen);   /* bytes o -1 */
