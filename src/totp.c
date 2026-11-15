/* PS5NAS - verificación en dos pasos (TOTP, RFC 6238)
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Códigos de 6 dígitos cada 30 s con HMAC-SHA1, compatibles con Google
   Authenticator, Microsoft Authenticator, Aegis, Bitwarden, etc. */

#include <ctype.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "totp.h"


uint32_t
totp_code(const uint8_t *key, size_t keylen, uint64_t step) {
  Hmac h;
  uint8_t msg[8], d[WC_SHA_DIGEST_SIZE];
  for(int i=7; i>=0; i--) {
    msg[i] = (uint8_t)(step & 0xff);
    step >>= 8;
  }
  if(wc_HmacInit(&h, NULL, INVALID_DEVID) ||
     wc_HmacSetKey(&h, WC_SHA, key, (word32)keylen) ||
     wc_HmacUpdate(&h, msg, sizeof(msg)) ||
     wc_HmacFinal(&h, d)) {
    wc_HmacFree(&h);
    return 0xffffffffu;   /* nunca coincide con 6 dígitos */
  }
  wc_HmacFree(&h);
  int off = d[WC_SHA_DIGEST_SIZE - 1] & 0x0f;
  uint32_t bin = ((uint32_t)(d[off] & 0x7f) << 24) | ((uint32_t)d[off+1] << 16) |
                 ((uint32_t)d[off+2] << 8) | d[off+3];
  return bin % 1000000u;
}


uint64_t
totp_verify(const uint8_t *key, size_t keylen, const char *code, uint64_t now, uint64_t last) {
  char digits[8];
  size_t n = 0;
  for(const char *p = code; *p; p++) {
    if(*p == ' ' || *p == '-') continue;
    if(!isdigit((unsigned char)*p) || n >= TOTP_DIGITS) return 0;
    digits[n++] = *p;
  }
  if(n != TOTP_DIGITS) return 0;
  digits[n] = 0;
  uint32_t want = 0;
  for(size_t i=0; i<n; i++) want = want * 10 + (uint32_t)(digits[i] - '0');

  uint64_t step = now / TOTP_PERIOD;
  uint64_t found = 0;
  /* Se calculan los tres siempre: mismo tiempo pase lo que pase. */
  for(int d=-1; d<=1; d++) {
    uint64_t s = step + (uint64_t)(int64_t)d;
    if(totp_code(key, keylen, s) == want && s > last && !found) found = s;
  }
  return found;
}


static const char B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";


void
base32_encode(const uint8_t *in, size_t n, char *out, size_t outlen) {
  size_t o = 0;
  uint32_t buf = 0;
  int bits = 0;
  for(size_t i=0; i<n; i++) {
    buf = (buf << 8) | in[i];
    bits += 8;
    while(bits >= 5) {
      if(o + 1 < outlen) out[o++] = B32[(buf >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if(bits > 0 && o + 1 < outlen) out[o++] = B32[(buf << (5 - bits)) & 31];
  if(outlen) out[o < outlen ? o : outlen - 1] = 0;
}


int
base32_decode(const char *in, uint8_t *out, size_t outlen) {
  uint32_t buf = 0;
  int bits = 0;
  size_t o = 0;
  for(const char *p = in; *p; p++) {
    if(*p == '=' || *p == ' ' || *p == '-') continue;
    const char *q = strchr(B32, toupper((unsigned char)*p));
    if(!q || !*q) return -1;
    buf = (buf << 5) | (uint32_t)(q - B32);
    bits += 5;
    if(bits >= 8) {
      if(o >= outlen) return -1;
      out[o++] = (uint8_t)(buf >> (bits - 8));
      bits -= 8;
    }
  }
  return (int)o;
}
