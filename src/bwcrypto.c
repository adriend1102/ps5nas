/* ps5share - criptografía compatible con los clientes de Bitwarden
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "bwcrypto.h"
#include "config.h"


static void
wipe(void *p, size_t n) {
  volatile uint8_t *v = p;
  while(n--) *v++ = 0;
}


int
bw_consttime_eq(const void *a, const void *b, size_t n) {
  const uint8_t *x = a, *y = b;
  uint8_t d = 0;
  for(size_t i=0; i<n; i++) d |= x[i] ^ y[i];
  return d == 0;
}


void
bw_random(uint8_t *buf, size_t n) {
  cfg_random(buf, n);
}


/* ------------------------------------------------------------------ */
/* Base64                                                              */
/* ------------------------------------------------------------------ */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


int
bw_b64_enc(const uint8_t *in, size_t n, char *out, size_t outlen) {
  size_t need = ((n + 2) / 3) * 4 + 1, o = 0;
  if(outlen < need) return -1;
  for(size_t i=0; i<n; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    if(i + 1 < n) v |= (uint32_t)in[i+1] << 8;
    if(i + 2 < n) v |= in[i+2];
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = i + 1 < n ? B64[(v >> 6) & 63] : '=';
    out[o++] = i + 2 < n ? B64[v & 63] : '=';
  }
  out[o] = 0;
  return (int)o;
}


static int
b64v(int c) {
  if(c >= 'A' && c <= 'Z') return c - 'A';
  if(c >= 'a' && c <= 'z') return c - 'a' + 26;
  if(c >= '0' && c <= '9') return c - '0' + 52;
  if(c == '+' || c == '-') return 62;
  if(c == '/' || c == '_') return 63;
  return -1;
}


int
bw_b64_dec(const char *in, size_t inlen, uint8_t *out, size_t outlen) {
  uint32_t acc = 0;
  int bits = 0;
  size_t o = 0;
  for(size_t i=0; i<inlen; i++) {
    int c = (unsigned char)in[i];
    if(c == '=') break;
    if(c == '\n' || c == '\r' || c == ' ') continue;
    int v = b64v(c);
    if(v < 0) return -1;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if(bits >= 8) {
      bits -= 8;
      if(o >= outlen) return -1;
      out[o++] = (uint8_t)(acc >> bits);
    }
  }
  return (int)o;
}


/* ------------------------------------------------------------------ */
/* Hashes, HMAC, PBKDF2, HKDF                                          */
/* ------------------------------------------------------------------ */

void
bw_sha256(const void *msg, size_t len, uint8_t out[32]) {
  wc_Sha256Hash(msg, (word32)len, out);
}


void
bw_hmac256(const uint8_t *key, size_t klen, const void *msg, size_t mlen, uint8_t out[32]) {
  Hmac h;
  wc_HmacInit(&h, NULL, INVALID_DEVID);
  wc_HmacSetKey(&h, WC_SHA256, key, (word32)klen);
  wc_HmacUpdate(&h, msg, (word32)mlen);
  wc_HmacFinal(&h, out);
  wc_HmacFree(&h);
}


/* PBKDF2-HMAC-SHA256 de un bloque (32 bytes), con los estados internos de
   HMAC precalculados: 2 compresiones por iteración. */
void
bw_pbkdf2(const uint8_t *pass, size_t plen, const uint8_t *salt, size_t slen,
          uint32_t iter, uint8_t out[32]) {
  uint8_t k[64] = {0}, pad[64], u[32], t[32];
  wc_Sha256 ictx, octx, c;

  if(plen > 64) bw_sha256(pass, plen, k);
  else memcpy(k, pass, plen);

  wc_InitSha256(&ictx);
  for(int i=0; i<64; i++) pad[i] = k[i] ^ 0x36;
  wc_Sha256Update(&ictx, pad, 64);
  wc_InitSha256(&octx);
  for(int i=0; i<64; i++) pad[i] = k[i] ^ 0x5c;
  wc_Sha256Update(&octx, pad, 64);

  /* U1 = HMAC(P, S || INT(1)) */
  static const uint8_t one[4] = {0, 0, 0, 1};
  wc_Sha256Copy(&ictx, &c);
  wc_Sha256Update(&c, salt, (word32)slen);
  wc_Sha256Update(&c, one, 4);
  wc_Sha256Final(&c, u);
  wc_Sha256Copy(&octx, &c);
  wc_Sha256Update(&c, u, 32);
  wc_Sha256Final(&c, u);
  memcpy(t, u, 32);

  for(uint32_t i=1; i<iter; i++) {
    wc_Sha256Copy(&ictx, &c);
    wc_Sha256Update(&c, u, 32);
    wc_Sha256Final(&c, u);
    wc_Sha256Copy(&octx, &c);
    wc_Sha256Update(&c, u, 32);
    wc_Sha256Final(&c, u);
    for(int j=0; j<32; j++) t[j] ^= u[j];
  }
  memcpy(out, t, 32);
  wc_Sha256Free(&ictx);
  wc_Sha256Free(&octx);
  wc_Sha256Free(&c);
  wipe(k, sizeof(k));
  wipe(pad, sizeof(pad));
  wipe(u, sizeof(u));
  wipe(t, sizeof(t));
}


static void
hkdf_expand32(const uint8_t prk[32], const char *info, uint8_t out[32]) {
  uint8_t msg[64];
  size_t l = strlen(info);
  memcpy(msg, info, l);
  msg[l] = 1;
  bw_hmac256(prk, 32, msg, l + 1, out);
}


void
bw_master_key(const char *password, const char *email, uint32_t iter, uint8_t mk[32]) {
  char salt[256];
  size_t i;
  for(i=0; email[i] && i + 1 < sizeof(salt); i++) {
    char c = email[i];
    salt[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
  }
  salt[i] = 0;
  bw_pbkdf2((const uint8_t*)password, strlen(password), (const uint8_t*)salt, i, iter, mk);
}


void
bw_master_hash(const uint8_t mk[32], const char *password, char out[64]) {
  uint8_t h[32];
  bw_pbkdf2(mk, 32, (const uint8_t*)password, strlen(password), 1, h);
  bw_b64_enc(h, 32, out, 64);
  wipe(h, sizeof(h));
}


void
bw_stretch(const uint8_t mk[32], uint8_t key[BW_KEY_LEN]) {
  hkdf_expand32(mk, "enc", key);
  hkdf_expand32(mk, "mac", key + 32);
}


/* ------------------------------------------------------------------ */
/* EncString tipo 2: AES-256-CBC + HMAC-SHA256                         */
/* ------------------------------------------------------------------ */

char *
bw_enc(const uint8_t key[BW_KEY_LEN], const void *plain, size_t n) {
  uint8_t iv[16], mac[32];
  size_t padded = (n / 16 + 1) * 16;
  uint8_t *buf = malloc(16 + padded);
  char *out = NULL;
  Aes aes;

  if(!buf) return NULL;
  bw_random(iv, 16);
  memcpy(buf, iv, 16);
  uint8_t *ct = buf + 16;
  memcpy(ct, plain, n);
  uint8_t p = (uint8_t)(padded - n);
  memset(ct + n, p, p);
  if(wc_AesInit(&aes, NULL, INVALID_DEVID) ||
     wc_AesSetKey(&aes, key, 32, iv, AES_ENCRYPTION) ||
     wc_AesCbcEncrypt(&aes, ct, ct, (word32)padded)) {
    wc_AesFree(&aes);
    free(buf);
    return NULL;
  }
  wc_AesFree(&aes);
  bw_hmac256(key + 32, 32, buf, 16 + padded, mac);

  size_t ol = 2 + 25 + 1 + ((padded + 2) / 3) * 4 + 1 + 45 + 1;
  out = malloc(ol);
  if(out) {
    size_t o = 0;
    out[o++] = '2';
    out[o++] = '.';
    o += (size_t)bw_b64_enc(iv, 16, out + o, ol - o);
    out[o++] = '|';
    o += (size_t)bw_b64_enc(ct, padded, out + o, ol - o);
    out[o++] = '|';
    bw_b64_enc(mac, 32, out + o, ol - o);
  }
  wipe(buf, 16 + padded);
  free(buf);
  return out;
}


char *
bw_enc_str(const uint8_t key[BW_KEY_LEN], const char *s) {
  return bw_enc(key, s, strlen(s));
}


int
bw_dec(const uint8_t key[BW_KEY_LEN], const char *enc, uint8_t **out, size_t *outlen) {
  *out = NULL;
  if(!enc || enc[0] != '2' || enc[1] != '.') return -1;
  const char *a = enc + 2;
  const char *b = strchr(a, '|');
  if(!b) return -1;
  const char *c = strchr(b + 1, '|');
  if(!c) return -1;
  size_t ctlen_b64 = (size_t)(c - b - 1);
  uint8_t iv[16], mac[32], calc[32];
  uint8_t *buf = malloc(16 + ctlen_b64 + 4);
  if(!buf) return -1;
  int r = -1;
  if(bw_b64_dec(a, (size_t)(b - a), iv, sizeof(iv) + 1) != 16) goto out;
  int ctl = bw_b64_dec(b + 1, ctlen_b64, buf + 16, ctlen_b64 + 4);
  if(ctl <= 0 || ctl % 16) goto out;
  if(bw_b64_dec(c + 1, strlen(c + 1), mac, sizeof(mac) + 1) != 32) goto out;
  memcpy(buf, iv, 16);
  bw_hmac256(key + 32, 32, buf, 16 + (size_t)ctl, calc);
  if(!bw_consttime_eq(calc, mac, 32)) goto out;

  Aes aes;
  uint8_t *pt = malloc((size_t)ctl + 1);
  if(!pt) goto out;
  if(wc_AesInit(&aes, NULL, INVALID_DEVID) ||
     wc_AesSetKey(&aes, key, 32, iv, AES_DECRYPTION) ||
     wc_AesCbcDecrypt(&aes, pt, buf + 16, (word32)ctl)) {
    wc_AesFree(&aes);
    free(pt);
    goto out;
  }
  wc_AesFree(&aes);
  uint8_t p = pt[ctl - 1];
  if(p == 0 || p > 16 || p > ctl) {
    free(pt);
    goto out;
  }
  for(int i=0; i<p; i++) if(pt[ctl - 1 - i] != p) { free(pt); goto out; }
  *outlen = (size_t)ctl - p;
  pt[*outlen] = 0;
  *out = pt;
  r = 0;
 out:
  free(buf);
  return r;
}


/* ------------------------------------------------------------------ */
/* RSA                                                                 */
/* ------------------------------------------------------------------ */

/* Escribe una longitud DER. */
static size_t
der_len(uint8_t *p, size_t len) {
  if(len < 128) { p[0] = (uint8_t)len; return 1; }
  if(len < 256) { p[0] = 0x81; p[1] = (uint8_t)len; return 2; }
  p[0] = 0x82;
  p[1] = (uint8_t)(len >> 8);
  p[2] = (uint8_t)len;
  return 3;
}


int
bw_rsa_keypair(uint8_t **pkcs8, size_t *p8len, char **spki_b64) {
  RsaKey key;
  WC_RNG rng;
  uint8_t *pk1 = malloc(4096), *pub = malloc(1024);
  int r = -1;

  *pkcs8 = NULL;
  *spki_b64 = NULL;
  if(!pk1 || !pub) goto out0;
  if(wc_InitRng(&rng)) goto out0;
  if(wc_InitRsaKey(&key, NULL)) goto out1;
  if(wc_MakeRsaKey(&key, 2048, 65537, &rng)) goto out2;
  int l1 = wc_RsaKeyToDer(&key, pk1, 4096);
  int lp = wc_RsaKeyToPublicDer(&key, pub, 1024);
  if(l1 <= 0 || lp <= 0) goto out2;

  /* PKCS#8: SEQUENCE { INTEGER 0, SEQUENCE { rsaEncryption, NULL }, OCTET STRING } */
  static const uint8_t alg[] = {0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
                                0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
  uint8_t oct[4];
  size_t ol = der_len(oct, (size_t)l1);
  size_t inner = sizeof(alg) + 1 + ol + (size_t)l1;
  uint8_t *p8 = malloc(inner + 8);
  if(!p8) goto out2;
  size_t o = 0;
  p8[o++] = 0x30;
  o += der_len(p8 + o, inner);
  memcpy(p8 + o, alg, sizeof(alg));
  o += sizeof(alg);
  p8[o++] = 0x04;
  memcpy(p8 + o, oct, ol);
  o += ol;
  memcpy(p8 + o, pk1, (size_t)l1);
  o += (size_t)l1;

  char *b = malloc(((size_t)lp + 2) / 3 * 4 + 1);
  if(!b) {
    wipe(p8, o);
    free(p8);
    goto out2;
  }
  bw_b64_enc(pub, (size_t)lp, b, ((size_t)lp + 2) / 3 * 4 + 1);
  *pkcs8 = p8;
  *p8len = o;
  *spki_b64 = b;
  r = 0;
 out2:
  wc_FreeRsaKey(&key);
 out1:
  wc_FreeRng(&rng);
 out0:
  if(pk1) wipe(pk1, 4096);
  free(pk1);
  free(pub);
  return r;
}


/* ------------------------------------------------------------------ */
/* Identificadores y fechas                                            */
/* ------------------------------------------------------------------ */

void
bw_uuid(char out[37]) {
  uint8_t b[16];
  bw_random(b, 16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
           b[13], b[14], b[15]);
}


long long
bw_now_us(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (long long)tv.tv_sec * 1000000LL + tv.tv_usec;
}


/* Días desde 1970-01-01 (algoritmo de Howard Hinnant). */
static long long
days_from_civil(long long y, unsigned m, unsigned d) {
  y -= m <= 2;
  long long era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400);
  unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + (long long)doe - 719468;
}


void
bw_iso(long long us, char out[40]) {
  long long s = us / 1000000LL;
  long long frac = us % 1000000LL;
  long long z = s / 86400 + 719468;
  long long sec = s % 86400;
  long long era = (z >= 0 ? z : z - 146096) / 146097;
  unsigned doe = (unsigned)(z - era * 146097);
  unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  long long y = (long long)yoe + era * 400;
  unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  unsigned mp = (5 * doy + 2) / 153;
  unsigned d = doy - (153 * mp + 2) / 5 + 1;
  unsigned m = mp < 10 ? mp + 3 : mp - 9;
  y += m <= 2;
  if(y < 0 || y > 9999) y = 1970;
  snprintf(out, 40, "%04d-%02u-%02uT%02d:%02d:%02d.%06dZ", (int)y, m % 13, d % 32,
           (int)(sec / 3600) % 24, (int)((sec / 60) % 60), (int)(sec % 60), (int)frac % 1000000);
}


long long
bw_parse_iso(const char *s) {
  int y, mo, d, h, mi, se;
  int n = 0;
  if(!s || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &se, &n) != 6) return -1;
  long long us = 0;
  const char *p = s + n;
  if(*p == '.') {
    long long scale = 100000;
    for(p++; *p >= '0' && *p <= '9'; p++) {
      us += (*p - '0') * scale;
      scale /= 10;
    }
  }
  if(mo < 1 || mo > 12 || d < 1 || d > 31) return -1;
  long long days = days_from_civil(y, (unsigned)mo, (unsigned)d);
  long long t = days * 86400 + h * 3600 + mi * 60 + se;
  if(*p == '+' || *p == '-') {
    int oh = 0, om = 0;
    if(sscanf(p + 1, "%2d:%2d", &oh, &om) >= 1) {
      long long off = oh * 3600 + om * 60;
      t += *p == '+' ? -off : off;
    }
  }
  return t * 1000000LL + us;
}


/* ------------------------------------------------------------------ */
/* JWT HS256                                                           */
/* ------------------------------------------------------------------ */

static void
b64url(const uint8_t *in, size_t n, char *out, size_t outlen) {
  bw_b64_enc(in, n, out, outlen);
  char *w = out;
  for(char *p = out; *p; p++) {
    if(*p == '=') continue;
    *w++ = *p == '+' ? '-' : (*p == '/' ? '_' : *p);
  }
  *w = 0;
}


char *
bw_jwt_sign(const uint8_t key[32], const char *payload) {
  static const char hdr[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
  size_t pl = strlen(payload);
  size_t cap = 64 + (pl + 2) / 3 * 4 + 64;
  char *out = malloc(cap);
  if(!out) return NULL;
  b64url((const uint8_t*)hdr, strlen(hdr), out, cap);
  size_t o = strlen(out);
  out[o++] = '.';
  b64url((const uint8_t*)payload, pl, out + o, cap - o);
  o = strlen(out);
  uint8_t mac[32];
  bw_hmac256(key, 32, out, o, mac);
  out[o++] = '.';
  b64url(mac, 32, out + o, cap - o);
  return out;
}


char *
bw_jwt_verify(const uint8_t key[32], const char *jwt) {
  const char *d1 = strchr(jwt, '.');
  if(!d1) return NULL;
  const char *d2 = strchr(d1 + 1, '.');
  if(!d2) return NULL;
  uint8_t mac[32], got[40];
  bw_hmac256(key, 32, jwt, (size_t)(d2 - jwt), mac);
  if(bw_b64_dec(d2 + 1, strlen(d2 + 1), got, sizeof(got)) != 32) return NULL;
  if(!bw_consttime_eq(mac, got, 32)) return NULL;
  size_t pl = (size_t)(d2 - d1 - 1);
  char *payload = malloc(pl + 1);
  if(!payload) return NULL;
  int n = bw_b64_dec(d1 + 1, pl, (uint8_t*)payload, pl);
  if(n < 0) {
    free(payload);
    return NULL;
  }
  payload[n] = 0;
  return payload;
}
