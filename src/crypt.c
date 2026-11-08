/* ps5share - carpetas privadas cifradas
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "config.h"
#include "crypt.h"

static const uint8_t MAGIC[8] = {'P','S','5','S','E','N','C','1'};


static void
wipe(void *p, size_t n) {
  volatile uint8_t *v = p;
  while(n--) *v++ = 0;
}


static int
hmac256(const uint8_t *key, size_t klen, const void *a, size_t alen,
        const void *b, size_t blen, uint8_t out[32]) {
  Hmac h;
  int r = -1;
  if(wc_HmacInit(&h, NULL, INVALID_DEVID)) return -1;
  if(!wc_HmacSetKey(&h, WC_SHA256, key, (word32)klen) &&
     !wc_HmacUpdate(&h, a, (word32)alen) &&
     (!blen || !wc_HmacUpdate(&h, b, (word32)blen)) &&
     !wc_HmacFinal(&h, out)) {
    r = 0;
  }
  wc_HmacFree(&h);
  return r;
}


void
crypt_key_init(ukey_t *k, const uint8_t dek[CRYPT_KEY_LEN]) {
  memcpy(k->dek, dek, CRYPT_KEY_LEN);
  hmac256(dek, CRYPT_KEY_LEN, "ps5share-name-mac", 17, NULL, 0, k->name_mac);
  hmac256(dek, CRYPT_KEY_LEN, "ps5share-name-enc", 17, NULL, 0, k->name_enc);
  k->ok = 1;
}


void
crypt_key_wipe(ukey_t *k) {
  wipe(k, sizeof(*k));
}


/* ------------------------------------------------------------------ */
/* Envoltura de la DEK                                                 */
/* ------------------------------------------------------------------ */

static void
hex_enc(const uint8_t *in, size_t n, char *out) {
  static const char hx[] = "0123456789abcdef";
  for(size_t i=0; i<n; i++) {
    out[i*2] = hx[in[i] >> 4];
    out[i*2+1] = hx[in[i] & 15];
  }
  out[n*2] = 0;
}


static int
hex_dec(const char *in, uint8_t *out, size_t n) {
  for(size_t i=0; i<n*2; i++) {
    char c = in[i];
    int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
    if(v < 0) return -1;
    if(i & 1) out[i/2] |= (uint8_t)v;
    else out[i/2] = (uint8_t)(v << 4);
  }
  return in[n*2] ? -1 : 0;
}


int
crypt_wrap(const uint8_t kek[CRYPT_KEY_LEN], const uint8_t dek[CRYPT_KEY_LEN],
           char out_hex[CRYPT_WRAP_HEX + 1]) {
  uint8_t blob[12 + 32 + 16];
  Aes aes;
  int r = -1;

  cfg_random(blob, 12);
  if(wc_AesInit(&aes, NULL, INVALID_DEVID)) return -1;
  if(!wc_AesGcmSetKey(&aes, kek, CRYPT_KEY_LEN) &&
     !wc_AesGcmEncrypt(&aes, blob + 12, dek, 32, blob, 12, blob + 44, 16,
                       (const byte*)"ps5share-dek", 12)) {
    hex_enc(blob, sizeof(blob), out_hex);
    r = 0;
  }
  wc_AesFree(&aes);
  return r;
}


int
crypt_unwrap(const uint8_t kek[CRYPT_KEY_LEN], const char *hex, uint8_t dek[CRYPT_KEY_LEN]) {
  uint8_t blob[12 + 32 + 16];
  Aes aes;
  int r = -1;

  if(strlen(hex) != CRYPT_WRAP_HEX || hex_dec(hex, blob, sizeof(blob))) return -1;
  if(wc_AesInit(&aes, NULL, INVALID_DEVID)) return -1;
  if(!wc_AesGcmSetKey(&aes, kek, CRYPT_KEY_LEN) &&
     !wc_AesGcmDecrypt(&aes, dek, blob + 12, 32, blob, 12, blob + 44, 16,
                       (const byte*)"ps5share-dek", 12)) {
    r = 0;
  }
  wc_AesFree(&aes);
  return r;
}


/* Secretos pequeños (contraseñas) cifrados con la clave maestra. */
int
crypt_seal(const uint8_t key[CRYPT_KEY_LEN], const char *aad, const void *plain,
           size_t len, char *out_hex, size_t outlen) {
  uint8_t blob[12 + CRYPT_SEAL_MAX + 16];
  Aes aes;
  int r = -1;

  if(len > CRYPT_SEAL_MAX || outlen < (12 + len + 16) * 2 + 1) return -1;
  cfg_random(blob, 12);
  if(wc_AesInit(&aes, NULL, INVALID_DEVID)) return -1;
  if(!wc_AesGcmSetKey(&aes, key, CRYPT_KEY_LEN) &&
     !wc_AesGcmEncrypt(&aes, blob + 12, plain, (word32)len, blob, 12, blob + 12 + len, 16,
                       (const byte*)aad, (word32)strlen(aad))) {
    hex_enc(blob, 12 + len + 16, out_hex);
    r = 0;
  }
  wc_AesFree(&aes);
  wipe(blob, sizeof(blob));
  return r;
}


int
crypt_open(const uint8_t key[CRYPT_KEY_LEN], const char *aad, const char *hex,
           char *out, size_t outlen) {
  uint8_t blob[12 + CRYPT_SEAL_MAX + 16];
  size_t hl = strlen(hex), n;
  Aes aes;
  int r = -1;

  if(hl & 1 || hl / 2 < 28 || hl / 2 > sizeof(blob)) return -1;
  n = hl / 2;
  if(hex_dec(hex, blob, n)) return -1;
  size_t len = n - 28;
  if(len + 1 > outlen) return -1;
  if(wc_AesInit(&aes, NULL, INVALID_DEVID)) return -1;
  if(!wc_AesGcmSetKey(&aes, key, CRYPT_KEY_LEN) &&
     !wc_AesGcmDecrypt(&aes, (byte*)out, blob + 12, (word32)len, blob, 12, blob + 12 + len, 16,
                       (const byte*)aad, (word32)strlen(aad))) {
    out[len] = 0;
    r = 0;
  }
  wc_AesFree(&aes);
  wipe(blob, sizeof(blob));
  return r;
}


/* ------------------------------------------------------------------ */
/* Nombres: SIV con HMAC-SHA256 + AES-CTR, base32                      */
/* ------------------------------------------------------------------ */

static const char B32[] = "abcdefghijklmnopqrstuvwxyz234567";


static size_t
b32_enc(const uint8_t *in, size_t n, char *out) {
  size_t o = 0;
  uint32_t acc = 0;
  int bits = 0;
  for(size_t i=0; i<n; i++) {
    acc = (acc << 8) | in[i];
    bits += 8;
    while(bits >= 5) {
      out[o++] = B32[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if(bits) out[o++] = B32[(acc << (5 - bits)) & 31];
  out[o] = 0;
  return o;
}


static int
b32_dec(const char *in, uint8_t *out, size_t outcap, size_t *outlen) {
  uint32_t acc = 0;
  int bits = 0;
  size_t o = 0;
  for(const char *p = in; *p; p++) {
    const char *q = strchr(B32, *p);
    if(!q || !*p) return -1;
    acc = (acc << 5) | (uint32_t)(q - B32);
    bits += 5;
    if(bits >= 8) {
      if(o >= outcap) return -1;
      out[o++] = (uint8_t)(acc >> (bits - 8));
      bits -= 8;
    }
  }
  /* los bits sobrantes deben ser cero (codificación canónica) */
  if(bits >= 5 || (acc & ((1u << bits) - 1))) return -1;
  *outlen = o;
  return 0;
}


static int
aes_ctr(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t n) {
  Aes aes;
  int r = -1;
  uint8_t ctr[16];
  memcpy(ctr, iv, 16);
  ctr[8] &= 0x7f;   /* como en SIV: evita desbordes del contador */
  ctr[12] &= 0x7f;
  if(wc_AesInit(&aes, NULL, INVALID_DEVID)) return -1;
  if(!wc_AesSetKey(&aes, key, 32, ctr, AES_ENCRYPTION) &&
     !wc_AesCtrEncrypt(&aes, out, in, (word32)n)) {
    r = 0;
  }
  wc_AesFree(&aes);
  return r;
}


int
crypt_name_enc(const ukey_t *k, const char *plain, char *out, size_t outlen) {
  size_t n = strlen(plain);
  uint8_t mac[32];
  uint8_t blob[16 + CRYPT_NAME_MAX];

  if(!k || !k->ok) { errno = EACCES; return -1; }
  if(n == 0) { errno = EINVAL; return -1; }
  if(n > CRYPT_NAME_MAX) { errno = ENAMETOOLONG; return -1; }
  if(outlen < ((16 + n) * 8 + 4) / 5 + 1) { errno = ENAMETOOLONG; return -1; }

  if(hmac256(k->name_mac, 32, "N", 1, plain, n, mac)) { errno = EIO; return -1; }
  memcpy(blob, mac, 16);
  if(aes_ctr(k->name_enc, blob, (const uint8_t*)plain, blob + 16, n)) { errno = EIO; return -1; }
  b32_enc(blob, 16 + n, out);
  return 0;
}


int
crypt_name_dec(const ukey_t *k, const char *enc, char *out, size_t outlen) {
  uint8_t blob[16 + CRYPT_NAME_MAX];
  uint8_t mac[32];
  size_t n;

  if(!k || !k->ok) return -1;
  if(b32_dec(enc, blob, sizeof(blob), &n) || n <= 16 || n - 16 >= outlen) return -1;
  n -= 16;
  if(aes_ctr(k->name_enc, blob, blob + 16, (uint8_t*)out, n)) return -1;
  out[n] = 0;
  if(memchr(out, 0, n) || memchr(out, '/', n)) return -1;
  if(hmac256(k->name_mac, 32, "N", 1, out, n, mac)) return -1;
  uint8_t d = 0;
  for(int i=0; i<16; i++) d |= mac[i] ^ blob[i];
  if(d) {
    wipe(out, n);
    out[0] = 0;
    return -1;
  }
  return 0;
}


/* ------------------------------------------------------------------ */
/* Contenido                                                           */
/* ------------------------------------------------------------------ */

#define DISK_CHUNK (CRYPT_CHUNK + CRYPT_OVERHEAD)


off_t
crypt_plain_size(off_t disk) {
  off_t d = disk - CRYPT_HDR;
  if(d <= 0) return 0;
  off_t full = d / DISK_CHUNK, rem = d % DISK_CHUNK;
  return full * CRYPT_CHUNK + (rem > CRYPT_OVERHEAD ? rem - CRYPT_OVERHEAD : 0);
}


static off_t
disk_size(cfile_t *f) {
  struct stat st;
  if(fstat(f->fd, &st)) return -1;
  return st.st_size;
}


static int
pread_full(int fd, void *buf, size_t len, off_t off, size_t *got) {
  size_t done = 0;
  while(done < len) {
    ssize_t n = pread(fd, (uint8_t*)buf + done, len - done, off + (off_t)done);
    if(n < 0 && errno == EINTR) continue;
    if(n < 0) return -1;
    if(n == 0) break;
    done += (size_t)n;
  }
  *got = done;
  return 0;
}


static int
pwrite_full(int fd, const void *buf, size_t len, off_t off) {
  size_t done = 0;
  while(done < len) {
    ssize_t n = pwrite(fd, (const uint8_t*)buf + done, len - done, off + (off_t)done);
    if(n < 0 && errno == EINTR) continue;
    if(n <= 0) return -1;
    done += (size_t)n;
  }
  return 0;
}


static void
chunk_aad(cfile_t *f, int64_t idx, uint8_t aad[24]) {
  memcpy(aad, f->file_id, 16);
  for(int i=0; i<8; i++) aad[16 + i] = (uint8_t)((uint64_t)idx >> (56 - 8*i));
}


int
cfile_flush(cfile_t *f) {
  uint8_t aad[24];
  Aes aes;
  int r = -1;

  if(!f->c_dirty) return 0;
  uint8_t *p = f->io_buf;
  cfg_random(p, 12);
  chunk_aad(f, f->c_idx, aad);
  if(wc_AesInit(&aes, NULL, INVALID_DEVID)) { errno = EIO; return -1; }
  if(!wc_AesGcmSetKey(&aes, f->key, 32) &&
     !wc_AesGcmEncrypt(&aes, p + 12, f->c_buf, (word32)f->c_len, p, 12,
                       p + 12 + f->c_len, 16, aad, sizeof(aad))) {
    r = 0;
  }
  wc_AesFree(&aes);
  if(r) { errno = EIO; return -1; }

  off_t off = CRYPT_HDR + (off_t)f->c_idx * DISK_CHUNK;
  if(pwrite_full(f->fd, p, f->c_len + CRYPT_OVERHEAD, off)) return -1;
  f->c_dirty = 0;
  return 0;
}


/* Carga el bloque IDX en la caché (vacío si está más allá del final). */
static int
load_chunk(cfile_t *f, int64_t idx) {
  uint8_t aad[24];
  size_t got;
  Aes aes;
  int r = -1;

  if(f->c_idx == idx) return 0;
  if(cfile_flush(f)) return -1;

  off_t off = CRYPT_HDR + (off_t)idx * DISK_CHUNK;
  if(pread_full(f->fd, f->io_buf, DISK_CHUNK, off, &got)) return -1;
  f->c_idx = idx;
  f->c_len = 0;
  if(got == 0) return 0;
  if(got <= CRYPT_OVERHEAD) {
    f->c_idx = -1;
    errno = EIO;
    return -1;
  }

  size_t clen = got - CRYPT_OVERHEAD;
  chunk_aad(f, idx, aad);
  if(wc_AesInit(&aes, NULL, INVALID_DEVID)) { f->c_idx = -1; errno = EIO; return -1; }
  if(!wc_AesGcmSetKey(&aes, f->key, 32) &&
     !wc_AesGcmDecrypt(&aes, f->c_buf, f->io_buf + 12, (word32)clen, f->io_buf, 12,
                       f->io_buf + 12 + clen, 16, aad, sizeof(aad))) {
    r = 0;
  }
  wc_AesFree(&aes);
  if(r) {
    f->c_idx = -1;
    errno = EIO;   /* dañado o manipulado */
    return -1;
  }
  f->c_len = clen;
  return 0;
}


off_t
cfile_size(cfile_t *f) {
  off_t d = disk_size(f);
  if(d < 0) return -1;
  off_t s = crypt_plain_size(d);
  if(f->c_dirty && f->c_idx >= 0) {
    off_t c = (off_t)f->c_idx * CRYPT_CHUNK + (off_t)f->c_len;
    if(c > s) s = c;
  }
  return s;
}


int
cfile_open(cfile_t *f, int fd, int writable, int fresh, const ukey_t *k) {
  uint8_t hdr[CRYPT_HDR];
  size_t got;

  memset(f, 0, sizeof(*f));
  f->fd = fd;
  f->writable = writable;
  f->c_idx = -1;

  if(!k || !k->ok) { errno = EACCES; return -1; }

  if(fresh) {
    if(ftruncate(fd, 0)) return -1;
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr, MAGIC, 8);
    cfg_random(hdr + 8, 16);
    if(pwrite_full(fd, hdr, sizeof(hdr), 0)) return -1;
  } else {
    if(pread_full(fd, hdr, sizeof(hdr), 0, &got)) return -1;
    if(got == 0 && writable) {   /* archivo vacío creado por otro medio */
      memset(hdr, 0, sizeof(hdr));
      memcpy(hdr, MAGIC, 8);
      cfg_random(hdr + 8, 16);
      if(pwrite_full(fd, hdr, sizeof(hdr), 0)) return -1;
    } else if(got != sizeof(hdr) || memcmp(hdr, MAGIC, 8)) {
      errno = EACCES;   /* no es un archivo cifrado de ps5share */
      return -1;
    }
  }
  memcpy(f->file_id, hdr + 8, 16);
  if(hmac256(k->dek, CRYPT_KEY_LEN, "ps5share-file", 13, f->file_id, 16, f->key)) {
    errno = EIO;
    return -1;
  }

  f->c_buf = malloc(CRYPT_CHUNK);
  f->io_buf = malloc(DISK_CHUNK);
  if(!f->c_buf || !f->io_buf) {
    free(f->c_buf);
    free(f->io_buf);
    f->c_buf = f->io_buf = NULL;
    errno = ENOMEM;
    return -1;
  }
  return 0;
}


ssize_t
cfile_pread(cfile_t *f, void *buf, size_t len, off_t off) {
  off_t size = cfile_size(f);
  size_t done = 0;
  if(size < 0) return -1;
  if(off >= size) return 0;
  if((off_t)len > size - off) len = (size_t)(size - off);

  while(done < len) {
    off_t pos = off + (off_t)done;
    int64_t idx = pos / CRYPT_CHUNK;
    size_t o = (size_t)(pos % CRYPT_CHUNK);
    if(load_chunk(f, idx)) return done ? (ssize_t)done : -1;
    if(o >= f->c_len) break;
    size_t m = f->c_len - o;
    if(m > len - done) m = len - done;
    memcpy((uint8_t*)buf + done, f->c_buf + o, m);
    done += m;
  }
  return (ssize_t)done;
}


static ssize_t
write_at(cfile_t *f, const uint8_t *buf, size_t len, off_t off) {
  size_t done = 0;
  while(done < len) {
    off_t pos = off + (off_t)done;
    int64_t idx = pos / CRYPT_CHUNK;
    size_t o = (size_t)(pos % CRYPT_CHUNK);
    if(load_chunk(f, idx)) return -1;
    size_t m = CRYPT_CHUNK - o;
    if(m > len - done) m = len - done;
    if(buf) memcpy(f->c_buf + o, buf + done, m);
    else memset(f->c_buf + o, 0, m);
    if(o > f->c_len) memset(f->c_buf + f->c_len, 0, o - f->c_len);
    if(o + m > f->c_len) f->c_len = o + m;
    f->c_dirty = 1;
    done += m;
    if(f->c_len == CRYPT_CHUNK && cfile_flush(f)) return -1;
  }
  return (ssize_t)done;
}


ssize_t
cfile_pwrite(cfile_t *f, const void *buf, size_t len, off_t off) {
  if(!f->writable) { errno = EBADF; return -1; }
  off_t size = cfile_size(f);
  if(size < 0) return -1;
  /* Rellena con ceros el hueco hasta OFF, para que todos los bloques
     anteriores al último estén completos. */
  if(off > size && write_at(f, NULL, (size_t)(off - size), size) < 0) return -1;
  return write_at(f, buf, len, off);
}


int
cfile_close(cfile_t *f) {
  int r = 0;
  if(f->fd >= 0) {
    if(cfile_flush(f)) r = -1;
    if(close(f->fd)) r = -1;
  }
  f->fd = -1;
  if(f->c_buf) {
    wipe(f->c_buf, CRYPT_CHUNK);
    free(f->c_buf);
  }
  free(f->io_buf);
  wipe(f->key, sizeof(f->key));
  f->c_buf = f->io_buf = NULL;
  return r;
}
