/* ps5share - HTTPS con certificado propio de la consola
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "config.h"
#include "log.h"
#include "tls.h"
#include "tsip.h"

#define CA_DAYS        3650
#define SRV_DAYS       397          /* máximo que aceptan Apple y Chrome */
#define SRV_RENEW_DAYS 30
#define MAX_NAMES      24
#define DER_MAX        4096

static pthread_mutex_t g_tls_lock = PTHREAD_MUTEX_INITIALIZER;
static char      g_dir[PATH_MAX];
static WOLFSSL_CTX *g_ctx = NULL;
static uint8_t   g_ca_der[DER_MAX];
static int       g_ca_der_len = 0;
static uint8_t   g_ca_key[DER_MAX];
static int       g_ca_key_len = 0;
static char      g_names[1024];     /* nombres del certificado actual */
static long long g_srv_expires = 0;
static int       g_wolf_init = 0;


/* ------------------------------------------------------------------ */
/* Archivos                                                            */
/* ------------------------------------------------------------------ */

static int
read_file(const char *name, void *buf, size_t max) {
  char path[PATH_MAX + 64];
  snprintf(path, sizeof(path), "%s/%s", g_dir, name);
  int fd = open(path, O_RDONLY);
  if(fd < 0) return -1;
  ssize_t n = read(fd, buf, max);
  close(fd);
  return n <= 0 || (size_t)n >= max ? -1 : (int)n;
}


static int
write_file(const char *name, const void *buf, size_t len, int mode) {
  char path[PATH_MAX + 64], tmp[PATH_MAX + 72];
  snprintf(path, sizeof(path), "%s/%s", g_dir, name);
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if(fd < 0) return -1;
  int ok = write(fd, buf, len) == (ssize_t)len && !fsync(fd);
  close(fd);
  if(!ok || rename(tmp, path)) {
    unlink(tmp);
    return -1;
  }
  chmod(path, mode);
  return 0;
}


/* ------------------------------------------------------------------ */
/* Lista de nombres y direcciones                                      */
/* ------------------------------------------------------------------ */

typedef struct names {
  int  n;
  char v[MAX_NAMES][128];
} names_t;


static void
names_add(names_t *nm, const char *s) {
  if(!s[0] || nm->n >= MAX_NAMES || strlen(s) >= sizeof(nm->v[0])) return;
  for(int i=0; i<nm->n; i++) if(!strcasecmp(nm->v[i], s)) return;
  snprintf(nm->v[nm->n++], sizeof(nm->v[0]), "%s", s);
}


static int
is_ipv4(const char *s) {
  struct in_addr a;
  return inet_pton(AF_INET, s, &a) == 1;
}


static void
collect_names(names_t *nm) {
  char ts[INET_ADDRSTRLEN] = "", extra[256];
  struct ifaddrs *ifa = NULL;

  memset(nm, 0, sizeof(*nm));
  cfg_lock();
  snprintf(extra, sizeof(extra), "%s", cfg_settings()->tls_names);
  cfg_unlock();

  /* Primero los nombres que pone el usuario (el primero es el CN). */
  char *save = NULL;
  for(char *t = strtok_r(extra, " ,", &save); t; t = strtok_r(NULL, " ,", &save)) {
    names_add(nm, t);
  }
  tsip_get(ts, sizeof(ts));
  names_add(nm, ts);
  if(!getifaddrs(&ifa)) {
    for(struct ifaddrs *i = ifa; i; i = i->ifa_next) {
      char ip[INET_ADDRSTRLEN];
      if(!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
      inet_ntop(AF_INET, &((struct sockaddr_in*)i->ifa_addr)->sin_addr, ip, sizeof(ip));
      if(!strncmp(ip, "0.", 2) || !strncmp(ip, "169.254.", 8)) continue;
      names_add(nm, ip);
    }
    freeifaddrs(ifa);
  }
  names_add(nm, "127.0.0.1");
  names_add(nm, "localhost");
}


static void
names_join(const names_t *nm, char *out, size_t outlen) {
  size_t o = 0;
  out[0] = 0;
  for(int i=0; i<nm->n; i++) {
    int k = snprintf(out + o, outlen - o, "%s%s", i ? " " : "", nm->v[i]);
    if(k < 0 || (size_t)k >= outlen - o) break;
    o += (size_t)k;
  }
}


/* GeneralNames (SEQUENCE de dNSName [2] / iPAddress [7]) en DER. */
static int
encode_san(const names_t *nm, uint8_t *out, size_t outlen) {
  uint8_t body[2048];
  size_t b = 0;
  for(int i=0; i<nm->n; i++) {
    struct in_addr a;
    if(inet_pton(AF_INET, nm->v[i], &a) == 1) {
      if(b + 6 > sizeof(body)) return -1;
      body[b++] = 0x87;
      body[b++] = 4;
      memcpy(body + b, &a.s_addr, 4);   /* ya en orden de red */
      b += 4;
    } else {
      size_t l = strlen(nm->v[i]);
      if(l > 127 || b + 2 + l > sizeof(body)) return -1;
      body[b++] = 0x82;
      body[b++] = (uint8_t)l;
      memcpy(body + b, nm->v[i], l);
      b += l;
    }
  }
  size_t o = 0;
  if(outlen < b + 4) return -1;
  out[o++] = 0x30;
  if(b < 128) {
    out[o++] = (uint8_t)b;
  } else if(b < 256) {
    out[o++] = 0x81;
    out[o++] = (uint8_t)b;
  } else {
    out[o++] = 0x82;
    out[o++] = (uint8_t)(b >> 8);
    out[o++] = (uint8_t)b;
  }
  memcpy(out + o, body, b);
  return (int)(o + b);
}


/* ------------------------------------------------------------------ */
/* Generación de claves y certificados                                 */
/* ------------------------------------------------------------------ */

static int
make_ecc_key(WC_RNG *rng, ecc_key *key, uint8_t *der, int *derlen) {
  if(wc_ecc_init(key) || wc_ecc_make_key_ex(rng, 32, key, ECC_SECP256R1)) return -1;
  int n = wc_EccKeyToDer(key, der, DER_MAX);
  if(n <= 0) return -1;
  *derlen = n;
  return 0;
}


static int
load_ecc_key(const uint8_t *der, int len, ecc_key *key) {
  word32 idx = 0;
  if(wc_ecc_init(key)) return -1;
  return wc_EccPrivateKeyDecode(der, &idx, key, (word32)len) ? -1 : 0;
}


static int
make_ca(void) {
  WC_RNG rng;
  ecc_key key;
  Cert *cert = calloc(1, sizeof(Cert));
  uint8_t *der = malloc(DER_MAX);
  uint8_t keyder[DER_MAX];
  int keylen = 0, r = -1;
  char cn[64], suffix[9];

  if(!cert || !der || wc_InitRng(&rng)) {
    free(cert);
    free(der);
    return -1;
  }
  if(make_ecc_key(&rng, &key, keyder, &keylen)) goto out;

  wc_InitCert(cert);
  cfg_random_hex(suffix, 4);
  snprintf(cn, sizeof(cn), "PS5NAS CA %s", suffix);
  snprintf(cert->subject.commonName, CTC_NAME_SIZE, "%s", cn);
  snprintf(cert->subject.org, CTC_NAME_SIZE, "PS5NAS");
  cert->isCA = 1;
  cert->basicConstSet = 1;
  cert->basicConstCrit = 1;      /* obligatorio en la verificación estricta (RFC 5280) */
  cert->sigType = CTC_SHA256wECDSA;
  cert->daysValid = CA_DAYS;
  if(wc_SetKeyUsage(cert, "keyCertSign,cRLSign")) goto out;
  if(wc_SetSubjectKeyIdFromPublicKey_ex(cert, ECC_TYPE, &key)) goto out;
  if(wc_MakeCert_ex(cert, der, DER_MAX, ECC_TYPE, &key, &rng) < 0) goto out;
  int n = wc_SignCert_ex(cert->bodySz, cert->sigType, der, DER_MAX, ECC_TYPE, &key, &rng);
  if(n <= 0) goto out;

  if(write_file("ca.key", keyder, (size_t)keylen, 0600) ||
     write_file("ca.der", der, (size_t)n, 0644)) goto out;
  memcpy(g_ca_der, der, (size_t)n);
  g_ca_der_len = n;
  memcpy(g_ca_key, keyder, (size_t)keylen);
  g_ca_key_len = keylen;
  LOG_PRINTF("ps5share: creada la autoridad de certificación '%s'\n", cn);
  r = 0;

 out:
  wc_ecc_free(&key);
  wc_FreeRng(&rng);
  memset(keyder, 0, sizeof(keyder));
  free(cert);
  free(der);
  return r;
}


static int
pem_of(const uint8_t *der, int len, int type, char *out, size_t outlen) {
  int n = wc_DerToPem(der, (word32)len, (byte*)out, (word32)outlen - 1, type);
  if(n <= 0) return -1;
  out[n] = 0;
  return n;
}


/* Crea el certificado del servidor y el contexto TLS.  Con el lock. */
static int
make_server_locked(const names_t *nm) {
  WC_RNG rng;
  ecc_key key, cakey;
  Cert *cert = calloc(1, sizeof(Cert));
  uint8_t *der = malloc(DER_MAX);
  uint8_t keyder[DER_MAX];
  int keylen = 0, r = -1, have_key = 0, have_ca = 0;

  if(!cert || !der || wc_InitRng(&rng)) {
    free(cert);
    free(der);
    return -1;
  }
  if(make_ecc_key(&rng, &key, keyder, &keylen)) goto out;
  have_key = 1;
  if(load_ecc_key(g_ca_key, g_ca_key_len, &cakey)) goto out;
  have_ca = 1;

  wc_InitCert(cert);
  /* CN: el primer nombre que no sea una IP, o la primera IP. */
  const char *cn = "PS5NAS";
  for(int i=0; i<nm->n; i++) {
    if(!is_ipv4(nm->v[i]) && strcmp(nm->v[i], "localhost")) { cn = nm->v[i]; break; }
  }
  snprintf(cert->subject.commonName, CTC_NAME_SIZE, "%.*s", CTC_NAME_SIZE - 1, cn);
  snprintf(cert->subject.org, CTC_NAME_SIZE, "PS5NAS");
  cert->sigType = CTC_SHA256wECDSA;
  cert->daysValid = SRV_DAYS;
  int sl = encode_san(nm, cert->altNames, sizeof(cert->altNames));
  if(sl <= 0) goto out;
  cert->altNamesSz = sl;
  if(wc_SetIssuerBuffer(cert, g_ca_der, g_ca_der_len)) goto out;
  if(wc_SetKeyUsage(cert, "digitalSignature,keyAgreement")) goto out;
  if(wc_SetExtKeyUsage(cert, "serverAuth")) goto out;
  if(wc_SetSubjectKeyIdFromPublicKey_ex(cert, ECC_TYPE, &key)) goto out;
  if(wc_SetAuthKeyIdFromPublicKey_ex(cert, ECC_TYPE, &cakey)) goto out;
  if(wc_MakeCert_ex(cert, der, DER_MAX, ECC_TYPE, &key, &rng) < 0) goto out;
  int n = wc_SignCert_ex(cert->bodySz, cert->sigType, der, DER_MAX, ECC_TYPE, &cakey, &rng);
  if(n <= 0) goto out;

  /* Cadena: servidor + CA, en PEM. */
  char chain[8192];
  int a = pem_of(der, n, CERT_TYPE, chain, sizeof(chain));
  if(a < 0) goto out;
  int b = pem_of(g_ca_der, g_ca_der_len, CERT_TYPE, chain + a, sizeof(chain) - (size_t)a);
  if(b < 0) goto out;

  WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
  if(!ctx) goto out;
  wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
  if(wolfSSL_CTX_use_certificate_chain_buffer(ctx, (const unsigned char*)chain, a + b)
       != WOLFSSL_SUCCESS ||
     wolfSSL_CTX_use_PrivateKey_buffer(ctx, keyder, keylen, WOLFSSL_FILETYPE_ASN1)
       != WOLFSSL_SUCCESS) {
    LOG_PUTS("ps5share: no se pudo cargar el certificado HTTPS");
    wolfSSL_CTX_free(ctx);
    goto out;
  }
  extern int tls_io_recv(WOLFSSL*, char*, int, void*);
  extern int tls_io_send(WOLFSSL*, char*, int, void*);
  wolfSSL_CTX_SetIORecv(ctx, tls_io_recv);
  wolfSSL_CTX_SetIOSend(ctx, tls_io_send);

  /* Se guarda para el siguiente arranque. */
  char meta[1200];
  names_join(nm, g_names, sizeof(g_names));
  g_srv_expires = (long long)time(NULL) + (long long)SRV_DAYS * 86400;
  snprintf(meta, sizeof(meta), "%lld\n%s\n", g_srv_expires, g_names);
  write_file("server.key", keyder, (size_t)keylen, 0600);
  write_file("server.der", der, (size_t)n, 0644);
  write_file("server.meta", meta, strlen(meta), 0644);

  /* Las conexiones abiertas conservan su referencia al contexto anterior. */
  if(g_ctx) wolfSSL_CTX_free(g_ctx);
  g_ctx = ctx;
  LOG_PRINTF("ps5share: certificado HTTPS emitido para: %s\n", g_names);
  r = 0;

 out:
  if(have_key) wc_ecc_free(&key);
  if(have_ca) wc_ecc_free(&cakey);
  wc_FreeRng(&rng);
  memset(keyder, 0, sizeof(keyder));
  free(cert);
  free(der);
  return r;
}


/* Carga el certificado guardado si sigue valiendo para estos nombres. */
static int
load_server_locked(const names_t *nm) {
  char meta[1200], want[1024];
  uint8_t key[DER_MAX], *der = malloc(DER_MAX);
  int ml, kl, dl, r = -1;

  if(!der) return -1;
  names_join(nm, want, sizeof(want));
  if((ml = read_file("server.meta", meta, sizeof(meta))) < 0) goto out;
  meta[ml] = 0;
  long long exp = atoll(meta);
  char *nl = strchr(meta, '\n');
  if(!nl) goto out;
  char *names = nl + 1;
  names[strcspn(names, "\n")] = 0;
  if(strcmp(names, want) || exp - (long long)time(NULL) < SRV_RENEW_DAYS * 86400LL) goto out;
  if((kl = read_file("server.key", key, sizeof(key))) < 0) goto out;
  if((dl = read_file("server.der", der, DER_MAX)) < 0) goto out;

  char chain[8192];
  int a = pem_of(der, dl, CERT_TYPE, chain, sizeof(chain));
  if(a < 0) goto out;
  int b = pem_of(g_ca_der, g_ca_der_len, CERT_TYPE, chain + a, sizeof(chain) - (size_t)a);
  if(b < 0) goto out;
  WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
  if(!ctx) goto out;
  wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
  if(wolfSSL_CTX_use_certificate_chain_buffer(ctx, (const unsigned char*)chain, a + b)
       != WOLFSSL_SUCCESS ||
     wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, kl, WOLFSSL_FILETYPE_ASN1)
       != WOLFSSL_SUCCESS) {
    wolfSSL_CTX_free(ctx);
    goto out;
  }
  extern int tls_io_recv(WOLFSSL*, char*, int, void*);
  extern int tls_io_send(WOLFSSL*, char*, int, void*);
  wolfSSL_CTX_SetIORecv(ctx, tls_io_recv);
  wolfSSL_CTX_SetIOSend(ctx, tls_io_send);
  if(g_ctx) wolfSSL_CTX_free(g_ctx);
  g_ctx = ctx;
  snprintf(g_names, sizeof(g_names), "%s", names);
  g_srv_expires = exp;
  r = 0;
 out:
  memset(key, 0, sizeof(key));
  free(der);
  return r;
}


/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

int
tls_io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl;
  int fd = (int)(intptr_t)ctx;
  for(;;) {
    ssize_t n = recv(fd, buf, (size_t)sz, 0);
    if(n > 0) return (int)n;
    if(n == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    if(errno == EINTR) continue;
    if(errno == EAGAIN || errno == EWOULDBLOCK) return WOLFSSL_CBIO_ERR_TIMEOUT;
    if(errno == ECONNRESET) return WOLFSSL_CBIO_ERR_CONN_RST;
    return WOLFSSL_CBIO_ERR_GENERAL;
  }
}


int
tls_io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl;
  int fd = (int)(intptr_t)ctx;
  for(;;) {
    ssize_t n = send(fd, buf, (size_t)sz, MSG_NOSIGNAL);
    if(n >= 0) return (int)n;
    if(errno == EINTR) continue;
    if(errno == EAGAIN || errno == EWOULDBLOCK) return WOLFSSL_CBIO_ERR_TIMEOUT;
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  }
}


int
tls_init(const char *confdir) {
  int r = -1;
  pthread_mutex_lock(&g_tls_lock);
  if(!g_wolf_init) {
    wolfSSL_Init();
    g_wolf_init = 1;
  }
  snprintf(g_dir, sizeof(g_dir), "%s/tls", confdir);
  mkdir(g_dir, 0700);

  g_ca_der_len = read_file("ca.der", g_ca_der, sizeof(g_ca_der));
  g_ca_key_len = read_file("ca.key", g_ca_key, sizeof(g_ca_key));
  if(g_ca_der_len <= 0 || g_ca_key_len <= 0) {
    if(make_ca()) {
      LOG_PUTS("ps5share: no se pudo crear la autoridad de certificación");
      goto out;
    }
  }
  names_t nm;
  collect_names(&nm);
  if(load_server_locked(&nm) && make_server_locked(&nm)) goto out;
  r = 0;
 out:
  pthread_mutex_unlock(&g_tls_lock);
  return r;
}


int
tls_refresh(int force) {
  names_t nm;
  char want[1024];
  int changed = 0;
  collect_names(&nm);
  names_join(&nm, want, sizeof(want));
  pthread_mutex_lock(&g_tls_lock);
  if(g_ca_der_len > 0 &&
     (force || !g_ctx || strcmp(want, g_names) ||
      g_srv_expires - (long long)time(NULL) < SRV_RENEW_DAYS * 86400LL)) {
    changed = !make_server_locked(&nm);
  }
  pthread_mutex_unlock(&g_tls_lock);
  return changed;
}


int
tls_regenerate_ca(void) {
  int r;
  pthread_mutex_lock(&g_tls_lock);
  r = make_ca();
  pthread_mutex_unlock(&g_tls_lock);
  if(!r) tls_refresh(1);
  return r;
}


void *
tls_accept(int fd) {
  WOLFSSL *ssl = NULL;
  pthread_mutex_lock(&g_tls_lock);
  if(g_ctx) ssl = wolfSSL_new(g_ctx);     /* toma una referencia al contexto */
  pthread_mutex_unlock(&g_tls_lock);
  if(!ssl) return NULL;
  wolfSSL_SetIOReadCtx(ssl, (void*)(intptr_t)fd);
  wolfSSL_SetIOWriteCtx(ssl, (void*)(intptr_t)fd);
  if(wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
    wolfSSL_free(ssl);
    return NULL;
  }
  return ssl;
}


long
tls_recv(void *ssl, void *buf, size_t n) {
  if(n > 0x7fffffff) n = 0x7fffffff;
  int k = wolfSSL_read((WOLFSSL*)ssl, buf, (int)n);
  if(k > 0) return k;
  int e = wolfSSL_get_error((WOLFSSL*)ssl, k);
  if(e == WOLFSSL_ERROR_ZERO_RETURN) return 0;
  errno = EIO;
  return -1;
}


int
tls_writeall(void *ssl, const void *buf, size_t n) {
  const char *p = buf;
  while(n) {
    int chunk = n > 16384 ? 16384 : (int)n;
    int k = wolfSSL_write((WOLFSSL*)ssl, p, chunk);
    if(k <= 0) {
      errno = EPIPE;
      return -1;
    }
    p += k;
    n -= (size_t)k;
  }
  return 0;
}


void
tls_close(void *ssl) {
  if(!ssl) return;
  wolfSSL_shutdown((WOLFSSL*)ssl);
  wolfSSL_free((WOLFSSL*)ssl);
}


long
tls_ca_pem(char *out, size_t outlen) {
  long r;
  pthread_mutex_lock(&g_tls_lock);
  r = g_ca_der_len > 0 ? pem_of(g_ca_der, g_ca_der_len, CERT_TYPE, out, outlen) : -1;
  pthread_mutex_unlock(&g_tls_lock);
  return r;
}


void
tls_ca_fingerprint(char *out, size_t outlen) {
  uint8_t d[32];
  size_t o = 0;
  out[0] = 0;
  pthread_mutex_lock(&g_tls_lock);
  int ok = g_ca_der_len > 0 && !wc_Sha256Hash(g_ca_der, (word32)g_ca_der_len, d);
  pthread_mutex_unlock(&g_tls_lock);
  if(!ok) return;
  for(int i=0; i<32 && o + 4 <= outlen; i++) {
    o += (size_t)snprintf(out + o, outlen - o, "%s%02X", i ? ":" : "", d[i]);
  }
}


void
tls_cert_names(char *out, size_t outlen) {
  pthread_mutex_lock(&g_tls_lock);
  snprintf(out, outlen, "%s", g_names);
  pthread_mutex_unlock(&g_tls_lock);
}


long long
tls_cert_expires(void) {
  long long e;
  pthread_mutex_lock(&g_tls_lock);
  e = g_srv_expires;
  pthread_mutex_unlock(&g_tls_lock);
  return e;
}
