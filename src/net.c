/* ps5share - conexiones salientes (DNS, TLS y cliente HTTPS)
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cacerts.h"
#include "config.h"
#include "io.h"
#include "log.h"
#include "net.h"

#define HTTPS_TIMEOUT 30


/* ------------------------------------------------------------------ */
/* DNS: getaddrinfo y, si no funciona en la consola, consulta propia    */
/* ------------------------------------------------------------------ */

static int
dns_query(const char *server, const char *host, struct in_addr *out) {
  uint8_t q[512], r[512];
  size_t n = 0;
  uint16_t id;
  cfg_random((uint8_t*)&id, sizeof(id));

  q[n++] = id >> 8; q[n++] = id & 0xff;
  q[n++] = 0x01; q[n++] = 0x00;                 /* RD */
  q[n++] = 0; q[n++] = 1; q[n++] = 0; q[n++] = 0;
  q[n++] = 0; q[n++] = 0; q[n++] = 0; q[n++] = 0;
  const char *p = host;
  while(*p) {
    const char *dot = strchr(p, '.');
    size_t l = dot ? (size_t)(dot - p) : strlen(p);
    if(l == 0 || l > 63 || n + l + 6 > sizeof(q)) return -1;
    q[n++] = (uint8_t)l;
    memcpy(q + n, p, l);
    n += l;
    p += l;
    if(*p == '.') p++;
  }
  q[n++] = 0;
  q[n++] = 0; q[n++] = 1;   /* A */
  q[n++] = 0; q[n++] = 1;   /* IN */

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd < 0) return -1;
  io_sock_timeouts(fd, 4);
  struct sockaddr_in sa = {0};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(53);
  inet_pton(AF_INET, server, &sa.sin_addr);
  int ret = -1;
  for(int attempt = 0; attempt < 2 && ret; attempt++) {
    if(sendto(fd, q, n, 0, (struct sockaddr*)&sa, sizeof(sa)) != (ssize_t)n) break;
    ssize_t rn = recv(fd, r, sizeof(r), 0);
    if(rn < 12 || r[0] != q[0] || r[1] != q[1] || (r[3] & 0x0f)) continue;
    int qd = (r[4] << 8) | r[5], an = (r[6] << 8) | r[7];
    size_t o = 12;
    for(int i=0; i<qd; i++) {               /* salta las preguntas */
      while(o < (size_t)rn && r[o] && !(r[o] & 0xc0)) o += r[o] + 1;
      o += (o < (size_t)rn && (r[o] & 0xc0)) ? 2 : 1;
      o += 4;
    }
    for(int i=0; i<an && o < (size_t)rn; i++) {
      while(o < (size_t)rn && r[o] && !(r[o] & 0xc0)) o += r[o] + 1;
      o += (o < (size_t)rn && (r[o] & 0xc0)) ? 2 : 1;
      if(o + 10 > (size_t)rn) break;
      int type = (r[o] << 8) | r[o+1];
      int rdlen = (r[o+8] << 8) | r[o+9];
      o += 10;
      if(o + rdlen > (size_t)rn) break;
      if(type == 1 && rdlen == 4) {
        memcpy(out, r + o, 4);
        ret = 0;
        break;
      }
      o += rdlen;
    }
  }
  close(fd);
  return ret;
}


int
net_resolve(const char *host, struct in_addr *out) {
  if(inet_pton(AF_INET, host, out) == 1) return 0;

  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if(!getaddrinfo(host, NULL, &hints, &res) && res) {
    *out = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
  }
  if(res) freeaddrinfo(res);
  static const char *servers[] = {"1.1.1.1", "8.8.8.8", "9.9.9.9"};
  for(size_t i=0; i<sizeof(servers)/sizeof(servers[0]); i++) {
    if(!dns_query(servers[i], host, out)) return 0;
  }
  return -1;
}


int
net_connect(const char *host, uint16_t port, int timeout, char *err, size_t errlen) {
  struct in_addr ip;
  if(net_resolve(host, &ip)) {
    snprintf(err, errlen, "No se encontró el servidor %s (¿hay internet en la consola?)", host);
    return -1;
  }
  struct sockaddr_in sa = {0};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr = ip;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) {
    snprintf(err, errlen, "socket: %s", strerror(errno));
    return -1;
  }
  io_sock_timeouts(fd, timeout);
  if(connect(fd, (struct sockaddr*)&sa, sizeof(sa))) {
    snprintf(err, errlen, "No se pudo conectar con %s:%u (%s)", host, port, strerror(errno));
    close(fd);
    return -1;
  }
  return fd;
}


/* ------------------------------------------------------------------ */
/* TLS                                                                 */
/* ------------------------------------------------------------------ */

static int
io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl;
  int fd = *(int*)ctx;
  for(;;) {
    ssize_t n = recv(fd, buf, (size_t)sz, 0);
    if(n > 0) return (int)n;
    if(n == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    if(errno == EINTR) continue;
    if(errno == EAGAIN || errno == EWOULDBLOCK) return WOLFSSL_CBIO_ERR_TIMEOUT;
    return WOLFSSL_CBIO_ERR_GENERAL;
  }
}


static int
io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl;
  int fd = *(int*)ctx;
  for(;;) {
    ssize_t n = send(fd, buf, (size_t)sz, MSG_NOSIGNAL);
    if(n >= 0) return (int)n;
    if(errno == EINTR) continue;
    if(errno == EAGAIN || errno == EWOULDBLOCK) return WOLFSSL_CBIO_ERR_TIMEOUT;
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  }
}


static pthread_once_t g_wolf_once = PTHREAD_ONCE_INIT;
static void wolf_init(void) { wolfSSL_Init(); }


/* Carga un PEM de disco como CA adicional (si existe). */
static void
load_extra_ca(WOLFSSL_CTX *ctx, const char *path) {
  FILE *f = fopen(path, "r");
  if(!f) return;
  char *pem = malloc(256 * 1024);
  if(pem) {
    size_t n = fread(pem, 1, 256 * 1024, f);
    if(n) wolfSSL_CTX_load_verify_buffer(ctx, (unsigned char*)pem, (long)n, WOLFSSL_FILETYPE_PEM);
    free(pem);
  }
  fclose(f);
}


int
net_tls_start(int *fdp, const char *host, WOLFSSL_CTX **ctxp, WOLFSSL **sslp,
              char *err, size_t errlen) {
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;

  pthread_once(&g_wolf_once, wolf_init);
  *ctxp = NULL;
  *sslp = NULL;
  if(!(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()))) {
    snprintf(err, errlen, "No se pudo preparar TLS");
    return -1;
  }
  *ctxp = ctx;
  wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
  if(wolfSSL_CTX_load_verify_buffer(ctx, (const unsigned char*)CA_CERTS_PEM,
                                    (long)strlen(CA_CERTS_PEM), WOLFSSL_FILETYPE_PEM)
     != WOLFSSL_SUCCESS) {
    snprintf(err, errlen, "No se pudieron cargar los certificados raíz");
    return -1;
  }
  const char *dir = cfg_dir();
  if(dir && dir[0]) {
    char path[512];
    snprintf(path, sizeof(path), "%s/ca-extra.pem", dir);
    load_extra_ca(ctx, path);
  }
#ifndef __PROSPERO__
  /* Pruebas locales: CA adicional. */
  const char *test_ca = getenv("PS5SHARE_TEST_CA");
  if(test_ca) load_extra_ca(ctx, test_ca);
#endif
  wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
  wolfSSL_CTX_SetIORecv(ctx, io_recv);
  wolfSSL_CTX_SetIOSend(ctx, io_send);

  if(!(ssl = wolfSSL_new(ctx))) {
    snprintf(err, errlen, "No se pudo preparar TLS");
    return -1;
  }
  *sslp = ssl;
  wolfSSL_SetIOReadCtx(ssl, fdp);
  wolfSSL_SetIOWriteCtx(ssl, fdp);
  wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host, (word16)strlen(host));
  wolfSSL_check_domain_name(ssl, host);

  if(wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
    int e = wolfSSL_get_error(ssl, 0);
    char es[80];
    wolfSSL_ERR_error_string_n(e, es, sizeof(es));
    if(e == ASN_AFTER_DATE_E || e == ASN_BEFORE_DATE_E) {
      snprintf(err, errlen, "Certificado del servidor fuera de fecha: revisa la hora de la consola");
    } else if(e == ASN_NO_SIGNER_E) {
      snprintf(err, errlen, "No se reconoce la CA del certificado de %s: añade su CA raíz "
               "en ca-extra.pem, en la carpeta de configuración", host);
    } else {
      snprintf(err, errlen, "Falló la conexión segura con %s (%d: %s)", host, e, es);
    }
    return -1;
  }
  return 0;
}


void
net_tls_close(WOLFSSL_CTX *ctx, WOLFSSL *ssl) {
  if(ssl) {
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
  }
  if(ctx) wolfSSL_CTX_free(ctx);
}


/* ------------------------------------------------------------------ */
/* Cliente HTTPS (una petición por conexión)                           */
/* ------------------------------------------------------------------ */

void
net_urlencode(const char *s, char *out, size_t outlen) {
  static const char hex[] = "0123456789ABCDEF";
  size_t o = 0;
  if(!outlen) return;
  for(const unsigned char *p = (const unsigned char*)s; *p; p++) {
    int safe = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' || *p == '~';
    if(safe) {
      if(o + 1 >= outlen) break;
      out[o++] = (char)*p;
    } else {
      if(o + 3 >= outlen) break;
      out[o++] = '%';
      out[o++] = hex[*p >> 4];
      out[o++] = hex[*p & 15];
    }
  }
  out[o] = 0;
}


void
https_resp_free(https_resp_t *r) {
  free(r->body);
  memset(r, 0, sizeof(*r));
}


static int
tls_writeall(WOLFSSL *ssl, const char *s, size_t n) {
  while(n) {
    int w = wolfSSL_write(ssl, s, (int)n);
    if(w <= 0) return -1;
    s += w;
    n -= (size_t)w;
  }
  return 0;
}


/* Decodifica en el sitio un cuerpo «chunked».  Devuelve la longitud o -1. */
static long
dechunk(char *buf, size_t len) {
  size_t in = 0, out = 0;
  for(;;) {
    char *nl = memchr(buf + in, '\n', len - in);
    if(!nl) return -1;
    unsigned long sz = strtoul(buf + in, NULL, 16);
    in = (size_t)(nl - buf) + 1;
    if(sz == 0) break;
    if(in + sz > len) return -1;
    memmove(buf + out, buf + in, sz);
    out += sz;
    in += sz;
    if(in < len && buf[in] == '\r') in++;
    if(in < len && buf[in] == '\n') in++;
  }
  buf[out] = 0;
  return (long)out;
}


int
https_request(const char *method, const char *url, const char *headers,
              const char *body, size_t body_len, https_resp_t *out,
              char *err, size_t errlen) {
  char host[256], hostport[300];
  const char *path;
  uint16_t port = 443;
  int fd = -1, ret = -1;
  WOLFSSL_CTX *ctx = NULL;
  WOLFSSL *ssl = NULL;
  char *buf = NULL;
  size_t len = 0, cap = 0;

  memset(out, 0, sizeof(*out));
  err[0] = 0;

  if(strncmp(url, "https://", 8)) {
    snprintf(err, errlen, "URL no válida: %s", url);
    return -1;
  }
  const char *h = url + 8;
  path = strchr(h, '/');
  size_t hl = path ? (size_t)(path - h) : strlen(h);
  if(!path) path = "/";
  if(hl == 0 || hl >= sizeof(host)) {
    snprintf(err, errlen, "URL no válida");
    return -1;
  }
  memcpy(host, h, hl);
  host[hl] = 0;
  memcpy(hostport, host, hl + 1);
  char *colon = strchr(host, ':');
  if(colon) {
    *colon = 0;
    port = (uint16_t)atoi(colon + 1);
  }

  if((fd = net_connect(host, port, HTTPS_TIMEOUT, err, errlen)) < 0) return -1;
  if(net_tls_start(&fd, host, &ctx, &ssl, err, errlen)) goto out;

  {
    char head[4096];
    int n = snprintf(head, sizeof(head),
                     "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: PS5NAS\r\n"
                     "Accept: application/json\r\nAccept-Encoding: identity\r\n"
                     "Connection: close\r\nContent-Length: %zu\r\n%s\r\n",
                     method, path, hostport, body ? body_len : 0, headers ? headers : "");
    if(n < 0 || (size_t)n >= sizeof(head)) {
      snprintf(err, errlen, "Petición demasiado larga");
      goto out;
    }
    if(tls_writeall(ssl, head, (size_t)n) || (body && body_len && tls_writeall(ssl, body, body_len))) {
      snprintf(err, errlen, "Conexión interrumpida con %s", host);
      goto out;
    }
  }

  /* Lee hasta que el servidor cierre. */
  for(;;) {
    if(len + 16385 > cap) {
      size_t nc = cap ? cap * 2 : 65536;
      if(nc > HTTPS_BODY_MAX + 65536) {
        snprintf(err, errlen, "Respuesta demasiado grande de %s", host);
        goto out;
      }
      char *nb = realloc(buf, nc);
      if(!nb) {
        snprintf(err, errlen, "Sin memoria");
        goto out;
      }
      buf = nb;
      cap = nc;
    }
    int r = wolfSSL_read(ssl, buf + len, (int)(cap - len - 1));
    if(r > 0) {
      len += (size_t)r;
      continue;
    }
    int e = wolfSSL_get_error(ssl, r);
    if(e == WOLFSSL_ERROR_ZERO_RETURN || e == SOCKET_PEER_CLOSED_E || r == 0) break;
    if(len) break;   /* algunos servidores cierran sin close_notify */
    snprintf(err, errlen, "No llegó respuesta de %s", host);
    goto out;
  }
  if(!buf) {
    snprintf(err, errlen, "Respuesta vacía de %s", host);
    goto out;
  }
  buf[len] = 0;

  /* Cabeceras */
  char *eoh = strstr(buf, "\r\n\r\n");
  if(strncmp(buf, "HTTP/1.", 7) || !eoh) {
    snprintf(err, errlen, "Respuesta no válida de %s", host);
    goto out;
  }
  out->status = atoi(buf + 9);
  int chunked = 0;
  long clen = -1;
  *eoh = 0;
  for(char *line = strstr(buf, "\r\n"); line; line = strstr(line, "\r\n")) {
    line += 2;
    if(!strncasecmp(line, "Transfer-Encoding:", 18) && strcasestr(line, "chunked")) chunked = 1;
    else if(!strncasecmp(line, "Content-Length:", 15)) clen = atol(line + 15);
    else if(!strncasecmp(line, "Retry-After:", 12)) out->retry_after = atoi(line + 12);
  }
  char *b = eoh + 4;
  size_t blen = len - (size_t)(b - buf);
  memmove(buf, b, blen);
  buf[blen] = 0;
  if(chunked) {
    long l = dechunk(buf, blen);
    if(l < 0) {
      snprintf(err, errlen, "Respuesta incompleta de %s", host);
      goto out;
    }
    blen = (size_t)l;
  } else if(clen >= 0 && (size_t)clen < blen) {
    blen = (size_t)clen;
    buf[blen] = 0;
  }
  out->body = buf;
  out->len = blen;
  buf = NULL;
  ret = 0;

 out:
  free(buf);
  net_tls_close(ctx, ssl);
  if(fd >= 0) close(fd);
  return ret;
}
