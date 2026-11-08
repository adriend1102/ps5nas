/* ps5share - envío de correos (recuperación de contraseñas)
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Cliente SMTP mínimo con TLS (wolfSSL) y verificación del certificado del
   servidor.  Puerto 465: TLS directo.  Puerto 587 (u otro): STARTTLS.
   Autenticación AUTH PLAIN (en Gmail, con una «contraseña de aplicación»). */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include "cacerts.h"
#include "config.h"
#include "io.h"
#include "log.h"
#include "smtp.h"

#define SMTP_TIMEOUT 20


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


static int
resolve(const char *host, struct in_addr *out) {
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


/* ------------------------------------------------------------------ */
/* Conexión (texto plano o TLS)                                        */
/* ------------------------------------------------------------------ */

typedef struct conn {
  int          fd;
  WOLFSSL_CTX *ctx;
  WOLFSSL     *ssl;
  char         buf[4096];
  size_t       len;
  char        *err;
  size_t       errlen;
} conn_t;


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


static int g_wolf_init = 0;


static int
tls_start(conn_t *c, const char *host) {
  if(!g_wolf_init) {
    wolfSSL_Init();
    g_wolf_init = 1;
  }
  if(!(c->ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()))) {
    snprintf(c->err, c->errlen, "No se pudo preparar TLS");
    return -1;
  }
  wolfSSL_CTX_SetMinVersion(c->ctx, WOLFSSL_TLSV1_2);
  if(wolfSSL_CTX_load_verify_buffer(c->ctx, (const unsigned char*)CA_CERTS_PEM,
                                    (long)strlen(CA_CERTS_PEM), WOLFSSL_FILETYPE_PEM)
     != WOLFSSL_SUCCESS) {
    snprintf(c->err, c->errlen, "No se pudieron cargar los certificados raíz");
    return -1;
  }
#ifndef __PROSPERO__
  /* Pruebas locales: CA adicional. */
  const char *test_ca = getenv("PS5SHARE_TEST_CA");
  if(test_ca) {
    FILE *f = fopen(test_ca, "r");
    if(f) {
      char pem[8192];
      size_t n = fread(pem, 1, sizeof(pem), f);
      fclose(f);
      wolfSSL_CTX_load_verify_buffer(c->ctx, (unsigned char*)pem, (long)n,
                                     WOLFSSL_FILETYPE_PEM);
    }
  }
#endif
  wolfSSL_CTX_set_verify(c->ctx, WOLFSSL_VERIFY_PEER, NULL);
  wolfSSL_CTX_SetIORecv(c->ctx, io_recv);
  wolfSSL_CTX_SetIOSend(c->ctx, io_send);

  if(!(c->ssl = wolfSSL_new(c->ctx))) {
    snprintf(c->err, c->errlen, "No se pudo preparar TLS");
    return -1;
  }
  wolfSSL_SetIOReadCtx(c->ssl, &c->fd);
  wolfSSL_SetIOWriteCtx(c->ssl, &c->fd);
  wolfSSL_UseSNI(c->ssl, WOLFSSL_SNI_HOST_NAME, host, (word16)strlen(host));
  wolfSSL_check_domain_name(c->ssl, host);

  if(wolfSSL_connect(c->ssl) != WOLFSSL_SUCCESS) {
    int e = wolfSSL_get_error(c->ssl, 0);
    char es[80];
    wolfSSL_ERR_error_string_n(e, es, sizeof(es));
    if(e == ASN_AFTER_DATE_E || e == ASN_BEFORE_DATE_E) {
      snprintf(c->err, c->errlen, "Certificado del servidor fuera de fecha: revisa la hora de la consola");
    } else {
      snprintf(c->err, c->errlen, "Falló la conexión segura con %s (%d: %s)", host, e, es);
    }
    return -1;
  }
  return 0;
}


static int
c_write(conn_t *c, const char *s, size_t n) {
  if(c->ssl) {
    while(n) {
      int w = wolfSSL_write(c->ssl, s, (int)n);
      if(w <= 0) return -1;
      s += w;
      n -= (size_t)w;
    }
    return 0;
  }
  return io_writeall(c->fd, s, n);
}


static int
c_puts(conn_t *c, const char *s) {
  return c_write(c, s, strlen(s));
}


/* Lee una línea (sin \r\n).  -1 si se corta. */
static int
c_readline(conn_t *c, char *out, size_t outlen) {
  for(;;) {
    char *nl = memchr(c->buf, '\n', c->len);
    if(nl) {
      size_t l = (size_t)(nl - c->buf);
      size_t cl = l;
      if(cl && c->buf[cl-1] == '\r') cl--;
      if(cl >= outlen) cl = outlen - 1;
      memcpy(out, c->buf, cl);
      out[cl] = 0;
      memmove(c->buf, nl + 1, c->len - l - 1);
      c->len -= l + 1;
      return 0;
    }
    if(c->len >= sizeof(c->buf) - 1) c->len = 0;   /* línea absurda */
    int n;
    if(c->ssl) n = wolfSSL_read(c->ssl, c->buf + c->len, (int)(sizeof(c->buf) - 1 - c->len));
    else n = (int)recv(c->fd, c->buf + c->len, sizeof(c->buf) - 1 - c->len, 0);
    if(n <= 0) return -1;
    c->len += (size_t)n;
  }
}


/* Lee una respuesta completa (multilínea) y devuelve el código. */
static int
c_reply(conn_t *c, char *last, size_t lastlen) {
  char line[1024];
  for(;;) {
    if(c_readline(c, line, sizeof(line))) {
      snprintf(c->err, c->errlen, "El servidor de correo cerró la conexión");
      return -1;
    }
    if(strlen(line) < 3) continue;
    if(last && lastlen) {
      size_t l = strlen(line);
      if(l >= lastlen) l = lastlen - 1;
      memcpy(last, line, l);
      last[l] = 0;
    }
    if(line[3] != '-') return atoi(line);
  }
}


static int
expect(conn_t *c, int want, const char *what) {
  char last[512];
  int code = c_reply(c, last, sizeof(last));
  if(code < 0) return -1;
  if(code / 100 != want / 100) {
    if(code == 535 || code == 534) {
      snprintf(c->err, c->errlen, "El servidor rechazó la cuenta o la contraseña de correo. "
               "En Gmail usa una «contraseña de aplicación» (%s)", last);
    } else {
      snprintf(c->err, c->errlen, "%s: %s", what, last);
    }
    return -1;
  }
  return 0;
}


static int
cmd(conn_t *c, const char *line, int want, const char *what) {
  if(c_puts(c, line) || c_puts(c, "\r\n")) {
    snprintf(c->err, c->errlen, "Conexión interrumpida");
    return -1;
  }
  return expect(c, want, what);
}


/* ------------------------------------------------------------------ */
/* Mensaje                                                             */
/* ------------------------------------------------------------------ */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


static size_t
b64(const unsigned char *in, size_t n, char *out) {
  size_t o = 0;
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
  return o;
}


static int
send_message(conn_t *c, const settings_t *s, const char *to, const char *subject,
             const char *body) {
  size_t blen = strlen(body), slen = strlen(subject);
  size_t cap = 4096 + slen * 2 + (blen + 2) / 3 * 4 + (blen / 57 + 2) * 2;
  char *msg = malloc(cap), *b64body = malloc((blen + 2) / 3 * 4 + 4);
  char *b64subj = malloc((slen + 2) / 3 * 4 + 4), *b64name = malloc(256);
  char date[64], mid[33];
  int ret = -1;

  if(!msg || !b64body || !b64subj || !b64name) {
    snprintf(c->err, c->errlen, "Sin memoria");
    goto out;
  }
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S +0000", &tm);
  cfg_random_hex(mid, 16);
  b64((const unsigned char*)subject, slen, b64subj);
  b64((const unsigned char*)s->smtp_from_name, strlen(s->smtp_from_name), b64name);
  b64((const unsigned char*)body, blen, b64body);

  size_t o = (size_t)snprintf(msg, cap,
      "From: =?UTF-8?B?%s?= <%s>\r\n"
      "To: <%s>\r\n"
      "Subject: =?UTF-8?B?%s?=\r\n"
      "Date: %s\r\n"
      "Message-ID: <%s@ps5nas>\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: text/plain; charset=utf-8\r\n"
      "Content-Transfer-Encoding: base64\r\n"
      "\r\n",
      b64name, s->smtp_user, to, b64subj, date, mid);
  for(size_t i=0, n=strlen(b64body); i<n; i += 76) {
    size_t l = n - i < 76 ? n - i : 76;
    memcpy(msg + o, b64body + i, l);
    o += l;
    msg[o++] = '\r';
    msg[o++] = '\n';
  }
  memcpy(msg + o, ".\r\n", 4);
  o += 3;

  if(cmd(c, "DATA", 354, "DATA")) goto out;
  if(c_write(c, msg, o)) {
    snprintf(c->err, c->errlen, "Conexión interrumpida al enviar");
    goto out;
  }
  if(expect(c, 250, "Envío rechazado")) goto out;
  ret = 0;

 out:
  free(msg);
  free(b64body);
  free(b64subj);
  free(b64name);
  return ret;
}


int
smtp_send(const char *to, const char *subject, const char *body, char *err, size_t errlen) {
  settings_t s;
  char pass[CRYPT_SEAL_MAX + 1], line[1024];
  conn_t c;
  struct in_addr ip;
  int ret = -1;

  memset(&c, 0, sizeof(c));
  c.fd = -1;
  c.err = err;
  c.errlen = errlen;
  err[0] = 0;

  cfg_lock();
  memcpy(&s, cfg_settings(), sizeof(s));
  cfg_unlock();
  if(!s.smtp_user[0] || !s.smtp_host[0] || cfg_smtp_password(pass, sizeof(pass))) {
    snprintf(err, errlen, "El correo saliente no está configurado (Ajustes → Correo)");
    return -1;
  }
  if(!cfg_valid_email(to)) {
    snprintf(err, errlen, "Destinatario no válido");
    goto out;
  }

  if(inet_pton(AF_INET, s.smtp_host, &ip) == 1) {
    /* Con una IP no se puede comprobar que el certificado sea del servidor. */
    snprintf(err, errlen, "Pon el nombre del servidor de correo (p. ej. smtp.gmail.com), no una IP");
    goto out;
  }
  if(resolve(s.smtp_host, &ip)) {
    snprintf(err, errlen, "No se encontró el servidor %s (¿hay internet en la consola?)",
             s.smtp_host);
    goto out;
  }
  struct sockaddr_in sa = {0};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(s.smtp_port);
  sa.sin_addr = ip;
  if((c.fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    snprintf(err, errlen, "socket: %s", strerror(errno));
    goto out;
  }
  io_sock_timeouts(c.fd, SMTP_TIMEOUT);
  if(connect(c.fd, (struct sockaddr*)&sa, sizeof(sa))) {
    snprintf(err, errlen, "No se pudo conectar con %s:%u (%s)", s.smtp_host, s.smtp_port,
             strerror(errno));
    goto out;
  }

  int implicit = s.smtp_port == 465;
  if(implicit && tls_start(&c, s.smtp_host)) goto out;
  if(expect(&c, 220, "Saludo del servidor")) goto out;
  if(cmd(&c, "EHLO ps5nas", 250, "EHLO")) goto out;
  if(!implicit) {
    if(cmd(&c, "STARTTLS", 220, "STARTTLS")) goto out;
    c.len = 0;
    if(tls_start(&c, s.smtp_host)) goto out;
    if(cmd(&c, "EHLO ps5nas", 250, "EHLO")) goto out;
  }

  /* AUTH PLAIN: base64("\0usuario\0contraseña") */
  {
    unsigned char raw[2 * (CFG_EMAIL_MAX + 1) + CRYPT_SEAL_MAX + 4];
    size_t ul = strlen(s.smtp_user), pl = strlen(pass);
    raw[0] = 0;
    memcpy(raw + 1, s.smtp_user, ul);
    raw[1 + ul] = 0;
    memcpy(raw + 2 + ul, pass, pl);
    char enc[sizeof(raw) * 2];
    b64(raw, 2 + ul + pl, enc);
    snprintf(line, sizeof(line), "AUTH PLAIN %s", enc);
    memset(raw, 0, sizeof(raw));
    memset(enc, 0, sizeof(enc));
    int r = cmd(&c, line, 235, "Autenticación");
    memset(line, 0, sizeof(line));
    if(r) goto out;
  }
  snprintf(line, sizeof(line), "MAIL FROM:<%s>", s.smtp_user);
  if(cmd(&c, line, 250, "Remitente rechazado")) goto out;
  snprintf(line, sizeof(line), "RCPT TO:<%s>", to);
  if(cmd(&c, line, 250, "Destinatario rechazado")) goto out;
  if(send_message(&c, &s, to, subject, body)) goto out;
  c_puts(&c, "QUIT\r\n");
  ret = 0;

 out:
  memset(pass, 0, sizeof(pass));
  if(c.ssl) {
    wolfSSL_shutdown(c.ssl);
    wolfSSL_free(c.ssl);
  }
  if(c.ctx) wolfSSL_CTX_free(c.ctx);
  if(c.fd >= 0) close(c.fd);
  if(ret) LOG_PRINTF("ps5share: no se pudo enviar el correo: %s\n", err);
  return ret;
}
