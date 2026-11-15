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

#include "config.h"
#include "io.h"
#include "log.h"
#include "net.h"
#include "smtp.h"

#define SMTP_TIMEOUT 20


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
tls_start(conn_t *c, const char *host) {
  return net_tls_start(&c->fd, host, &c->ctx, &c->ssl, c->err, c->errlen);
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
  if((c.fd = net_connect(s.smtp_host, s.smtp_port, SMTP_TIMEOUT, err, errlen)) < 0) goto out;

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
  net_tls_close(c.ctx, c.ssl);
  if(c.fd >= 0) close(c.fd);
  if(ret) LOG_PRINTF("ps5share: no se pudo enviar el correo: %s\n", err);
  return ret;
}
