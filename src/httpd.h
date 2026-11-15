/* ps5share - piezas internas del servidor web compartidas con los módulos
   del gestor de contraseñas (vault.c, vaultweb.c).
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#pragma once

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "crypt.h"

#define HTTP_HDR_MAX       16384
#define HTTP_BODY_MAX      (256 * 1024)
#define HTTP_BODY_MAX_BIG  (16 * 1024 * 1024)   /* importaciones del gestor */


/* Buffer dinámico para construir respuestas */
typedef struct sb {
  char  *p;
  size_t len, cap;
} sb_t;

void sb_putn(sb_t *b, const char *s, size_t n);
void sb_puts(sb_t *b, const char *s);
void sb_printf(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sb_json_str(sb_t *b, const char *s);


typedef struct req {
  int   fd;
  void *ssl;           /* WOLFSSL* si la conexión es HTTPS */
  int   tls;
  struct sockaddr_in peer;
  char method[8];
  char path[2048];
  char query[4096];
  long long content_length;
  int  chunked;
  int  csrf_ok;
  char cookie_token[80];
  char range[128];
  /* Cabeceras usadas por la API compatible con Bitwarden */
  char auth[4096];          /* Authorization */
  char origin[256];
  char ctype[128];          /* Content-Type */
  char acr_headers[512];    /* Access-Control-Request-Headers */
  char req_email[256];      /* X-Request-Email (base64url) */
  char device_id[128];      /* X-Device-Identifier */
  char host[256];
  /* Pasarela pública (servidor intermedio con Caddy) */
  char gw_hdr[80];          /* X-PS5NAS-Gateway */
  char fwd_for[64];         /* último X-Forwarded-For */
  char fwd_proto[8];        /* X-Forwarded-Proto */
  char fwd_host[256];       /* X-Forwarded-Host */
  char fwd_uri[2048];       /* X-Forwarded-Uri */
  int  via_gw;              /* la petición viene de la pasarela (clave correcta) */
  char alang[3];            /* idioma preferido del navegador (es/en/de) */

  char  hdr[HTTP_HDR_MAX];
  size_t hdr_len;      /* bytes leídos en hdr */
  size_t body_start;   /* offset del cuerpo dentro de hdr */

  char *body;          /* cuerpo (para formularios) */
  size_t body_len;

  user_t user;         /* usuario autenticado (si lo hay) */
  ukey_t key;          /* su clave de cifrado (si la tiene) */
  int    authed;
  const char *extra_hdr;  /* cabeceras extra para todas las respuestas (CORS) */
} req_t;


/* ¿El cliente usa HTTPS?  (directo, o a través de la pasarela) */
int  req_https(const req_t *r);

/* E/S de la conexión (TCP o TLS). */
long req_recv(req_t *r, void *buf, size_t n);
int  req_write(req_t *r, const void *buf, size_t n);

int  get_param(const char *qs, const char *name, char *out, size_t outlen);
int  read_body(req_t *r);
int  read_body_max(req_t *r, size_t max);

int  send_head(req_t *r, int code, const char *ctype, long long len, const char *extra);
int  send_body(req_t *r, int code, const char *ctype, const char *body, size_t len,
               const char *extra);
int  send_json(req_t *r, int code, sb_t *b, const char *extra);
int  send_err(req_t *r, int code, const char *msg);
int  send_ok(req_t *r);

/* IP real del cliente (la de la pasarela si se entra desde internet). */
uint32_t req_ip(const req_t *r);

/* Límite de intentos de inicio de sesión por IP. */
int  rl_blocked(uint32_t ip);
void rl_fail(uint32_t ip);
void rl_clear(uint32_t ip);
