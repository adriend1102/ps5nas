/* ps5share - servidor web: explorador de archivos y administración
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Servidor HTTP/1.1 mínimo (una petición por conexión) con:
   - Sesiones por cookie (HttpOnly, SameSite=Strict).
   - Protección CSRF: toda petición que modifica algo exige la cabecera
     "X-PS5Share: 1", que un formulario de otra web no puede enviar.
   - API de archivos (/api/fs/...) limitada al VFS del usuario.
   - API de administración (/api/admin/...) solo para administradores.  */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "http.h"
#include "httpd.h"
#include "tls.h"
#include "vault.h"
#include "vaultweb.h"
#include "notify.h"
#include "sha256.h"
#include "smtp.h"
#include "tsip.h"
#include "sftp.h"
#include "io.h"
#include "log.h"
#include "vfs.h"
#include "webui.h"

#define HTTP_MAX_CLIENTS   64
#define HTTP_TIMEOUT       60
#define SESSION_MAX        256
#define SESSION_TTL        (12 * 3600)
#define SESSION_TTL_LONG   (180 * 24 * 3600)   /* «recordar sesión en este dispositivo» */
#define RL_SLOTS           64
#define RL_WINDOW          600
#define RL_MAX_FAILS       10


/* ------------------------------------------------------------------ */
/* Buffer dinámico para construir respuestas JSON                      */
/* ------------------------------------------------------------------ */

void
sb_putn(sb_t *b, const char *s, size_t n) {
  if(b->len + n + 1 > b->cap) {
    size_t nc = b->cap ? b->cap : 1024;
    while(nc < b->len + n + 1) nc *= 2;
    char *np = realloc(b->p, nc);
    if(!np) return;
    b->p = np;
    b->cap = nc;
  }
  memcpy(b->p + b->len, s, n);
  b->len += n;
  b->p[b->len] = 0;
}


void sb_puts(sb_t *b, const char *s) { sb_putn(b, s, strlen(s)); }


void
sb_printf(sb_t *b, const char *fmt, ...) {
  char tmp[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if(n > 0 && (size_t)n >= sizeof(tmp)) {
    char *big = malloc((size_t)n + 1);
    if(!big) return;
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    sb_putn(b, big, (size_t)n);
    free(big);
    return;
  }
  if(n > 0) sb_putn(b, tmp, (size_t)n);
}


void
sb_json_str(sb_t *b, const char *s) {
  sb_putn(b, "\"", 1);
  for(const unsigned char *p = (const unsigned char*)s; *p; p++) {
    char esc[8];
    switch(*p) {
    case '"':  sb_putn(b, "\\\"", 2); break;
    case '\\': sb_putn(b, "\\\\", 2); break;
    case '\n': sb_putn(b, "\\n", 2); break;
    case '\r': sb_putn(b, "\\r", 2); break;
    case '\t': sb_putn(b, "\\t", 2); break;
    default:
      if(*p < 0x20) {
        snprintf(esc, sizeof(esc), "\\u%04x", *p);
        sb_puts(b, esc);
      } else {
        sb_putn(b, (const char*)p, 1);
      }
    }
  }
  sb_putn(b, "\"", 1);
}


/* ------------------------------------------------------------------ */
/* Petición                                                            */
/* ------------------------------------------------------------------ */

/* E/S de la conexión: TCP directo o TLS. */
long
req_recv(req_t *r, void *buf, size_t n) {
  if(r->ssl) return tls_recv(r->ssl, buf, n);
  for(;;) {
    ssize_t k = recv(r->fd, buf, n, 0);
    if(k < 0 && errno == EINTR) continue;
    return (long)k;
  }
}


int
req_write(req_t *r, const void *buf, size_t n) {
  if(r->ssl) return tls_writeall(r->ssl, buf, n);
  return io_writeall(r->fd, buf, n);
}


static int
hexval(int c) {
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}


/* Decodifica %xx y '+' (si PLUS).  Devuelve -1 si aparece un byte nulo. */
static int
url_decode(const char *in, size_t n, char *out, size_t outlen, int plus) {
  size_t o = 0;
  for(size_t i=0; i<n && o + 1 < outlen; i++) {
    char c = in[i];
    if(c == '%' && i + 2 < n && hexval(in[i+1]) >= 0 && hexval(in[i+2]) >= 0) {
      c = (char)(hexval(in[i+1]) * 16 + hexval(in[i+2]));
      i += 2;
    } else if(plus && c == '+') {
      c = ' ';
    }
    if(c == 0) return -1;
    out[o++] = c;
  }
  out[o] = 0;
  return 0;
}


/* Busca NAME en una cadena tipo a=1&b=2 y lo decodifica en OUT. */
int
get_param(const char *qs, const char *name, char *out, size_t outlen) {
  size_t nlen = strlen(name);
  const char *p = qs;
  out[0] = 0;
  if(!qs) return -1;
  while(*p) {
    const char *amp = strchr(p, '&');
    size_t seg = amp ? (size_t)(amp - p) : strlen(p);
    if(seg > nlen && p[nlen] == '=' && !strncmp(p, name, nlen)) {
      return url_decode(p + nlen + 1, seg - nlen - 1, out, outlen, 1);
    }
    if(seg == nlen && !strncmp(p, name, nlen)) {
      return 0;
    }
    if(!amp) break;
    p = amp + 1;
  }
  return -1;
}


static int
read_headers(req_t *r) {
  r->hdr_len = 0;
  for(;;) {
    if(r->hdr_len >= sizeof(r->hdr) - 1) return -1;
    long n = req_recv(r, r->hdr + r->hdr_len, sizeof(r->hdr) - 1 - r->hdr_len);
    if(n <= 0) return -1;
    r->hdr_len += (size_t)n;
    r->hdr[r->hdr_len] = 0;
    char *end = strstr(r->hdr, "\r\n\r\n");
    if(end) {
      r->body_start = (size_t)(end - r->hdr) + 4;
      return 0;
    }
  }
}


static void
trim(char *s) {
  size_t n = strlen(s);
  while(n && (s[n-1] == ' ' || s[n-1] == '\t')) s[--n] = 0;
}


static int
parse_request(req_t *r) {
  char *save = NULL;
  /* Corta el texto en el final de las cabeceras para que strtok_r no toque
     los primeros bytes del cuerpo, que ya están en el mismo búfer. */
  r->hdr[r->body_start - 1] = 0;
  char *line = strtok_r(r->hdr, "\r\n", &save);
  char target[8192];

  if(!line) return -1;
  if(sscanf(line, "%7s %8191s", r->method, target) != 2) return -1;

  char *q = strchr(target, '?');
  if(q) {
    *q++ = 0;
    snprintf(r->query, sizeof(r->query), "%s", q);
  }
  if(url_decode(target, strlen(target), r->path, sizeof(r->path), 0)) return -1;

  r->content_length = -1;
  while((line = strtok_r(NULL, "\r\n", &save))) {
    char *colon = strchr(line, ':');
    if(!colon) continue;
    *colon = 0;
    char *val = colon + 1;
    while(*val == ' ' || *val == '\t') val++;
    trim(val);

    if(!strcasecmp(line, "Content-Length")) {
      r->content_length = atoll(val);
    } else if(!strcasecmp(line, "Transfer-Encoding")) {
      r->chunked = strcasecmp(val, "identity") != 0;
    } else if(!strcasecmp(line, "X-PS5Share")) {
      r->csrf_ok = !strcmp(val, "1");
    } else if(!strcasecmp(line, "Range")) {
      snprintf(r->range, sizeof(r->range), "%s", val);
    } else if(!strcasecmp(line, "Authorization")) {
      snprintf(r->auth, sizeof(r->auth), "%s", val);
    } else if(!strcasecmp(line, "Origin")) {
      snprintf(r->origin, sizeof(r->origin), "%s", val);
    } else if(!strcasecmp(line, "Content-Type")) {
      snprintf(r->ctype, sizeof(r->ctype), "%s", val);
    } else if(!strcasecmp(line, "Access-Control-Request-Headers")) {
      snprintf(r->acr_headers, sizeof(r->acr_headers), "%s", val);
    } else if(!strcasecmp(line, "X-Request-Email")) {
      snprintf(r->req_email, sizeof(r->req_email), "%s", val);
    } else if(!strcasecmp(line, "X-Device-Identifier")) {
      snprintf(r->device_id, sizeof(r->device_id), "%s", val);
    } else if(!strcasecmp(line, "Host")) {
      snprintf(r->host, sizeof(r->host), "%s", val);
    } else if(!strcasecmp(line, "Cookie")) {
      const char *c = strstr(val, "ps5s=");
      while(c && c != val && c[-1] != ' ' && c[-1] != ';') c = strstr(c + 1, "ps5s=");
      if(c) {
        c += 5;
        size_t n = strcspn(c, "; ");
        if(n < sizeof(r->cookie_token)) {
          memcpy(r->cookie_token, c, n);
          r->cookie_token[n] = 0;
        }
      }
    }
  }
  return 0;
}


/* Lee el cuerpo completo (para formularios pequeños). */
int
read_body(req_t *r) {
  return read_body_max(r, HTTP_BODY_MAX);
}


int
read_body_max(req_t *r, size_t max) {
  if(r->body) return 0;
  if(r->chunked) return -1;
  long long cl = r->content_length < 0 ? 0 : r->content_length;
  if(cl > (long long)max) return -1;

  r->body = malloc((size_t)cl + 1);
  if(!r->body) return -1;

  size_t have = r->hdr_len - r->body_start;
  if(have > (size_t)cl) have = (size_t)cl;
  memcpy(r->body, r->hdr + r->body_start, have);
  while(have < (size_t)cl) {
    long n = req_recv(r, r->body + have, (size_t)cl - have);
    if(n <= 0) return -1;
    have += (size_t)n;
  }
  r->body[have] = 0;
  r->body_len = have;
  return 0;
}


/* ------------------------------------------------------------------ */
/* Respuestas                                                          */
/* ------------------------------------------------------------------ */

static const char *
status_text(int code) {
  switch(code) {
  case 200: return "OK";
  case 204: return "No Content";
  case 206: return "Partial Content";
  case 400: return "Bad Request";
  case 401: return "Unauthorized";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 409: return "Conflict";
  case 411: return "Length Required";
  case 413: return "Payload Too Large";
  case 416: return "Range Not Satisfiable";
  case 429: return "Too Many Requests";
  case 500: return "Internal Server Error";
  case 503: return "Service Unavailable";
  case 507: return "Insufficient Storage";
  default:  return "Error";
  }
}


int
send_head(req_t *r, int code, const char *ctype, long long len, const char *extra) {
  char h[4096];
  int n = snprintf(h, sizeof(h),
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Type: %s\r\n"
                   "Content-Length: %lld\r\n"
                   "Connection: close\r\n"
                   "Cache-Control: no-store\r\n"
                   "X-Content-Type-Options: nosniff\r\n"
                   "X-Frame-Options: DENY\r\n"
                   "Referrer-Policy: no-referrer\r\n"
                   "%s%s%s\r\n",
                   code, status_text(code), ctype, len,
                   r->tls ? "Strict-Transport-Security: max-age=31536000\r\n" : "",
                   r->extra_hdr ? r->extra_hdr : "", extra ? extra : "");
  if(n < 0 || (size_t)n >= sizeof(h)) return -1;
  return req_write(r, h, (size_t)n);
}


int
send_body(req_t *r, int code, const char *ctype, const char *body, size_t len,
          const char *extra) {
  if(send_head(r, code, ctype, (long long)len, extra)) return -1;
  if(!strcmp(r->method, "HEAD")) return 0;
  return req_write(r, body, len);
}


int
send_json(req_t *r, int code, sb_t *b, const char *extra) {
  int ret = send_body(r, code, "application/json; charset=utf-8",
                      b->p ? b->p : "{}", b->p ? b->len : 2, extra);
  free(b->p);
  b->p = NULL;
  return ret;
}


int
send_err(req_t *r, int code, const char *msg) {
  sb_t b = {0};
  sb_puts(&b, "{\"error\":");
  sb_json_str(&b, msg);
  sb_puts(&b, "}");
  return send_json(r, code, &b, NULL);
}


int
send_ok(req_t *r) {
  sb_t b = {0};
  sb_puts(&b, "{\"ok\":true}");
  return send_json(r, 200, &b, NULL);
}


static int
send_errno(req_t *r) {
  int e = errno;
  switch(e) {
  case ENOENT:    return send_err(r, 404, "No existe el archivo o carpeta");
  case EACCES:
  case EPERM:     return send_err(r, 403, "Permiso denegado");
  case EEXIST:    return send_err(r, 409, "Ya existe un elemento con ese nombre");
  case ENOTEMPTY: return send_err(r, 409, "La carpeta no está vacía");
  case ENOSPC:    return send_err(r, 507, "Sin espacio en el disco");
  case EXDEV:     return send_err(r, 400, "No se puede mover entre carpetas distintas");
  default:        return send_err(r, 400, strerror(e));
  }
}


/* ------------------------------------------------------------------ */
/* Sesiones y límite de intentos                                       */
/* ------------------------------------------------------------------ */

typedef struct session {
  char   thash[65];    /* SHA-256 del token (el token solo lo tiene el navegador) */
  char   user[CFG_NAME_MAX+1];
  time_t expires;
  int    persist;      /* se guarda en disco y sobrevive a reinicios */
  ukey_t key;          /* clave de sus carpetas cifradas (solo en memoria) */
} session_t;

static session_t g_sess[SESSION_MAX];
static pthread_mutex_t g_sess_lock = PTHREAD_MUTEX_INITIALIZER;


static void
token_hash(const char *token, char out[65]) {
  static const char hx[] = "0123456789abcdef";
  uint8_t d[32];
  SHA256_CTX c;
  sha256_init(&c);
  sha256_update(&c, (const uint8_t*)token, strlen(token));
  sha256_final(&c, d);
  for(int i=0; i<32; i++) {
    out[i*2] = hx[d[i] >> 4];
    out[i*2+1] = hx[d[i] & 15];
  }
  out[64] = 0;
}


/* Guarda las sesiones recordadas (con el lock de sesiones tomado). */
static void
sessions_save_locked(void) {
  char path[PATH_MAX], tmp[PATH_MAX + 8];
  time_t now = time(NULL);
  snprintf(path, sizeof(path), "%s/sessions.conf", cfg_dir());
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE *f = fopen(tmp, "w");
  if(!f) return;
  fprintf(f, "# Sesiones web recordadas (hash del token, usuario, caducidad)\n");
  for(int i=0; i<SESSION_MAX; i++) {
    if(g_sess[i].persist && g_sess[i].expires > now) {
      fprintf(f, "%s\t%s\t%lld\n", g_sess[i].thash, g_sess[i].user,
              (long long)g_sess[i].expires);
    }
  }
  fclose(f);
  rename(tmp, path);
  chmod(path, 0600);
}


static void
sessions_load(void) {
  char path[PATH_MAX], line[256];
  time_t now = time(NULL);
  int n = 0;
  snprintf(path, sizeof(path), "%s/sessions.conf", cfg_dir());
  FILE *f = fopen(path, "r");
  if(!f) return;
  pthread_mutex_lock(&g_sess_lock);
  while(n < SESSION_MAX && fgets(line, sizeof(line), f)) {
    char th[65], user[CFG_NAME_MAX+1];
    long long exp;
    if(line[0] == '#') continue;
    if(sscanf(line, "%64[0-9a-f]\t%48[^\t]\t%lld", th, user, &exp) != 3) continue;
    if(strlen(th) != 64 || exp <= now) continue;
    session_t *se = &g_sess[n++];
    memset(se, 0, sizeof(*se));
    memcpy(se->thash, th, sizeof(se->thash));
    snprintf(se->user, sizeof(se->user), "%s", user);
    se->expires = (time_t)exp;
    se->persist = 1;
  }
  pthread_mutex_unlock(&g_sess_lock);
  fclose(f);
  if(n) LOG_PRINTF("ps5share: %d sesión(es) recordada(s)\n", n);
}


static void
session_create(const char *user, const ukey_t *key, int persist, char *token_out) {
  time_t now = time(NULL);
  int slot = 0;

  cfg_random_hex(token_out, 32);
  pthread_mutex_lock(&g_sess_lock);
  for(int i=0; i<SESSION_MAX; i++) {
    if(g_sess[i].expires < now) { slot = i; break; }
    if(g_sess[i].expires < g_sess[slot].expires) slot = i;
  }
  int was_persist = g_sess[slot].persist;
  memset(&g_sess[slot], 0, sizeof(g_sess[slot]));
  token_hash(token_out, g_sess[slot].thash);
  snprintf(g_sess[slot].user, sizeof(g_sess[slot].user), "%s", user);
  g_sess[slot].expires = now + (persist ? SESSION_TTL_LONG : SESSION_TTL);
  g_sess[slot].persist = persist;
  if(key) memcpy(&g_sess[slot].key, key, sizeof(*key));
  if(persist || was_persist) sessions_save_locked();
  pthread_mutex_unlock(&g_sess_lock);
}


static int
session_lookup(const char *token, char *user_out, ukey_t *key_out) {
  time_t now = time(NULL);
  char th[65];
  int r = -1, idx = -1;
  if(strlen(token) != 64) return -1;
  token_hash(token, th);
  pthread_mutex_lock(&g_sess_lock);
  for(int i=0; i<SESSION_MAX; i++) {
    if(g_sess[i].expires >= now && cfg_consttime_eq(g_sess[i].thash, th)) {
      snprintf(user_out, CFG_NAME_MAX + 1, "%s", g_sess[i].user);
      memcpy(key_out, &g_sess[i].key, sizeof(*key_out));
      idx = i;
      r = 0;
      break;
    }
  }
  pthread_mutex_unlock(&g_sess_lock);

  /* Sesión sin clave (recordada tras un reinicio, o carpeta privada nueva):
     se abre con la contraseña guardada. */
  if(!r && !key_out->ok) {
    user_t u;
    if(!cfg_get_user(user_out, &u) && cfg_user_has_enc(&u)) {
      cfg_unlock_key_stored(user_out, key_out);
      if(key_out->ok) {
        pthread_mutex_lock(&g_sess_lock);
        if(cfg_consttime_eq(g_sess[idx].thash, th)) {
          memcpy(&g_sess[idx].key, key_out, sizeof(*key_out));
        }
        pthread_mutex_unlock(&g_sess_lock);
      }
    }
    memset(&u, 0, sizeof(u));
  }
  return r;
}


static void
session_set_key(const char *token, const ukey_t *key) {
  char th[65];
  token_hash(token, th);
  pthread_mutex_lock(&g_sess_lock);
  for(int i=0; i<SESSION_MAX; i++) {
    if(g_sess[i].thash[0] && cfg_consttime_eq(g_sess[i].thash, th)) {
      memcpy(&g_sess[i].key, key, sizeof(*key));
    }
  }
  pthread_mutex_unlock(&g_sess_lock);
}


static void
session_destroy(const char *token) {
  char th[65];
  int changed = 0;
  token_hash(token, th);
  pthread_mutex_lock(&g_sess_lock);
  for(int i=0; i<SESSION_MAX; i++) {
    if(g_sess[i].thash[0] && cfg_consttime_eq(g_sess[i].thash, th)) {
      changed |= g_sess[i].persist;
      crypt_key_wipe(&g_sess[i].key);
      memset(&g_sess[i], 0, sizeof(g_sess[i]));
    }
  }
  if(changed) sessions_save_locked();
  pthread_mutex_unlock(&g_sess_lock);
}


/* Cierra todas las sesiones de USER salvo la de KEEP_TOKEN (puede ser NULL). */
static void
session_destroy_user(const char *user, const char *keep_token) {
  char keep[65] = "";
  int changed = 0;
  if(keep_token && keep_token[0]) token_hash(keep_token, keep);
  pthread_mutex_lock(&g_sess_lock);
  for(int i=0; i<SESSION_MAX; i++) {
    if(!strcmp(g_sess[i].user, user) && !(keep[0] && !strcmp(g_sess[i].thash, keep))) {
      changed |= g_sess[i].persist;
      crypt_key_wipe(&g_sess[i].key);
      memset(&g_sess[i], 0, sizeof(g_sess[i]));
    }
  }
  if(changed) sessions_save_locked();
  pthread_mutex_unlock(&g_sess_lock);
}


typedef struct rl_slot {
  uint32_t ip;
  int      fails;
  time_t   first;
} rl_slot_t;

static rl_slot_t g_rl[RL_SLOTS];
static pthread_mutex_t g_rl_lock = PTHREAD_MUTEX_INITIALIZER;


int
rl_blocked(uint32_t ip) {
  time_t now = time(NULL);
  int blocked = 0;
  pthread_mutex_lock(&g_rl_lock);
  for(int i=0; i<RL_SLOTS; i++) {
    if(g_rl[i].ip == ip && now - g_rl[i].first < RL_WINDOW && g_rl[i].fails >= RL_MAX_FAILS) {
      blocked = 1;
    }
  }
  pthread_mutex_unlock(&g_rl_lock);
  return blocked;
}


void
rl_fail(uint32_t ip) {
  time_t now = time(NULL);
  int slot = -1, oldest = 0;
  pthread_mutex_lock(&g_rl_lock);
  for(int i=0; i<RL_SLOTS; i++) {
    if(g_rl[i].ip == ip) { slot = i; break; }
    if(g_rl[i].first < g_rl[oldest].first) oldest = i;
  }
  if(slot < 0 || now - g_rl[slot].first >= RL_WINDOW) {
    if(slot < 0) slot = oldest;
    g_rl[slot].ip = ip;
    g_rl[slot].fails = 0;
    g_rl[slot].first = now;
  }
  g_rl[slot].fails++;
  pthread_mutex_unlock(&g_rl_lock);
}


void
rl_clear(uint32_t ip) {
  pthread_mutex_lock(&g_rl_lock);
  for(int i=0; i<RL_SLOTS; i++) {
    if(g_rl[i].ip == ip) memset(&g_rl[i], 0, sizeof(g_rl[i]));
  }
  pthread_mutex_unlock(&g_rl_lock);
}


static int
login_reply(req_t *r, const char *user, const ukey_t *key, int remember) {
  char token[65];
  char cookie[256];
  sb_t b = {0};

  session_create(user, key, remember, token);
  if(remember) {
    snprintf(cookie, sizeof(cookie),
             "Set-Cookie: ps5s=%s; Path=/; HttpOnly; SameSite=Strict%s; Max-Age=%d\r\n",
             token, r->tls ? "; Secure" : "", SESSION_TTL_LONG);
  } else {
    /* Cookie de sesión: se borra al cerrar el navegador. */
    snprintf(cookie, sizeof(cookie),
             "Set-Cookie: ps5s=%s; Path=/; HttpOnly; SameSite=Strict%s\r\n", token,
             r->tls ? "; Secure" : "");
  }
  sb_puts(&b, "{\"ok\":true}");
  return send_json(r, 200, &b, cookie);
}


/* ------------------------------------------------------------------ */
/* Rutas públicas                                                      */
/* ------------------------------------------------------------------ */

static int
h_status(req_t *r) {
  sb_t b = {0};
  char ts[INET_ADDRSTRLEN] = "";
  cfg_lock();
  int setup = cfg_nusers() == 0;
  settings_t *st = cfg_settings();
  int rec_mail = st->recover_email && st->smtp_user[0] && st->smtp_passenc[0];
  int rec_admin = st->recover_admin;
  uint16_t sftp_port = st->sftp_enabled ? st->sftp_port : 0;
  uint16_t https_port = st->https_enabled ? st->https_port : 0;
  int vault_on = st->vault_enabled;
  cfg_unlock();
  tsip_get(ts, sizeof(ts));
  sb_printf(&b, "{\"name\":\"PS5NAS\",\"setup\":%s,\"recover_email\":%s,"
            "\"recover_admin\":%s,\"sftp_port\":%u,\"https_port\":%u,\"vault\":%s,"
            "\"secure\":%s,\"version\":",
            setup ? "true" : "false", rec_mail ? "true" : "false",
            rec_admin ? "true" : "false", sftp_port, https_port, vault_on ? "true" : "false",
            r->tls ? "true" : "false");
  sb_json_str(&b, VERSION_TAG);
  sb_puts(&b, ",\"tailscale_ip\":");
  sb_json_str(&b, ts);
  sb_puts(&b, "}");
  return send_json(r, 200, &b, NULL);
}


static int
h_setup(req_t *r) {
  char user[CFG_NAME_MAX+1], pass[256], err[256];
  user_t u;

  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "user", user, sizeof(user));
  get_param(r->body, "pass", pass, sizeof(pass));

  cfg_lock();
  int setup = cfg_nusers() == 0;
  cfg_unlock();
  if(!setup) return send_err(r, 403, "La configuración inicial ya se hizo");

  memset(&u, 0, sizeof(u));
  snprintf(u.name, sizeof(u.name), "%s", user);
  u.admin = 1;
  u.enabled = 1;
  u.can_chpass = 1;
  u.vault = 1;
  if(!pass[0]) return send_err(r, 400, "Falta la contraseña");
  if(cfg_upsert_user(&u, pass, err, sizeof(err))) return send_err(r, 400, err);
  LOG_PRINTF("ps5share: administrador inicial '%s' creado\n", user);
  vault_ensure(user, pass);
  return login_reply(r, user, NULL, 0);
}


static int
h_login(req_t *r) {
  char user[CFG_NAME_MAX+1], pass[256], rem[8];
  uint32_t ip = r->peer.sin_addr.s_addr;

  if(rl_blocked(ip)) {
    return send_err(r, 429, "Demasiados intentos. Espera unos minutos.");
  }
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "user", user, sizeof(user));
  get_param(r->body, "pass", pass, sizeof(pass));
  get_param(r->body, "remember", rem, sizeof(rem));

  if(cfg_authenticate(user, pass, NULL)) {
    rl_fail(ip);
    sleep(1);
    return send_err(r, 401, "Usuario o contraseña incorrectos");
  }
  rl_clear(ip);
  ukey_t key;
  cfg_unlock_key(user, pass, &key);
  {
    user_t lu;
    if(!cfg_get_user(user, &lu) && lu.vault && !lu.must_chpass && !vault_has_account(user)) {
      vault_ensure(user, pass);
    }
    memset(&lu, 0, sizeof(lu));
  }
  memset(pass, 0, sizeof(pass));
  int ret = login_reply(r, user, &key, !strcmp(rem, "1"));
  crypt_key_wipe(&key);
  return ret;
}


static int
h_logout(req_t *r) {
  if(r->cookie_token[0]) session_destroy(r->cookie_token);
  sb_t b = {0};
  sb_puts(&b, "{\"ok\":true}");
  return send_json(r, 200, &b,
                   "Set-Cookie: ps5s=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0\r\n");
}


static int
h_me(req_t *r) {
  sb_t b = {0};
  sb_puts(&b, "{\"user\":");
  sb_json_str(&b, r->user.name);
  sb_puts(&b, ",\"email\":");
  sb_json_str(&b, r->user.email);
  cfg_lock();
  int vault_on = cfg_settings()->vault_enabled;
  cfg_unlock();
  sb_printf(&b, ",\"vault\":%s", (vault_on && r->user.vault) ? "true" : "false");
  sb_printf(&b, ",\"admin\":%s,\"can_chpass\":%s,\"must_chpass\":%s,\"mounts\":[",
            r->user.admin ? "true" : "false",
            (r->user.can_chpass || r->user.must_chpass) ? "true" : "false",
            r->user.must_chpass ? "true" : "false");
  for(int i=0; i<r->user.nmounts; i++) {
    if(i) sb_puts(&b, ",");
    sb_puts(&b, "{\"name\":");
    sb_json_str(&b, r->user.mounts[i].name);
    sb_printf(&b, ",\"rw\":%s,\"enc\":%s,\"locked\":%s}",
              r->user.mounts[i].rw ? "true" : "false",
              r->user.mounts[i].enc ? "true" : "false",
              vfs_mount_usable(&r->user, &r->key, i) ? "false" : "true");
  }
  sb_puts(&b, "]}");
  return send_json(r, 200, &b, NULL);
}


static int
h_me_password(req_t *r) {
  char oldp[256], newp[256], err[256], email[CFG_EMAIL_MAX + 2];
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "old", oldp, sizeof(oldp));
  get_param(r->body, "new", newp, sizeof(newp));
  int set_email = !get_param(r->body, "email", email, sizeof(email));
  if(set_email && email[0] && !cfg_valid_email(email)) {
    return send_err(r, 400, "El correo de recuperación no es válido");
  }
  int ret = cfg_change_own_password(r->user.name, oldp, newp, err, sizeof(err));
  if(!ret && set_email) cfg_set_email(r->user.name, email, err, sizeof(err));
  if(!ret && !r->key.ok) {
    /* Tras el primer cambio ya puede abrir (o crear) su clave. */
    ukey_t key;
    cfg_unlock_key(r->user.name, newp, &key);
    if(key.ok) session_set_key(r->cookie_token, &key);
    crypt_key_wipe(&key);
  }
  if(!ret && r->user.vault) vault_password_changed(r->user.name, newp);
  memset(oldp, 0, sizeof(oldp));
  memset(newp, 0, sizeof(newp));
  if(ret) return send_err(r, 400, err);
  LOG_PRINTF("ps5share: '%s' cambió su contraseña\n", r->user.name);
  return send_ok(r);
}


static int
h_me_email(req_t *r) {
  char pass[256], email[CFG_EMAIL_MAX + 2], err[256];
  uint32_t ip = r->peer.sin_addr.s_addr;
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  if(rl_blocked(ip)) return send_err(r, 429, "Demasiados intentos. Espera unos minutos.");
  get_param(r->body, "pass", pass, sizeof(pass));
  get_param(r->body, "email", email, sizeof(email));
  if(cfg_authenticate(r->user.name, pass, NULL)) {
    rl_fail(ip);
    memset(pass, 0, sizeof(pass));
    return send_err(r, 403, "La contraseña no es correcta");
  }
  memset(pass, 0, sizeof(pass));
  if(cfg_set_email(r->user.name, email, err, sizeof(err))) return send_err(r, 400, err);
  return send_ok(r);
}


/* ------------------------------------------------------------------ */
/* Recuperación de contraseña                                          */
/* ------------------------------------------------------------------ */

#define RECOV_MAX      32
#define RECOV_TTL      (24 * 3600)
#define RECOV_COOLDOWN 120     /* segundos entre correos al mismo usuario */

typedef struct recov {
  char     id[17];               /* identificador para el administrador */
  char     thash[65];            /* hash del token que guarda el navegador */
  char     user[CFG_NAME_MAX+1];
  char     ip[INET_ADDRSTRLEN];
  time_t   created;
  int      state;                /* 0 pendiente, 1 aceptada, 2 rechazada */
} recov_t;

static recov_t g_recov[RECOV_MAX];
static struct { char user[CFG_NAME_MAX+1]; time_t when; } g_mailed[RECOV_MAX];
static pthread_mutex_t g_recov_lock = PTHREAD_MUTEX_INITIALIZER;


typedef struct mailjob {
  char to[CFG_EMAIL_MAX+1];
  char user[CFG_NAME_MAX+1];
  char pass[CRYPT_SEAL_MAX+1];
} mailjob_t;


static void*
mail_thread(void *p) {
  mailjob_t *j = p;
  char body[1024], err[256];
  snprintf(body, sizeof(body),
           "Hola, %s:\n\n"
           "Alguien (seguramente tú) ha pedido recuperar la contraseña de tu cuenta de PS5NAS.\n\n"
           "Usuario: %s\n"
           "Contraseña: %s\n\n"
           "Úsala para entrar por SFTP o desde la web. Si puedes, cámbiala después desde la web "
           "(botón «Mi cuenta»).\n\n"
           "Si no lo has pedido tú, avisa al administrador de la consola.\n\n"
           "-- PS5NAS\n", j->user, j->user, j->pass);
  if(!smtp_send(j->to, "PS5NAS: tu contraseña", body, err, sizeof(err))) {
    LOG_PRINTF("ps5share: enviado el correo de recuperación de '%s'\n", j->user);
  }
  memset(body, 0, sizeof(body));
  memset(j, 0, sizeof(*j));
  free(j);
  return NULL;
}


static int
h_forgot_email(req_t *r) {
  char user[CFG_NAME_MAX+1], email[CFG_EMAIL_MAX + 2];
  uint32_t ip = r->peer.sin_addr.s_addr;
  user_t u;
  int recover;

  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  if(rl_blocked(ip)) return send_err(r, 429, "Demasiados intentos. Espera unos minutos.");
  get_param(r->body, "user", user, sizeof(user));
  get_param(r->body, "email", email, sizeof(email));
  cfg_lock();
  recover = cfg_settings()->recover_email;
  cfg_unlock();
  if(!recover) return send_err(r, 403, "La recuperación por correo está desactivada");
  rl_fail(ip);    /* cuenta como intento: limita los envíos por IP */

  if(!cfg_get_user(user, &u) && u.enabled && u.email[0] && !strcasecmp(u.email, email)) {
    time_t now = time(NULL);
    int slot = 0, recent = 0;
    pthread_mutex_lock(&g_recov_lock);
    for(int i=0; i<RECOV_MAX; i++) {
      if(!strcmp(g_mailed[i].user, user)) {
        slot = i;
        recent = now - g_mailed[i].when < RECOV_COOLDOWN;
        break;
      }
      if(g_mailed[i].when < g_mailed[slot].when) slot = i;
    }
    if(!recent) {
      snprintf(g_mailed[slot].user, sizeof(g_mailed[slot].user), "%s", user);
      g_mailed[slot].when = now;
    }
    pthread_mutex_unlock(&g_recov_lock);

    mailjob_t *j = recent ? NULL : calloc(1, sizeof(*j));
    if(j && !cfg_get_password(user, j->pass, sizeof(j->pass))) {
      snprintf(j->to, sizeof(j->to), "%s", u.email);
      snprintf(j->user, sizeof(j->user), "%s", u.name);
      pthread_t t;
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      pthread_attr_setstacksize(&attr, 512 * 1024);
      if(pthread_create(&t, &attr, mail_thread, j)) free(j);
      pthread_attr_destroy(&attr);
    } else if(j) {
      LOG_PRINTF("ps5share: '%s' pidió su contraseña, pero aún no se conoce\n", user);
      free(j);
    }
  }
  memset(&u, 0, sizeof(u));
  /* Misma respuesta siempre: no revela qué usuarios o correos existen. */
  sb_t b = {0};
  sb_puts(&b, "{\"ok\":true}");
  return send_json(r, 200, &b, NULL);
}


static int
h_forgot_request(req_t *r) {
  char user[CFG_NAME_MAX+1], token[65];
  uint32_t ip = r->peer.sin_addr.s_addr;
  int recover;
  time_t now = time(NULL);

  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  if(rl_blocked(ip)) return send_err(r, 429, "Demasiadas solicitudes. Espera unos minutos.");
  get_param(r->body, "user", user, sizeof(user));
  cfg_lock();
  recover = cfg_settings()->recover_admin;
  cfg_unlock();
  if(!recover) return send_err(r, 403, "Pedir la contraseña al administrador está desactivado");
  if(!cfg_valid_username(user)) return send_err(r, 400, "Usuario no válido");
  rl_fail(ip);

  cfg_random_hex(token, 32);
  pthread_mutex_lock(&g_recov_lock);
  int slot = -1, oldest = 0;
  for(int i=0; i<RECOV_MAX; i++) {
    /* Una solicitud pendiente por usuario: la nueva sustituye a la anterior. */
    if(g_recov[i].created && !strcmp(g_recov[i].user, user) && g_recov[i].state == 0) {
      slot = i;
      break;
    }
    if(!g_recov[i].created || now - g_recov[i].created > RECOV_TTL) {
      if(slot < 0) slot = i;
    }
    if(g_recov[i].created < g_recov[oldest].created) oldest = i;
  }
  if(slot < 0) slot = oldest;
  recov_t *q = &g_recov[slot];
  memset(q, 0, sizeof(*q));
  cfg_random_hex(q->id, 8);
  token_hash(token, q->thash);
  snprintf(q->user, sizeof(q->user), "%s", user);
  inet_ntop(AF_INET, &r->peer.sin_addr, q->ip, sizeof(q->ip));
  q->created = now;
  pthread_mutex_unlock(&g_recov_lock);

  user_t u;
  if(!cfg_get_user(user, &u)) {
    notify("PS5NAS: %s pide recuperar su contraseña. Acéptalo en Usuarios.", user);
    LOG_PRINTF("ps5share: '%s' pide recuperar su contraseña (desde %s)\n", user, q->ip);
  }
  memset(&u, 0, sizeof(u));

  sb_t b = {0};
  sb_puts(&b, "{\"token\":");
  sb_json_str(&b, token);
  sb_puts(&b, "}");
  return send_json(r, 200, &b, NULL);
}


static int
h_forgot_status(req_t *r) {
  char token[80], th[65], user[CFG_NAME_MAX+1] = "";
  int state = -1;
  time_t now = time(NULL);

  get_param(r->query, "token", token, sizeof(token));
  if(strlen(token) != 64) return send_err(r, 400, "Solicitud no válida");
  token_hash(token, th);
  pthread_mutex_lock(&g_recov_lock);
  for(int i=0; i<RECOV_MAX; i++) {
    recov_t *q = &g_recov[i];
    if(q->created && now - q->created <= RECOV_TTL && cfg_consttime_eq(q->thash, th)) {
      state = q->state;
      snprintf(user, sizeof(user), "%s", q->user);
      if(state != 0) memset(q, 0, sizeof(*q));   /* la respuesta se entrega una vez */
      break;
    }
  }
  pthread_mutex_unlock(&g_recov_lock);

  sb_t b = {0};
  if(state == 1) {
    char pass[CRYPT_SEAL_MAX + 1];
    if(cfg_get_password(user, pass, sizeof(pass))) {
      sb_puts(&b, "{\"state\":\"denied\"}");
    } else {
      sb_puts(&b, "{\"state\":\"approved\",\"user\":");
      sb_json_str(&b, user);
      sb_puts(&b, ",\"password\":");
      sb_json_str(&b, pass);
      sb_puts(&b, "}");
    }
    memset(pass, 0, sizeof(pass));
  } else {
    sb_puts(&b, state == 0 ? "{\"state\":\"pending\"}" :
                state == 2 ? "{\"state\":\"denied\"}" : "{\"state\":\"unknown\"}");
  }
  int ret = send_json(r, 200, &b, NULL);
  return ret;
}


/* ------------------------------------------------------------------ */
/* API de archivos                                                     */
/* ------------------------------------------------------------------ */

static int
lookup_param(req_t *r, const char *src, const char *name, vfs_res_t *res) {
  char v[PATH_MAX];
  if(get_param(src, name, v, sizeof(v))) {
    errno = EINVAL;
    return -1;
  }
  return vfs_lookup(&r->user, &r->key, "/", v, res);
}


static int
h_fs_list(req_t *r) {
  vfs_res_t res;
  struct stat st;
  sb_t b = {0};

  if(lookup_param(r, r->query, "path", &res)) return send_errno(r);

  sb_puts(&b, "{\"path\":");
  sb_json_str(&b, res.vpath);

  if(res.mount < 0) {
    sb_puts(&b, ",\"rw\":false,\"root\":true,\"entries\":[");
    for(int i=0; i<r->user.nmounts; i++) {
      const mount_t *m = &r->user.mounts[i];
      int ok = !stat(m->path, &st) && S_ISDIR(st.st_mode);
      if(i) sb_puts(&b, ",");
      sb_puts(&b, "{\"name\":");
      sb_json_str(&b, m->name);
      sb_printf(&b, ",\"dir\":true,\"size\":0,\"mtime\":%lld,\"rw\":%s,\"missing\":%s,"
                "\"enc\":%s,\"locked\":%s}",
                ok ? (long long)st.st_mtime : 0LL, m->rw ? "true" : "false",
                ok ? "false" : "true", m->enc ? "true" : "false",
                vfs_mount_usable(&r->user, &r->key, i) ? "false" : "true");
    }
    sb_puts(&b, "]}");
    return send_json(r, 200, &b, NULL);
  }

  DIR *d = opendir(res.real);
  if(!d) {
    free(b.p);
    return send_errno(r);
  }
  sb_printf(&b, ",\"rw\":%s,\"enc\":%s,\"root\":false,\"entries\":[",
            res.rw ? "true" : "false", res.enc ? "true" : "false");

  struct dirent *e;
  char full[PATH_MAX * 2], name[NAME_MAX + 1];
  int first = 1;
  while((e = readdir(d))) {
    if(vfs_entry_name(&res, e->d_name, name, sizeof(name))) continue;
    snprintf(full, sizeof(full), "%s/%s", res.real, e->d_name);
    if(lstat(full, &st) || S_ISLNK(st.st_mode)) continue;
    if(!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) continue;
    vfs_fix_size(&res, &st);
    if(!first) sb_puts(&b, ",");
    first = 0;
    sb_puts(&b, "{\"name\":");
    sb_json_str(&b, name);
    sb_printf(&b, ",\"dir\":%s,\"size\":%" PRIu64 ",\"mtime\":%lld}",
              S_ISDIR(st.st_mode) ? "true" : "false", (uint64_t)st.st_size,
              (long long)st.st_mtime);
  }
  closedir(d);
  sb_puts(&b, "]}");
  return send_json(r, 200, &b, NULL);
}


static const char *
mime_inline(const char *name) {
  static const struct { const char *ext, *type; } t[] = {
    {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"}, {".png", "image/png"},
    {".gif", "image/gif"}, {".webp", "image/webp"}, {".bmp", "image/bmp"},
    {".mp4", "video/mp4"}, {".m4v", "video/mp4"}, {".webm", "video/webm"},
    {".mkv", "video/x-matroska"}, {".mov", "video/quicktime"},
    {".mp3", "audio/mpeg"}, {".m4a", "audio/mp4"}, {".ogg", "audio/ogg"},
    {".flac", "audio/flac"}, {".wav", "audio/wav"},
    {".txt", "text/plain; charset=utf-8"}, {".log", "text/plain; charset=utf-8"},
    {".md", "text/plain; charset=utf-8"}, {".json", "text/plain; charset=utf-8"},
    {".pdf", "application/pdf"},
  };
  const char *dot = strrchr(name, '.');
  if(!dot) return NULL;
  for(size_t i=0; i<sizeof(t)/sizeof(t[0]); i++) {
    if(!strcasecmp(dot, t[i].ext)) return t[i].type;
  }
  return NULL;
}


static void
content_disposition(char *out, size_t outlen, const char *kind, const char *name) {
  /* RFC 5987: filename*=UTF-8''nombre%20codificado */
  size_t o = snprintf(out, outlen, "Content-Disposition: %s; filename*=UTF-8''", kind);
  for(const unsigned char *p = (const unsigned char*)name; *p && o + 4 < outlen; p++) {
    if((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
       *p == '.' || *p == '-' || *p == '_') {
      out[o++] = (char)*p;
    } else {
      o += snprintf(out + o, outlen - o, "%%%02X", *p);
    }
  }
  snprintf(out + o, outlen - o, "\r\n");
}


static int
h_fs_get(req_t *r) {
  vfs_res_t res;
  struct stat st;
  char extra[1536], disp[1024], dl[8];
  vfile_t vf;

  if(lookup_param(r, r->query, "path", &res)) return send_errno(r);
  if(res.mount < 0 || res.is_mount_root) return send_err(r, 400, "No es un archivo");
  if(stat(res.real, &st) || !S_ISREG(st.st_mode)) {
    if(errno == ENOENT) return send_errno(r);
    return send_err(r, 400, "No es un archivo");
  }
  if(vf_open(&vf, &res, O_RDONLY)) return send_errno(r);
  st.st_size = vf_size(&vf);

  const char *name = strrchr(res.vpath, '/');
  name = name ? name + 1 : res.vpath;
  get_param(r->query, "dl", dl, sizeof(dl));
  const char *mt = mime_inline(name);
  int inline_ok = mt && !dl[0];
  content_disposition(disp, sizeof(disp), inline_ok ? "inline" : "attachment", name);

  long long size = (long long)st.st_size;
  long long start = 0, end = size - 1;
  int code = 200;

  if(r->range[0] && !strncmp(r->range, "bytes=", 6) && !strchr(r->range, ',')) {
    const char *spec = r->range + 6;
    char *dash = strchr(spec, '-');
    if(dash) {
      if(spec == dash) {                         /* bytes=-N */
        long long n = atoll(dash + 1);
        start = n >= size ? 0 : size - n;
      } else {
        start = atoll(spec);
        if(dash[1]) end = atoll(dash + 1);
      }
      if(end >= size) end = size - 1;
      if(start > end || start >= size) {
        vf_close(&vf);
        snprintf(extra, sizeof(extra), "Content-Range: bytes */%lld\r\n", size);
        return send_body(r, 416, "text/plain", "", 0, extra);
      }
      code = 206;
    }
  }

  long long len = size ? end - start + 1 : 0;
  int n = snprintf(extra, sizeof(extra),
                   "%sAccept-Ranges: bytes\r\n"
                   "Content-Security-Policy: sandbox; default-src 'none'; img-src 'self'; media-src 'self'\r\n",
                   disp);
  if(code == 206) {
    snprintf(extra + n, sizeof(extra) - n, "Content-Range: bytes %lld-%lld/%lld\r\n",
             start, end, size);
  }

  if(send_head(r, code, inline_ok ? mt : "application/octet-stream", len, extra) ||
     !strcmp(r->method, "HEAD")) {
    vf_close(&vf);
    return 0;
  }

  void *buf = malloc(IO_BUFSIZE);
  if(buf) {
    off_t pos = start;
    long long left = len;
    while(left > 0) {
      size_t want = left < IO_BUFSIZE ? (size_t)left : IO_BUFSIZE;
      ssize_t n = vf_pread(&vf, buf, want, pos);
      if(n <= 0 || req_write(r, buf, (size_t)n)) break;
      pos += n;
      left -= n;
    }
    free(buf);
  }
  vf_close(&vf);
  return 0;
}


static int
h_fs_put(req_t *r) {
  vfs_res_t res;
  char part[PATH_MAX + 32];

  if(lookup_param(r, r->query, "path", &res)) return send_errno(r);
  if(res.mount < 0 || res.is_mount_root || !res.rw) return send_err(r, 403, "Permiso denegado");
  if(r->chunked || r->content_length < 0) return send_err(r, 411, "Falta Content-Length");

  struct stat st;
  if(!stat(res.real, &st) && S_ISDIR(st.st_mode)) {
    return send_err(r, 409, "Ya existe una carpeta con ese nombre");
  }

  /* Se escribe en un temporal y se renombra al terminar.  En una carpeta
     cifrada el temporal también va cifrado (y su nombre no es visible). */
  vfs_res_t pres = res;
  vfile_t vf;
  snprintf(part, sizeof(part), "%s.ps5share-part", res.real);
  if(strlen(part) >= sizeof(pres.real)) {
    errno = ENAMETOOLONG;
    return send_errno(r);
  }
  memcpy(pres.real, part, strlen(part) + 1);
  if(vf_open(&vf, &pres, O_WRONLY | O_CREAT | O_TRUNC)) return send_errno(r);

  void *buf = malloc(IO_BUFSIZE);
  if(!buf) {
    vf_close(&vf);
    unlink(part);
    return send_err(r, 500, "Sin memoria");
  }

  long long remaining = r->content_length;
  off_t pos = 0;
  int err = 0;

  size_t have = r->hdr_len - r->body_start;
  if(have > (size_t)remaining) have = (size_t)remaining;
  if(have) {
    if(vf_pwrite(&vf, r->hdr + r->body_start, have, 0) != (ssize_t)have) err = errno ? errno : EIO;
    pos += (off_t)have;
  }
  remaining -= (long long)have;

  io_sock_timeouts(r->fd, 300);
  while(!err && remaining > 0) {
    size_t want = remaining < IO_BUFSIZE ? (size_t)remaining : IO_BUFSIZE;
    errno = 0;
    ssize_t n = req_recv(r, buf, want);
    if(n <= 0) { err = (n == 0 || !errno) ? EPIPE : errno; break; }
    if(vf_pwrite(&vf, buf, (size_t)n, pos) != n) { err = errno ? errno : EIO; break; }
    pos += n;
    remaining -= n;
  }
  free(buf);

  if(vf_close(&vf) && !err) err = errno;
  if(err) {
    unlink(part);
    errno = err;
    return send_errno(r);
  }
  if(rename(part, res.real)) {
    int e = errno;
    unlink(part);
    errno = e;
    return send_errno(r);
  }
  return send_ok(r);
}


static int
h_fs_mkdir(req_t *r) {
  vfs_res_t res;
  if(lookup_param(r, r->query, "path", &res)) return send_errno(r);
  if(res.mount < 0 || res.is_mount_root || !res.rw) return send_err(r, 403, "Permiso denegado");
  if(mkdir(res.real, 0777)) return send_errno(r);
  return send_ok(r);
}


static int
rm_rf(const char *path, int depth) {
  struct stat st;
  if(depth > 64) {
    errno = ELOOP;
    return -1;
  }
  if(lstat(path, &st)) return -1;
  if(!S_ISDIR(st.st_mode)) return unlink(path);

  DIR *d = opendir(path);
  if(!d) return -1;
  struct dirent *e;
  char *child = malloc(PATH_MAX);
  int ret = 0;
  if(!child) {
    closedir(d);
    return -1;
  }
  while((e = readdir(d))) {
    if(!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
    snprintf(child, PATH_MAX, "%s/%s", path, e->d_name);
    if(rm_rf(child, depth + 1)) { ret = -1; break; }
  }
  free(child);
  closedir(d);
  if(ret) return -1;
  return rmdir(path);
}


static int
h_fs_delete(req_t *r) {
  vfs_res_t res;
  if(lookup_param(r, r->query, "path", &res)) return send_errno(r);
  if(res.mount < 0 || res.is_mount_root || !res.rw) return send_err(r, 403, "Permiso denegado");
  if(rm_rf(res.real, 0)) return send_errno(r);
  return send_ok(r);
}


static int
h_fs_rename(req_t *r) {
  vfs_res_t from, to;
  struct stat st;
  if(lookup_param(r, r->query, "from", &from)) return send_errno(r);
  if(lookup_param(r, r->query, "to", &to)) return send_errno(r);
  if(from.mount < 0 || from.is_mount_root || !from.rw ||
     to.mount < 0 || to.is_mount_root || !to.rw || from.mount != to.mount) {
    return send_err(r, 403, "Permiso denegado");
  }
  if(!lstat(to.real, &st)) return send_err(r, 409, "Ya existe un elemento con ese nombre");
  if(rename(from.real, to.real)) return send_errno(r);
  return send_ok(r);
}


/* ------------------------------------------------------------------ */
/* API de administración                                               */
/* ------------------------------------------------------------------ */

static int
h_admin_users(req_t *r) {
  sb_t b = {0};
  char vdir[PATH_MAX];
  cfg_vault_dir(vdir, sizeof(vdir));
  sb_puts(&b, "{\"users\":[");
  cfg_lock();
  for(int i=0; i<cfg_nusers(); i++) {
    user_t *u = cfg_user_at(i);
    if(i) sb_puts(&b, ",");
    sb_puts(&b, "{\"name\":");
    sb_json_str(&b, u->name);
    sb_puts(&b, ",\"email\":");
    sb_json_str(&b, u->email);
    sb_printf(&b, ",\"admin\":%s,\"enabled\":%s,\"can_chpass\":%s,\"must_chpass\":%s,"
              "\"has_key\":%s,\"pw_known\":%s,\"vault\":%s,\"vault_ready\":%s,\"mounts\":[",
              u->admin ? "true" : "false", u->enabled ? "true" : "false",
              u->can_chpass ? "true" : "false", u->must_chpass ? "true" : "false",
              u->kwrap[0] ? "true" : "false", u->pwenc[0] ? "true" : "false",
              u->vault ? "true" : "false", vault_has_account_in(vdir, u->name) ? "true" : "false");
    for(int j=0; j<u->nmounts; j++) {
      if(j) sb_puts(&b, ",");
      sb_puts(&b, "{\"name\":");
      sb_json_str(&b, u->mounts[j].name);
      sb_puts(&b, ",\"path\":");
      sb_json_str(&b, u->mounts[j].path);
      sb_printf(&b, ",\"rw\":%s,\"enc\":%s}", u->mounts[j].rw ? "true" : "false",
                u->mounts[j].enc ? "true" : "false");
    }
    sb_puts(&b, "]}");
  }
  cfg_unlock();
  sb_puts(&b, "]}");
  return send_json(r, 200, &b, NULL);
}


/* mounts: una por línea, "rw|Nombre|/ruta/real" o "ro|Nombre|/ruta" */
static int
parse_mounts(const char *src, user_t *u, char *err, size_t errlen) {
  const char *p = src;
  u->nmounts = 0;
  while(*p) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    char line[PATH_MAX + 128];
    if(len >= sizeof(line)) {
      snprintf(err, errlen, "Línea de carpeta demasiado larga");
      return -1;
    }
    memcpy(line, p, len);
    line[len] = 0;
    if(len && line[len-1] == '\r') line[--len] = 0;

    if(len) {
      char *a = strchr(line, '|');
      char *bb = a ? strchr(a + 1, '|') : NULL;
      if(!a || !bb) {
        snprintf(err, errlen, "Formato de carpeta no válido");
        return -1;
      }
      *a = 0;
      *bb = 0;
      if(u->nmounts >= CFG_MAX_MOUNTS) {
        snprintf(err, errlen, "Máximo %d carpetas por usuario", CFG_MAX_MOUNTS);
        return -1;
      }
      mount_t *m = &u->mounts[u->nmounts++];
      m->enc = !strcmp(line, "enc");
      m->rw = m->enc || !strcmp(line, "rw");
      snprintf(m->name, sizeof(m->name), "%s", a + 1);
      snprintf(m->path, sizeof(m->path), "%s", bb + 1);
    }
    if(!nl) break;
    p = nl + 1;
  }
  return 0;
}


static int
h_admin_user_save(req_t *r) {
  user_t u;
  char pass[256], tmp[16], err[512];
  char *mounts;

  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  memset(&u, 0, sizeof(u));
  get_param(r->body, "name", u.name, sizeof(u.name));
  get_param(r->body, "password", pass, sizeof(pass));
  get_param(r->body, "admin", tmp, sizeof(tmp));
  u.admin = !strcmp(tmp, "1");
  get_param(r->body, "enabled", tmp, sizeof(tmp));
  u.enabled = !strcmp(tmp, "1");
  get_param(r->body, "can_chpass", tmp, sizeof(tmp));
  u.can_chpass = !strcmp(tmp, "1");
  get_param(r->body, "must_chpass", tmp, sizeof(tmp));
  u.must_chpass = !strcmp(tmp, "1");
  get_param(r->body, "vault", tmp, sizeof(tmp));
  u.vault = !strcmp(tmp, "1");
  {
    char em[CFG_EMAIL_MAX + 2];
    get_param(r->body, "email", em, sizeof(em));
    if(strlen(em) > CFG_EMAIL_MAX) return send_err(r, 400, "Correo demasiado largo");
    memcpy(u.email, em, strlen(em) + 1);
  }

  if(!(mounts = malloc(HTTP_BODY_MAX))) return send_err(r, 500, "Sin memoria");
  get_param(r->body, "mounts", mounts, HTTP_BODY_MAX);
  int pr = parse_mounts(mounts, &u, err, sizeof(err));
  free(mounts);
  if(pr) return send_err(r, 400, err);

  if(!strcmp(u.name, r->user.name) && (!u.admin || !u.enabled)) {
    return send_err(r, 400, "No puedes quitarte a ti mismo el rol de administrador");
  }
  if(cfg_upsert_user(&u, pass, err, sizeof(err))) return send_err(r, 400, err);
  /* Desactivado o con contraseña nueva: sus sesiones dejan de valer. */
  if(!u.enabled || pass[0]) session_destroy_user(u.name, NULL);
  /* Gestor de contraseñas: se crea o se vuelve a proteger con la nueva. */
  if(u.vault) {
    if(pass[0]) vault_password_changed(u.name, pass);
    else vault_ensure_stored(u.name);
  }
  memset(pass, 0, sizeof(pass));
  LOG_PRINTF("ps5share: '%s' guardó el usuario '%s'\n", r->user.name, u.name);
  return send_ok(r);
}


static int
h_admin_user_delete(req_t *r) {
  char name[CFG_NAME_MAX+1], err[256];
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "name", name, sizeof(name));
  if(!strcmp(name, r->user.name)) return send_err(r, 400, "No puedes borrarte a ti mismo");
  if(cfg_delete_user(name, err, sizeof(err))) return send_err(r, 400, err);
  session_destroy_user(name, NULL);
  vault_user_deleted(name);
  LOG_PRINTF("ps5share: '%s' borró el usuario '%s'\n", r->user.name, name);
  return send_ok(r);
}


/* ------------------------------------------------------------------ */
/* Accesos directos a otras webs de la consola (pestaña «Apps»)        */
/* ------------------------------------------------------------------ */

static int
h_links(req_t *r) {
  link_t *ls = calloc(CFG_MAX_LINKS, sizeof(link_t));
  if(!ls) return send_err(r, 500, "Sin memoria");
  int n = cfg_links(ls, CFG_MAX_LINKS, &r->user);
  sb_t b = {0};
  sb_puts(&b, "{\"links\":[");
  for(int i=0; i<n; i++) {
    if(i) sb_puts(&b, ",");
    sb_puts(&b, "{\"id\":");
    sb_json_str(&b, ls[i].id);
    sb_puts(&b, ",\"name\":");
    sb_json_str(&b, ls[i].name);
    sb_puts(&b, ",\"target\":");
    sb_json_str(&b, ls[i].target);
    if(r->user.admin) {
      /* Solo el administrador ve a quién se muestra cada acceso. */
      sb_printf(&b, ",\"all\":%s,\"users\":[", ls[i].all ? "true" : "false");
      for(int j=0; j<ls[i].nusers; j++) {
        if(j) sb_puts(&b, ",");
        sb_json_str(&b, ls[i].users[j]);
      }
      sb_puts(&b, "]");
    }
    sb_puts(&b, "}");
  }
  sb_puts(&b, "]}");
  free(ls);
  return send_json(r, 200, &b, NULL);
}


static int
h_admin_link(req_t *r) {
  char tmp[16], err[256];
  char *users = malloc(CFG_MAX_USERS * (CFG_NAME_MAX + 2) + 1);
  link_t *l = calloc(1, sizeof(*l));
  int ret;
  if(!users || !l) {
    free(users);
    free(l);
    return send_err(r, 500, "Sin memoria");
  }
  if(read_body(r)) {
    ret = send_err(r, 400, "Petición no válida");
    goto out;
  }
  get_param(r->body, "id", l->id, sizeof(l->id));
  if(get_param(r->body, "name", l->name, sizeof(l->name)) ||
     get_param(r->body, "target", l->target, sizeof(l->target))) {
    ret = send_err(r, 400, "Faltan el nombre o el destino (o son demasiado largos)");
    goto out;
  }
  get_param(r->body, "all", tmp, sizeof(tmp));
  l->all = !strcmp(tmp, "1");
  users[0] = 0;
  get_param(r->body, "users", users, CFG_MAX_USERS * (CFG_NAME_MAX + 2) + 1);
  for(char *save = NULL, *t = strtok_r(users, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
    if(!*t) continue;
    if(l->nusers >= CFG_MAX_USERS || strlen(t) > CFG_NAME_MAX) {
      ret = send_err(r, 400, "Lista de usuarios no válida");
      goto out;
    }
    int dup = 0;
    for(int j=0; j<l->nusers; j++) dup |= !strcmp(l->users[j], t);
    if(!dup) snprintf(l->users[l->nusers++], CFG_NAME_MAX + 1, "%s", t);
  }
  if(cfg_link_save(l, err, sizeof(err))) {
    ret = send_err(r, 400, err);
    goto out;
  }
  {
    sb_t b = {0};
    sb_puts(&b, "{\"ok\":true,\"id\":");
    sb_json_str(&b, l->id);
    sb_puts(&b, "}");
    ret = send_json(r, 200, &b, NULL);
  }
 out:
  free(users);
  free(l);
  return ret;
}


static int
h_admin_link_delete(req_t *r) {
  char id[32], err[256];
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "id", id, sizeof(id));
  if(cfg_link_delete(id, err, sizeof(err))) return send_err(r, 400, err);
  return send_ok(r);
}


/* Muestra la contraseña de un usuario (ojo del panel de administración). */
static int
h_admin_user_password(req_t *r) {
  char name[CFG_NAME_MAX+1], pass[CRYPT_SEAL_MAX + 1];
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "name", name, sizeof(name));
  if(cfg_get_password(name, pass, sizeof(pass))) {
    return send_err(r, 404, "Aún no se conoce: se guardará la próxima vez que inicie sesión "
                    "(o ponle tú una nueva)");
  }
  sb_t b = {0};
  sb_puts(&b, "{\"password\":");
  sb_json_str(&b, pass);
  sb_puts(&b, "}");
  memset(pass, 0, sizeof(pass));
  LOG_PRINTF("ps5share: '%s' consultó la contraseña de '%s'\n", r->user.name, name);
  int ret = send_json(r, 200, &b, NULL);
  return ret;
}


static int
h_admin_requests(req_t *r) {
  sb_t b = {0};
  time_t now = time(NULL);
  int first = 1;
  sb_puts(&b, "{\"requests\":[");
  pthread_mutex_lock(&g_recov_lock);
  for(int i=0; i<RECOV_MAX; i++) {
    recov_t *q = &g_recov[i];
    if(!q->created || q->state != 0 || now - q->created > RECOV_TTL) continue;
    user_t u;
    if(cfg_get_user(q->user, &u)) continue;    /* usuarios que no existen: se ignoran */
    if(!first) sb_puts(&b, ",");
    first = 0;
    sb_puts(&b, "{\"id\":");
    sb_json_str(&b, q->id);
    sb_puts(&b, ",\"user\":");
    sb_json_str(&b, q->user);
    sb_puts(&b, ",\"ip\":");
    sb_json_str(&b, q->ip);
    sb_printf(&b, ",\"created\":%lld,\"pw_known\":%s}", (long long)q->created,
              u.pwenc[0] ? "true" : "false");
    memset(&u, 0, sizeof(u));
  }
  pthread_mutex_unlock(&g_recov_lock);
  sb_puts(&b, "]}");
  return send_json(r, 200, &b, NULL);
}


static int
h_admin_request_decide(req_t *r) {
  char id[32], action[16], user[CFG_NAME_MAX+1] = "";
  int found = 0;
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "id", id, sizeof(id));
  get_param(r->body, "action", action, sizeof(action));
  int approve = !strcmp(action, "approve");
  if(!approve && strcmp(action, "deny")) return send_err(r, 400, "Acción no válida");

  pthread_mutex_lock(&g_recov_lock);
  for(int i=0; i<RECOV_MAX; i++) {
    recov_t *q = &g_recov[i];
    if(q->created && q->state == 0 && !strcmp(q->id, id)) {
      snprintf(user, sizeof(user), "%s", q->user);
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&g_recov_lock);
  if(!found) return send_err(r, 404, "La solicitud ya no existe");

  if(approve) {
    char pass[CRYPT_SEAL_MAX + 1];
    int known = !cfg_get_password(user, pass, sizeof(pass));
    memset(pass, 0, sizeof(pass));
    if(!known) {
      return send_err(r, 409, "No se conoce su contraseña: ponle una nueva en su ficha y "
                      "vuelve a aceptar la solicitud");
    }
  }
  pthread_mutex_lock(&g_recov_lock);
  for(int i=0; i<RECOV_MAX; i++) {
    if(g_recov[i].created && !strcmp(g_recov[i].id, id)) g_recov[i].state = approve ? 1 : 2;
  }
  pthread_mutex_unlock(&g_recov_lock);
  LOG_PRINTF("ps5share: '%s' %s la recuperación de '%s'\n", r->user.name,
             approve ? "aceptó" : "rechazó", user);
  return send_ok(r);
}


static int
h_admin_mail_test(req_t *r) {
  char to[CFG_EMAIL_MAX + 2], err[512];
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "to", to, sizeof(to));
  if(smtp_send(to, "PS5NAS: correo de prueba",
               "Este es un correo de prueba de PS5NAS.\n\n"
               "Si lo has recibido, los usuarios ya pueden recuperar su contraseña "
               "con «¿Olvidaste tu contraseña?».\n", err, sizeof(err))) {
    return send_err(r, 400, err);
  }
  return send_ok(r);
}


/* Explora carpetas reales de la PS5 (solo carpetas) para elegir montajes. */
static int
h_admin_browse(req_t *r) {
  char raw[PATH_MAX], path[PATH_MAX];
  sb_t b = {0};

  if(get_param(r->query, "path", raw, sizeof(raw)) || !raw[0]) strcpy(raw, "/");
  vfs_normalize("/", raw, path, sizeof(path));

  DIR *d = opendir(path);
  if(!d) return send_errno(r);

  sb_puts(&b, "{\"path\":");
  sb_json_str(&b, path);
  sb_puts(&b, ",\"dirs\":[");
  struct dirent *e;
  struct stat st;
  char full[PATH_MAX * 2];
  int first = 1;
  while((e = readdir(d))) {
    if(!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
    snprintf(full, sizeof(full), "%s/%s", strcmp(path, "/") ? path : "", e->d_name);
    if(lstat(full, &st) || !S_ISDIR(st.st_mode)) continue;
    if(!first) sb_puts(&b, ",");
    first = 0;
    sb_json_str(&b, e->d_name);
  }
  closedir(d);
  sb_puts(&b, "]}");
  return send_json(r, 200, &b, NULL);
}


static int
h_admin_settings_get(req_t *r) {
  settings_t s;
  sb_t b = {0};
  char ip[INET_ADDRSTRLEN];
  struct ifaddrs *ifa = NULL;

  cfg_lock();
  memcpy(&s, cfg_settings(), sizeof(s));
  cfg_unlock();

  sb_printf(&b, "{\"ftp_port\":%u,\"http_port\":%u,\"pasv_min\":%u,\"pasv_max\":%u,"
            "\"sftp_port\":%u,\"sftp_enabled\":%s,\"ftp_enabled\":%s,"
            "\"pasv_address\":",
            s.ftp_port, s.http_port, s.pasv_min, s.pasv_max,
            s.sftp_port,
            s.sftp_enabled ? "true" : "false", s.ftp_enabled ? "true" : "false");
  sb_json_str(&b, s.pasv_address);
  sb_puts(&b, ",\"smtp_host\":");
  sb_json_str(&b, s.smtp_host);
  sb_puts(&b, ",\"smtp_user\":");
  sb_json_str(&b, s.smtp_user);
  sb_puts(&b, ",\"smtp_from_name\":");
  sb_json_str(&b, s.smtp_from_name);
  sb_printf(&b, ",\"smtp_port\":%u,\"smtp_pass_set\":%s,\"recover_email\":%s,"
            "\"recover_admin\":%s", s.smtp_port, s.smtp_passenc[0] ? "true" : "false",
            s.recover_email ? "true" : "false", s.recover_admin ? "true" : "false");
  {
    char ts[INET_ADDRSTRLEN] = "";
    tsip_get(ts, sizeof(ts));
    sb_puts(&b, ",\"tailscale_ip\":");
    sb_json_str(&b, ts);
  }
  {
    char vd[PATH_MAX], fp[128], names[1024];
    cfg_vault_dir(vd, sizeof(vd));
    tls_ca_fingerprint(fp, sizeof(fp));
    tls_cert_names(names, sizeof(names));
    sb_printf(&b, ",\"vault_enabled\":%s,\"https_enabled\":%s,\"https_port\":%u,"
              "\"tls_expires\":%lld,\"vault_dir\":", s.vault_enabled ? "true" : "false",
              s.https_enabled ? "true" : "false", s.https_port, tls_cert_expires());
    sb_json_str(&b, s.vault_dir);
    sb_puts(&b, ",\"vault_dir_effective\":");
    sb_json_str(&b, vd);
    sb_puts(&b, ",\"vault_domain\":");
    sb_json_str(&b, s.vault_domain);
    sb_puts(&b, ",\"tls_names\":");
    sb_json_str(&b, s.tls_names);
    sb_puts(&b, ",\"tls_cert_names\":");
    sb_json_str(&b, names);
    sb_puts(&b, ",\"ca_fingerprint\":");
    sb_json_str(&b, fp);
  }
  sb_puts(&b, ",\"fp_ecdsa\":");
  sb_json_str(&b, sftp_fingerprint_ecdsa());
  sb_puts(&b, ",\"fp_rsa\":");
  sb_json_str(&b, sftp_fingerprint_rsa());
  sb_puts(&b, ",\"interfaces\":[");
  if(!getifaddrs(&ifa)) {
    int first = 1;
    for(struct ifaddrs *i = ifa; i; i = i->ifa_next) {
      if(!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
      inet_ntop(AF_INET, &((struct sockaddr_in*)i->ifa_addr)->sin_addr, ip, sizeof(ip));
      if(!first) sb_puts(&b, ",");
      first = 0;
      sb_puts(&b, "{\"name\":");
      sb_json_str(&b, i->ifa_name);
      sb_puts(&b, ",\"ip\":");
      sb_json_str(&b, ip);
      sb_puts(&b, "}");
    }
    freeifaddrs(ifa);
  }
  sb_puts(&b, "]}");
  return send_json(r, 200, &b, NULL);
}


static int
h_admin_settings_set(req_t *r) {
  settings_t s;
  char v[128], err[256];

  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  cfg_lock();
  memcpy(&s, cfg_settings(), sizeof(s));
  cfg_unlock();

  if(!get_param(r->body, "ftp_port", v, sizeof(v))) s.ftp_port = (uint16_t)atoi(v);
  if(!get_param(r->body, "http_port", v, sizeof(v))) s.http_port = (uint16_t)atoi(v);
  if(!get_param(r->body, "pasv_min", v, sizeof(v))) s.pasv_min = (uint16_t)atoi(v);
  if(!get_param(r->body, "pasv_max", v, sizeof(v))) s.pasv_max = (uint16_t)atoi(v);
  if(!get_param(r->body, "sftp_port", v, sizeof(v))) s.sftp_port = (uint16_t)atoi(v);
  if(!get_param(r->body, "sftp_enabled", v, sizeof(v))) s.sftp_enabled = !strcmp(v, "1");
  if(!get_param(r->body, "ftp_enabled", v, sizeof(v))) s.ftp_enabled = !strcmp(v, "1");
  if(!get_param(r->body, "pasv_address", v, sizeof(v))) {
    if(strlen(v) >= sizeof(s.pasv_address)) return send_err(r, 400, "IP demasiado larga");
    memcpy(s.pasv_address, v, strlen(v) + 1);
  }
  if(!get_param(r->body, "smtp_host", v, sizeof(v))) {
    if(strlen(v) >= sizeof(s.smtp_host)) return send_err(r, 400, "Servidor de correo demasiado largo");
    memcpy(s.smtp_host, v, strlen(v) + 1);
  }
  if(!get_param(r->body, "smtp_port", v, sizeof(v))) s.smtp_port = (uint16_t)atoi(v);
  if(!get_param(r->body, "smtp_user", v, sizeof(v))) {
    if(strlen(v) >= sizeof(s.smtp_user)) return send_err(r, 400, "Cuenta de correo demasiado larga");
    memcpy(s.smtp_user, v, strlen(v) + 1);
  }
  if(!get_param(r->body, "smtp_from_name", v, sizeof(v))) {
    if(strlen(v) >= sizeof(s.smtp_from_name)) return send_err(r, 400, "Nombre del remitente demasiado largo");
    memcpy(s.smtp_from_name, v, strlen(v) + 1);
  }
  if(!get_param(r->body, "recover_email", v, sizeof(v))) s.recover_email = !strcmp(v, "1");
  if(!get_param(r->body, "recover_admin", v, sizeof(v))) s.recover_admin = !strcmp(v, "1");
  if(!get_param(r->body, "vault_enabled", v, sizeof(v))) s.vault_enabled = !strcmp(v, "1");
  if(!get_param(r->body, "https_enabled", v, sizeof(v))) s.https_enabled = !strcmp(v, "1");
  if(!get_param(r->body, "https_port", v, sizeof(v))) s.https_port = (uint16_t)atoi(v);
  if(!get_param(r->body, "vault_domain", v, sizeof(v))) {
    if(strlen(v) >= sizeof(s.vault_domain)) return send_err(r, 400, "Dominio demasiado largo");
    memcpy(s.vault_domain, v, strlen(v) + 1);
  }
  {
    char tn[300];
    if(!get_param(r->body, "tls_names", tn, sizeof(tn))) {
      if(strlen(tn) >= sizeof(s.tls_names)) return send_err(r, 400, "Demasiados nombres");
      memcpy(s.tls_names, tn, strlen(tn) + 1);
    }
  }
  char old_vdir[PATH_MAX], new_vdir_raw[PATH_MAX];
  cfg_vault_dir(old_vdir, sizeof(old_vdir));
  int vdir_set = !get_param(r->body, "vault_dir", new_vdir_raw, sizeof(new_vdir_raw));
  if(vdir_set) {
    size_t l = strlen(new_vdir_raw);
    while(l > 1 && new_vdir_raw[l-1] == '/') new_vdir_raw[--l] = 0;
    if(l >= sizeof(s.vault_dir)) return send_err(r, 400, "Ruta demasiado larga");
    memcpy(s.vault_dir, new_vdir_raw, l + 1);
  }
  {
    char sp[256];
    /* Contraseña SMTP: solo se cambia si se escribe una (o se pide borrarla). */
    if(!get_param(r->body, "smtp_pass", sp, sizeof(sp)) && sp[0]) {
      char nospace[256];
      size_t o = 0;
      for(char *c = sp; *c && o + 1 < sizeof(nospace); c++) {
        if(*c != ' ') nospace[o++] = *c;   /* Google la muestra en grupos de 4 */
      }
      nospace[o] = 0;
      if(cfg_set_smtp_password(&s, nospace)) return send_err(r, 400, "Contraseña de correo no válida");
      memset(nospace, 0, sizeof(nospace));
    }
    if(!get_param(r->body, "smtp_pass_clear", sp, sizeof(sp)) && !strcmp(sp, "1")) {
      s.smtp_passenc[0] = 0;
    }
    memset(sp, 0, sizeof(sp));
  }
  if(vdir_set) {
    char new_vdir[PATH_MAX + 16];
    if(s.vault_dir[0]) snprintf(new_vdir, sizeof(new_vdir), "%s", s.vault_dir);
    else snprintf(new_vdir, sizeof(new_vdir), "%s/vault", cfg_dir());
    if(s.vault_dir[0] && s.vault_dir[0] != '/') return send_err(r, 400, "La carpeta debe ser una ruta absoluta");
    /* Primero se mueven las bóvedas; si falla, no se cambia el ajuste. */
    if(strcmp(old_vdir, new_vdir) && vault_move_dir(old_vdir, new_vdir, err, sizeof(err))) {
      return send_err(r, 400, err);
    }
  }
  if(cfg_update_settings(&s, err, sizeof(err))) return send_err(r, 400, err);
  tls_refresh(0);      /* por si cambiaron los nombres del certificado */
  return send_ok(r);
}


/* ------------------------------------------------------------------ */
/* Enrutado                                                            */
/* ------------------------------------------------------------------ */

typedef int (handler_t)(req_t *r);

typedef struct route {
  const char *method;
  const char *path;
  handler_t  *fn;
  int         auth;    /* 0 público, 1 usuario, 2 administrador */
} route_t;


static const route_t routes[] = {
  {"GET",  "/api/status",               h_status,              0},
  {"POST", "/api/setup",                h_setup,               0},
  {"POST", "/api/login",                h_login,               0},
  {"POST", "/api/logout",               h_logout,              0},
  {"GET",  "/api/me",                   h_me,                  1},
  {"POST", "/api/me/password",          h_me_password,         1},
  {"POST", "/api/me/email",             h_me_email,            1},
  {"POST", "/api/forgot/email",         h_forgot_email,        0},
  {"POST", "/api/forgot/request",       h_forgot_request,      0},
  {"GET",  "/api/forgot/status",        h_forgot_status,       0},
  {"GET",  "/api/fs/list",              h_fs_list,             1},
  {"GET",  "/api/fs/get",               h_fs_get,              1},
  {"HEAD", "/api/fs/get",               h_fs_get,              1},
  {"PUT",  "/api/fs/put",               h_fs_put,              1},
  {"POST", "/api/fs/mkdir",             h_fs_mkdir,            1},
  {"POST", "/api/fs/delete",            h_fs_delete,           1},
  {"POST", "/api/fs/rename",            h_fs_rename,           1},
  {"GET",  "/api/admin/users",          h_admin_users,         2},
  {"POST", "/api/admin/user",           h_admin_user_save,     2},
  {"POST", "/api/admin/user/delete",    h_admin_user_delete,   2},
  {"POST", "/api/admin/user/password",  h_admin_user_password, 2},
  {"GET",  "/api/links",                h_links,               1},
  {"POST", "/api/admin/link",           h_admin_link,          2},
  {"POST", "/api/admin/link/delete",    h_admin_link_delete,   2},
  {"GET",  "/api/admin/requests",       h_admin_requests,      2},
  {"POST", "/api/admin/request",        h_admin_request_decide, 2},
  {"POST", "/api/admin/mail/test",      h_admin_mail_test,     2},
  {"GET",  "/api/admin/browse",         h_admin_browse,        2},
  {"GET",  "/api/admin/settings",       h_admin_settings_get,  2},
  {"POST", "/api/admin/settings",       h_admin_settings_set,  2},
  {"POST", "/api/admin/tls",            h_admin_tls_regen,     2},
  {"GET",  "/api/pw/info",              h_pw_info,             1},
  {"GET",  "/api/pw/items",             h_pw_items,            1},
  {"POST", "/api/pw/item",              h_pw_save,             1},
  {"POST", "/api/pw/item/delete",       h_pw_delete,           1},
  {"POST", "/api/pw/item/restore",      h_pw_restore,          1},
  {"POST", "/api/pw/folder",            h_pw_folder,           1},
  {"POST", "/api/pw/folder/delete",     h_pw_folder_delete,    1},
  {"POST", "/api/pw/import",            h_pw_import,           1},
  {"POST", "/api/pw/export",            h_pw_export,           1},
};


static void
handle(req_t *r) {
  if(read_headers(r) || parse_request(r)) {
    send_err(r, 400, "Petición no válida");
    return;
  }

  if(!strcmp(r->path, "/") || !strcmp(r->path, "/index.html")) {
    if(strcmp(r->method, "GET") && strcmp(r->method, "HEAD")) {
      send_err(r, 405, "Método no permitido");
      return;
    }
    send_body(r, 200, "text/html; charset=utf-8", (const char*)web_index_html,
              web_index_html_len,
              "Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; "
              "style-src 'unsafe-inline'; img-src 'self' data:; media-src 'self'; "
              "frame-ancestors 'none'\r\n");
    return;
  }
  if(!strcmp(r->path, "/favicon.ico")) {
    send_body(r, 204, "text/plain", "", 0, NULL);
    return;
  }
  if(!strcmp(r->path, "/ps5nas-ca.crt") && !strcmp(r->method, "GET")) {
    h_pw_ca(r);
    return;
  }

  int path_found = 0;
  for(size_t i=0; i<sizeof(routes)/sizeof(routes[0]); i++) {
    const route_t *rt = &routes[i];
    if(strcmp(r->path, rt->path)) continue;
    path_found = 1;
    if(strcmp(r->method, rt->method)) continue;

    int mutating = strcmp(r->method, "GET") && strcmp(r->method, "HEAD");
    if(mutating && !r->csrf_ok) {
      send_err(r, 403, "Falta la cabecera X-PS5Share");
      return;
    }

    if(rt->auth) {
      char uname[CFG_NAME_MAX+1];
      if(!r->cookie_token[0] || session_lookup(r->cookie_token, uname, &r->key) ||
         cfg_get_user(uname, &r->user) || !r->user.enabled) {
        send_err(r, 401, "Sesión no válida o caducada");
        return;
      }
      r->authed = 1;
      /* Con el cambio de contraseña pendiente solo puede cambiarla. */
      if(r->user.must_chpass && rt->fn != h_me && rt->fn != h_me_password) {
        send_err(r, 403, "Debes cambiar tu contraseña antes de continuar");
        return;
      }
      if(rt->auth == 2 && !r->user.admin) {
        send_err(r, 403, "Solo para administradores");
        return;
      }
    }
    rt->fn(r);
    return;
  }

  if(path_found) send_err(r, 405, "Método no permitido");
  else if(!vault_handle(r)) send_err(r, 404, "No encontrado");
}


/* ------------------------------------------------------------------ */
/* Bucle del servidor                                                  */
/* ------------------------------------------------------------------ */

static int g_nclients = 0;
static pthread_mutex_t g_nclients_lock = PTHREAD_MUTEX_INITIALIZER;


static void*
client_thread(void *p) {
  req_t *r = p;

  io_sock_timeouts(r->fd, HTTP_TIMEOUT);
  setsockopt(r->fd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));
  if(r->tls) {
    io_sock_timeouts(r->fd, 15);       /* el saludo TLS no puede eternizarse */
    r->ssl = tls_accept(r->fd);
    io_sock_timeouts(r->fd, HTTP_TIMEOUT);
  }
  if(!r->tls || r->ssl) handle(r);
  if(r->ssl) {
    tls_close(r->ssl);
    r->ssl = NULL;
  }

  shutdown(r->fd, SHUT_WR);
  /* Vacía lo que quede (evita RST que corta la respuesta en el navegador). */
  char junk[4096];
  io_sock_timeouts(r->fd, 2);
  for(int i=0; i<64 && recv(r->fd, junk, sizeof(junk), 0) > 0; i++) {}
  close(r->fd);
  free(r->body);
  crypt_key_wipe(&r->key);
  free(r);

  pthread_mutex_lock(&g_nclients_lock);
  g_nclients--;
  pthread_mutex_unlock(&g_nclients_lock);
  return NULL;
}


/* Lanza un hilo para atender la conexión FD.  0 o -1. */
static int
spawn_client(int fd, const struct sockaddr_in *peer, int tls) {
  pthread_mutex_lock(&g_nclients_lock);
  int full = g_nclients >= HTTP_MAX_CLIENTS;
  if(!full) g_nclients++;
  pthread_mutex_unlock(&g_nclients_lock);
  if(full) {
    close(fd);
    return -1;
  }

  req_t *r = calloc(1, sizeof(*r));
  if(!r) {
    close(fd);
    pthread_mutex_lock(&g_nclients_lock);
    g_nclients--;
    pthread_mutex_unlock(&g_nclients_lock);
    return -1;
  }
  r->fd = fd;
  r->peer = *peer;
  r->tls = tls;

  pthread_t t;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, 1024 * 1024);
  int e = pthread_create(&t, &attr, client_thread, r);
  pthread_attr_destroy(&attr);
  if(e) {
    close(fd);
    free(r);
    pthread_mutex_lock(&g_nclients_lock);
    g_nclients--;
    pthread_mutex_unlock(&g_nclients_lock);
    return -1;
  }
  return 0;
}


static int
listen_on(uint16_t port) {
  struct sockaddr_in sa;
  int srv;
  if((srv = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_PERROR("socket");
    return -1;
  }
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port = htons(port);
  if(bind(srv, (struct sockaddr*)&sa, sizeof(sa)) || listen(srv, 32)) {
    LOG_PERROR("http bind/listen");
    close(srv);
    return -1;
  }
  return srv;
}


int
http_serve(uint16_t port) {
  int srv = listen_on(port);
  if(srv < 0) return -1;
  LOG_PRINTF("ps5share: web escuchando en el puerto %u\n", port);
  sessions_load();

  for(;;) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int fd = accept(srv, (struct sockaddr*)&peer, &plen);
    if(fd < 0) {
      if(errno == EINTR || errno == ECONNABORTED) continue;
      LOG_PERROR("http accept");
      break;
    }
    spawn_client(fd, &peer, 0);
  }

  close(srv);
  return -1;
}


/* Servidor HTTPS: se puede activar, desactivar o cambiar de puerto desde
   los ajustes sin reiniciar.  Revisa cada minuto si cambiaron las IPs para
   volver a emitir el certificado. */
int
http_serve_tls(void) {
  time_t last_check = 0;
  for(;;) {
    cfg_lock();
    int enabled = cfg_settings()->https_enabled;
    uint16_t port = cfg_settings()->https_port;
    cfg_unlock();
    if(!enabled) {
      sleep(2);
      continue;
    }
    int srv = listen_on(port);
    if(srv < 0) {
      sleep(10);
      continue;
    }
    LOG_PRINTF("ps5share: HTTPS escuchando en el puerto %u\n", port);
    for(;;) {
      if(time(NULL) - last_check >= 60) {
        last_check = time(NULL);
        tls_refresh(0);
      }
      cfg_lock();
      int still = cfg_settings()->https_enabled && cfg_settings()->https_port == port;
      cfg_unlock();
      if(!still) break;
      if(io_wait_readable(srv, 1000) <= 0) continue;
      struct sockaddr_in peer;
      socklen_t plen = sizeof(peer);
      int fd = accept(srv, (struct sockaddr*)&peer, &plen);
      if(fd < 0) {
        if(errno == EINTR || errno == ECONNABORTED || errno == EAGAIN) continue;
        LOG_PERROR("https accept");
        break;
      }
      spawn_client(fd, &peer, 1);
    }
    close(srv);
    LOG_PRINTF("ps5share: HTTPS detenido en el puerto %u\n", port);
  }
  return -1;
}
