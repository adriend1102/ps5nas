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
#include "sftp.h"
#include "io.h"
#include "log.h"
#include "vfs.h"
#include "webui.h"

#define HTTP_MAX_CLIENTS   64
#define HTTP_HDR_MAX       16384
#define HTTP_BODY_MAX      (256 * 1024)
#define HTTP_TIMEOUT       60
#define SESSION_MAX        256
#define SESSION_TTL        (12 * 3600)
#define RL_SLOTS           64
#define RL_WINDOW          600
#define RL_MAX_FAILS       10


/* ------------------------------------------------------------------ */
/* Buffer dinámico para construir respuestas JSON                      */
/* ------------------------------------------------------------------ */

typedef struct sb {
  char  *p;
  size_t len, cap;
} sb_t;


static void
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


static void sb_puts(sb_t *b, const char *s) { sb_putn(b, s, strlen(s)); }


static void
sb_printf(sb_t *b, const char *fmt, ...) {
  char tmp[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if(n > 0) sb_putn(b, tmp, (size_t)n < sizeof(tmp) ? (size_t)n : sizeof(tmp) - 1);
}


static void
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

typedef struct req {
  int  fd;
  struct sockaddr_in peer;
  char method[8];
  char path[2048];
  char query[4096];
  long long content_length;
  int  chunked;
  int  csrf_ok;
  char cookie_token[80];
  char range[128];

  char  hdr[HTTP_HDR_MAX];
  size_t hdr_len;      /* bytes leídos en hdr */
  size_t body_start;   /* offset del cuerpo dentro de hdr */

  char *body;          /* cuerpo (para formularios) */
  size_t body_len;

  user_t user;         /* usuario autenticado (si lo hay) */
  int    authed;
} req_t;


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
static int
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
    ssize_t n = recv(r->fd, r->hdr + r->hdr_len, sizeof(r->hdr) - 1 - r->hdr_len, 0);
    if(n < 0 && errno == EINTR) continue;
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
static int
read_body(req_t *r) {
  if(r->body) return 0;
  if(r->chunked) return -1;
  long long cl = r->content_length < 0 ? 0 : r->content_length;
  if(cl > HTTP_BODY_MAX) return -1;

  r->body = malloc((size_t)cl + 1);
  if(!r->body) return -1;

  size_t have = r->hdr_len - r->body_start;
  if(have > (size_t)cl) have = (size_t)cl;
  memcpy(r->body, r->hdr + r->body_start, have);
  while(have < (size_t)cl) {
    ssize_t n = recv(r->fd, r->body + have, (size_t)cl - have, 0);
    if(n < 0 && errno == EINTR) continue;
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
  case 507: return "Insufficient Storage";
  default:  return "Error";
  }
}


static int
send_head(req_t *r, int code, const char *ctype, long long len, const char *extra) {
  char h[2048];
  int n = snprintf(h, sizeof(h),
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Type: %s\r\n"
                   "Content-Length: %lld\r\n"
                   "Connection: close\r\n"
                   "Cache-Control: no-store\r\n"
                   "X-Content-Type-Options: nosniff\r\n"
                   "X-Frame-Options: DENY\r\n"
                   "Referrer-Policy: no-referrer\r\n"
                   "%s\r\n",
                   code, status_text(code), ctype, len, extra ? extra : "");
  if(n < 0 || (size_t)n >= sizeof(h)) return -1;
  return io_writeall(r->fd, h, (size_t)n);
}


static int
send_body(req_t *r, int code, const char *ctype, const char *body, size_t len,
          const char *extra) {
  if(send_head(r, code, ctype, (long long)len, extra)) return -1;
  if(!strcmp(r->method, "HEAD")) return 0;
  return io_writeall(r->fd, body, len);
}


static int
send_json(req_t *r, int code, sb_t *b, const char *extra) {
  int ret = send_body(r, code, "application/json; charset=utf-8",
                      b->p ? b->p : "{}", b->p ? b->len : 2, extra);
  free(b->p);
  b->p = NULL;
  return ret;
}


static int
send_err(req_t *r, int code, const char *msg) {
  sb_t b = {0};
  sb_puts(&b, "{\"error\":");
  sb_json_str(&b, msg);
  sb_puts(&b, "}");
  return send_json(r, code, &b, NULL);
}


static int
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
  char   token[65];
  char   user[CFG_NAME_MAX+1];
  time_t expires;
} session_t;

static session_t g_sess[SESSION_MAX];
static pthread_mutex_t g_sess_lock = PTHREAD_MUTEX_INITIALIZER;


static void
session_create(const char *user, char *token_out) {
  time_t now = time(NULL);
  int slot = 0;

  cfg_random_hex(token_out, 32);
  pthread_mutex_lock(&g_sess_lock);
  for(int i=0; i<SESSION_MAX; i++) {
    if(g_sess[i].expires < now) { slot = i; break; }
    if(g_sess[i].expires < g_sess[slot].expires) slot = i;
  }
  snprintf(g_sess[slot].token, sizeof(g_sess[slot].token), "%s", token_out);
  snprintf(g_sess[slot].user, sizeof(g_sess[slot].user), "%s", user);
  g_sess[slot].expires = now + SESSION_TTL;
  pthread_mutex_unlock(&g_sess_lock);
}


static int
session_lookup(const char *token, char *user_out) {
  time_t now = time(NULL);
  int r = -1;
  if(strlen(token) != 64) return -1;
  pthread_mutex_lock(&g_sess_lock);
  for(int i=0; i<SESSION_MAX; i++) {
    if(g_sess[i].expires >= now && cfg_consttime_eq(g_sess[i].token, token)) {
      snprintf(user_out, CFG_NAME_MAX + 1, "%s", g_sess[i].user);
      r = 0;
      break;
    }
  }
  pthread_mutex_unlock(&g_sess_lock);
  return r;
}


static void
session_destroy(const char *token) {
  pthread_mutex_lock(&g_sess_lock);
  for(int i=0; i<SESSION_MAX; i++) {
    if(g_sess[i].token[0] && cfg_consttime_eq(g_sess[i].token, token)) {
      memset(&g_sess[i], 0, sizeof(g_sess[i]));
    }
  }
  pthread_mutex_unlock(&g_sess_lock);
}


static void
session_destroy_user(const char *user) {
  pthread_mutex_lock(&g_sess_lock);
  for(int i=0; i<SESSION_MAX; i++) {
    if(!strcmp(g_sess[i].user, user)) memset(&g_sess[i], 0, sizeof(g_sess[i]));
  }
  pthread_mutex_unlock(&g_sess_lock);
}


typedef struct rl_slot {
  uint32_t ip;
  int      fails;
  time_t   first;
} rl_slot_t;

static rl_slot_t g_rl[RL_SLOTS];
static pthread_mutex_t g_rl_lock = PTHREAD_MUTEX_INITIALIZER;


static int
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


static void
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


static void
rl_clear(uint32_t ip) {
  pthread_mutex_lock(&g_rl_lock);
  for(int i=0; i<RL_SLOTS; i++) {
    if(g_rl[i].ip == ip) memset(&g_rl[i], 0, sizeof(g_rl[i]));
  }
  pthread_mutex_unlock(&g_rl_lock);
}


static int
login_reply(req_t *r, const char *user) {
  char token[65];
  char cookie[256];
  sb_t b = {0};

  session_create(user, token);
  snprintf(cookie, sizeof(cookie),
           "Set-Cookie: ps5s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d\r\n",
           token, SESSION_TTL);
  sb_puts(&b, "{\"ok\":true}");
  return send_json(r, 200, &b, cookie);
}


/* ------------------------------------------------------------------ */
/* Rutas públicas                                                      */
/* ------------------------------------------------------------------ */

static int
h_status(req_t *r) {
  sb_t b = {0};
  cfg_lock();
  int setup = cfg_nusers() == 0;
  cfg_unlock();
  sb_printf(&b, "{\"setup\":%s,\"version\":", setup ? "true" : "false");
  sb_json_str(&b, VERSION_TAG);
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
  if(!pass[0]) return send_err(r, 400, "Falta la contraseña");
  if(cfg_upsert_user(&u, pass, err, sizeof(err))) return send_err(r, 400, err);
  LOG_PRINTF("ps5share: administrador inicial '%s' creado\n", user);
  return login_reply(r, user);
}


static int
h_login(req_t *r) {
  char user[CFG_NAME_MAX+1], pass[256];
  uint32_t ip = r->peer.sin_addr.s_addr;

  if(rl_blocked(ip)) {
    return send_err(r, 429, "Demasiados intentos. Espera unos minutos.");
  }
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "user", user, sizeof(user));
  get_param(r->body, "pass", pass, sizeof(pass));

  if(cfg_authenticate(user, pass, NULL)) {
    rl_fail(ip);
    sleep(1);
    return send_err(r, 401, "Usuario o contraseña incorrectos");
  }
  rl_clear(ip);
  return login_reply(r, user);
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
  sb_printf(&b, ",\"admin\":%s,\"mounts\":[", r->user.admin ? "true" : "false");
  for(int i=0; i<r->user.nmounts; i++) {
    if(i) sb_puts(&b, ",");
    sb_puts(&b, "{\"name\":");
    sb_json_str(&b, r->user.mounts[i].name);
    sb_printf(&b, ",\"rw\":%s}", r->user.mounts[i].rw ? "true" : "false");
  }
  sb_puts(&b, "]}");
  return send_json(r, 200, &b, NULL);
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
  return vfs_lookup(&r->user, "/", v, res);
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
      sb_printf(&b, ",\"dir\":true,\"size\":0,\"mtime\":%lld,\"rw\":%s,\"missing\":%s}",
                ok ? (long long)st.st_mtime : 0LL, m->rw ? "true" : "false",
                ok ? "false" : "true");
    }
    sb_puts(&b, "]}");
    return send_json(r, 200, &b, NULL);
  }

  DIR *d = opendir(res.real);
  if(!d) {
    free(b.p);
    return send_errno(r);
  }
  sb_printf(&b, ",\"rw\":%s,\"root\":false,\"entries\":[", res.rw ? "true" : "false");

  struct dirent *e;
  char full[PATH_MAX * 2];
  int first = 1;
  while((e = readdir(d))) {
    if(!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
    snprintf(full, sizeof(full), "%s/%s", res.real, e->d_name);
    if(lstat(full, &st) || S_ISLNK(st.st_mode)) continue;
    if(!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) continue;
    if(!first) sb_puts(&b, ",");
    first = 0;
    sb_puts(&b, "{\"name\":");
    sb_json_str(&b, e->d_name);
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
  int fd;

  if(lookup_param(r, r->query, "path", &res)) return send_errno(r);
  if(res.mount < 0) return send_err(r, 400, "No es un archivo");
  if((fd = open(res.real, O_RDONLY)) < 0) return send_errno(r);
  if(fstat(fd, &st) || !S_ISREG(st.st_mode)) {
    close(fd);
    return send_err(r, 400, "No es un archivo");
  }

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
        close(fd);
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
    close(fd);
    return 0;
  }

  void *buf = malloc(IO_BUFSIZE);
  if(buf) {
    if(lseek(fd, start, SEEK_SET) >= 0) io_copy(fd, r->fd, (size_t)len, buf, IO_BUFSIZE);
    free(buf);
  }
  close(fd);
  return 0;
}


static int
h_fs_put(req_t *r) {
  vfs_res_t res;
  char part[PATH_MAX + 32];
  int fd;

  if(lookup_param(r, r->query, "path", &res)) return send_errno(r);
  if(res.mount < 0 || res.is_mount_root || !res.rw) return send_err(r, 403, "Permiso denegado");
  if(r->chunked || r->content_length < 0) return send_err(r, 411, "Falta Content-Length");

  struct stat st;
  if(!stat(res.real, &st) && S_ISDIR(st.st_mode)) {
    return send_err(r, 409, "Ya existe una carpeta con ese nombre");
  }

  snprintf(part, sizeof(part), "%s.ps5share-part", res.real);
  if((fd = open(part, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) return send_errno(r);

  void *buf = malloc(IO_BUFSIZE);
  if(!buf) {
    close(fd);
    unlink(part);
    return send_err(r, 500, "Sin memoria");
  }

  long long remaining = r->content_length;
  int err = 0;

  size_t have = r->hdr_len - r->body_start;
  if(have > (size_t)remaining) have = (size_t)remaining;
  if(have && io_writeall(fd, r->hdr + r->body_start, have)) err = errno;
  remaining -= (long long)have;

  io_sock_timeouts(r->fd, 300);
  while(!err && remaining > 0) {
    size_t want = remaining < IO_BUFSIZE ? (size_t)remaining : IO_BUFSIZE;
    ssize_t n = recv(r->fd, buf, want, 0);
    if(n < 0 && errno == EINTR) continue;
    if(n <= 0) { err = n == 0 ? EPIPE : errno; break; }
    if(io_writeall(fd, buf, (size_t)n)) { err = errno; break; }
    remaining -= n;
  }
  free(buf);

  if(close(fd) && !err) err = errno;
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
  sb_puts(&b, "{\"users\":[");
  cfg_lock();
  for(int i=0; i<cfg_nusers(); i++) {
    user_t *u = cfg_user_at(i);
    if(i) sb_puts(&b, ",");
    sb_puts(&b, "{\"name\":");
    sb_json_str(&b, u->name);
    sb_printf(&b, ",\"admin\":%s,\"enabled\":%s,\"mounts\":[",
              u->admin ? "true" : "false", u->enabled ? "true" : "false");
    for(int j=0; j<u->nmounts; j++) {
      if(j) sb_puts(&b, ",");
      sb_puts(&b, "{\"name\":");
      sb_json_str(&b, u->mounts[j].name);
      sb_puts(&b, ",\"path\":");
      sb_json_str(&b, u->mounts[j].path);
      sb_printf(&b, ",\"rw\":%s}", u->mounts[j].rw ? "true" : "false");
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
      m->rw = !strcmp(line, "rw");
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

  if(!(mounts = malloc(HTTP_BODY_MAX))) return send_err(r, 500, "Sin memoria");
  get_param(r->body, "mounts", mounts, HTTP_BODY_MAX);
  int pr = parse_mounts(mounts, &u, err, sizeof(err));
  free(mounts);
  if(pr) return send_err(r, 400, err);

  if(!strcmp(u.name, r->user.name) && (!u.admin || !u.enabled)) {
    return send_err(r, 400, "No puedes quitarte a ti mismo el rol de administrador");
  }
  if(cfg_upsert_user(&u, pass, err, sizeof(err))) return send_err(r, 400, err);
  if(!u.enabled) session_destroy_user(u.name);
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
  session_destroy_user(name);
  LOG_PRINTF("ps5share: '%s' borró el usuario '%s'\n", r->user.name, name);
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
            "\"kill_ftpsrv\":%s,\"sftp_port\":%u,\"sftp_enabled\":%s,\"ftp_enabled\":%s,"
            "\"pasv_address\":",
            s.ftp_port, s.http_port, s.pasv_min, s.pasv_max,
            s.kill_ftpsrv ? "true" : "false", s.sftp_port,
            s.sftp_enabled ? "true" : "false", s.ftp_enabled ? "true" : "false");
  sb_json_str(&b, s.pasv_address);
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
  if(!get_param(r->body, "kill_ftpsrv", v, sizeof(v))) s.kill_ftpsrv = !strcmp(v, "1");
  if(!get_param(r->body, "sftp_port", v, sizeof(v))) s.sftp_port = (uint16_t)atoi(v);
  if(!get_param(r->body, "sftp_enabled", v, sizeof(v))) s.sftp_enabled = !strcmp(v, "1");
  if(!get_param(r->body, "ftp_enabled", v, sizeof(v))) s.ftp_enabled = !strcmp(v, "1");
  if(!get_param(r->body, "pasv_address", v, sizeof(v))) {
    if(strlen(v) >= sizeof(s.pasv_address)) return send_err(r, 400, "IP demasiado larga");
    memcpy(s.pasv_address, v, strlen(v) + 1);
  }
  if(cfg_update_settings(&s, err, sizeof(err))) return send_err(r, 400, err);
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
  {"GET",  "/api/admin/browse",         h_admin_browse,        2},
  {"GET",  "/api/admin/settings",       h_admin_settings_get,  2},
  {"POST", "/api/admin/settings",       h_admin_settings_set,  2},
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
      if(!r->cookie_token[0] || session_lookup(r->cookie_token, uname) ||
         cfg_get_user(uname, &r->user) || !r->user.enabled) {
        send_err(r, 401, "Sesión no válida o caducada");
        return;
      }
      r->authed = 1;
      if(rt->auth == 2 && !r->user.admin) {
        send_err(r, 403, "Solo para administradores");
        return;
      }
    }
    rt->fn(r);
    return;
  }

  if(path_found) send_err(r, 405, "Método no permitido");
  else send_err(r, 404, "No encontrado");
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
  handle(r);

  shutdown(r->fd, SHUT_WR);
  /* Vacía lo que quede (evita RST que corta la respuesta en el navegador). */
  char junk[4096];
  io_sock_timeouts(r->fd, 2);
  for(int i=0; i<64 && recv(r->fd, junk, sizeof(junk), 0) > 0; i++) {}
  close(r->fd);
  free(r->body);
  free(r);

  pthread_mutex_lock(&g_nclients_lock);
  g_nclients--;
  pthread_mutex_unlock(&g_nclients_lock);
  return NULL;
}


int
http_serve(uint16_t port) {
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
  LOG_PRINTF("ps5share: web escuchando en el puerto %u\n", port);

  for(;;) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int fd = accept(srv, (struct sockaddr*)&peer, &plen);
    if(fd < 0) {
      if(errno == EINTR || errno == ECONNABORTED) continue;
      LOG_PERROR("http accept");
      break;
    }

    pthread_mutex_lock(&g_nclients_lock);
    int full = g_nclients >= HTTP_MAX_CLIENTS;
    if(!full) g_nclients++;
    pthread_mutex_unlock(&g_nclients_lock);
    if(full) {
      close(fd);
      continue;
    }

    req_t *r = calloc(1, sizeof(*r));
    if(!r) {
      close(fd);
      pthread_mutex_lock(&g_nclients_lock);
      g_nclients--;
      pthread_mutex_unlock(&g_nclients_lock);
      continue;
    }
    r->fd = fd;
    r->peer = peer;

    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 1024 * 1024);
    if(pthread_create(&t, &attr, client_thread, r)) {
      close(fd);
      free(r);
      pthread_mutex_lock(&g_nclients_lock);
      g_nclients--;
      pthread_mutex_unlock(&g_nclients_lock);
    }
    pthread_attr_destroy(&attr);
  }

  close(srv);
  return -1;
}
