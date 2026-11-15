/* ps5share - playlists mensuales de Spotify
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   API usada (Web API tras los cambios de febrero de 2026):
     POST accounts/api/token          código PKCE y refresco
     GET  /v1/me                      usuario
     GET  /v1/me/tracks               «Me gusta» (50 por página, más nuevas primero)
     GET  /v1/me/playlists            para adoptar playlists que ya existan
     POST /v1/me/playlists            crear playlist (sustituye a /users/{id}/playlists)
     GET  /v1/playlists/{id}/items    contenido (sustituye a .../tracks)
     POST /v1/playlists/{id}/items    añadir (máx. 100 por petición)  */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hash.h>

#include "config.h"
#include "json.h"
#include "library.h"
#include "log.h"
#include "net.h"
#include "notify.h"
#include "spotify.h"

#define SP_MAX_MONTHS    600
#define SP_MAX_TRACKS    50000
#define SP_RETRY_FAIL    (15 * 60)       /* tras un error, reintenta en 15 min */
#define SP_LIB_EVERY     (5 * 60)        /* revisa la carpeta Entrada cada 5 min */
#define SP_LOGIN_TTL     (30 * 60)
#define SP_REFRESH_LIFE  (182 * 24 * 3600)  /* el token de refresco dura ~6 meses */
#define SP_SCOPES        "user-library-read playlist-read-private playlist-modify-private playlist-modify-public " \
                         "user-top-read user-read-recently-played"
#define SP_HIST_EVERY    (20 * 60)       /* historial de escuchas: solo da las 50 últimas */
#define SP_HIST_KEEP     (400LL * 24 * 3600 * 1000)
#define SP_AAD           "ps5share-spotify"


typedef struct sp_month {
  int  ym;
  char pid[64];      /* id de la playlist en Spotify */
  int  synced;       /* canciones de ese mes ya comprobadas en la playlist */
  int  total;
  int  have;         /* con archivo en la carpeta de música */
} sp_month_t;


typedef struct sp_top {
  int      ym;
  char     pid[64];
  int      final;       /* mes cerrado: ya no se toca */
  uint32_t hash;        /* de la última lista enviada */
  int      plays;       /* escuchas registradas ese mes */
  int      n;           /* canciones en la lista */
  int      have;        /* con archivo en la PS5 */
} sp_top_t;


static struct {
  char   client_id[80];
  char   refresh_enc[CRYPT_SEAL_HEX + 1];
  char   user_id[128];
  char   user_name[128];
  int    start_ym;
  char   music_dir[PATH_MAX];
  int    interval_h;
  int    enabled;
  time_t connected_at;
  time_t last_sync;
  time_t next_sync;
  int    last_ok;
  char   message[512];
  int    syncing;
  int    want_sync;
  /* inicio de sesión pendiente */
  char   verifier[80];
  char   state[40];
  time_t login_at;
  /* token de acceso (solo en memoria) */
  char   access[512];
  time_t access_exp;
  int          nmonths;
  sp_month_t   months[SP_MAX_MONTHS];
  /* lo más escuchado */
  int          top_enabled;
  int          top_size;
  char         scopes[512];
  char         top_msg[256];
  long long    hist_last_ms;     /* última escucha guardada */
  time_t       hist_at;
  int          ntops;
  sp_top_t     tops[SP_MAX_MONTHS];
} S;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_wake = PTHREAD_COND_INITIALIZER;
static char g_dir[PATH_MAX - 64];


/* ------------------------------------------------------------------ */
/* Utilidades                                                          */
/* ------------------------------------------------------------------ */

typedef struct jb { char *p; size_t len, cap; } jb_t;


static void
jb_printf(jb_t *b, const char *fmt, ...) {
  va_list ap;
  for(;;) {
    va_start(ap, fmt);
    int n = vsnprintf(b->p ? b->p + b->len : NULL, b->p ? b->cap - b->len : 0, fmt, ap);
    va_end(ap);
    if(n < 0) return;
    if(b->p && b->len + (size_t)n < b->cap) { b->len += (size_t)n; return; }
    size_t nc = b->cap ? b->cap : 4096;
    while(nc <= b->len + (size_t)n) nc *= 2;
    char *np = realloc(b->p, nc);
    if(!np) return;
    b->p = np;
    b->cap = nc;
  }
}


static void
jb_str(jb_t *b, const char *s) {
  jb_printf(b, "\"");
  for(const unsigned char *p = (const unsigned char*)s; *p; p++) {
    if(*p == '"' || *p == '\\') jb_printf(b, "\\%c", *p);
    else if(*p < 0x20) jb_printf(b, "\\u%04x", *p);
    else jb_printf(b, "%c", *p);
  }
  jb_printf(b, "\"");
}


static const char *
accounts_base(void) {
#ifndef __PROSPERO__
  const char *e = getenv("PS5SHARE_SPOTIFY_ACCOUNTS");
  if(e) return e;
#endif
  return "https://accounts.spotify.com";
}


static const char *
api_base(void) {
#ifndef __PROSPERO__
  const char *e = getenv("PS5SHARE_SPOTIFY_API");
  if(e) return e;
#endif
  return "https://api.spotify.com";
}


static int
parse_ym(const char *s) {
  int y, m;
  if(sscanf(s, "%d-%d", &y, &m) != 2 || y < 2000 || y > 2200 || m < 1 || m > 12) return -1;
  return y * 12 + m - 1;
}


static void
set_msg(int ok, const char *fmt, ...) {
  va_list ap;
  pthread_mutex_lock(&g_lock);
  va_start(ap, fmt);
  vsnprintf(S.message, sizeof(S.message), fmt, ap);
  va_end(ap);
  S.last_ok = ok;
  pthread_mutex_unlock(&g_lock);
}


static sp_month_t *
month_get_locked(int ym, int create) {
  for(int i=0; i<S.nmonths; i++) if(S.months[i].ym == ym) return &S.months[i];
  if(!create || S.nmonths >= SP_MAX_MONTHS) return NULL;
  /* mantiene el orden por fecha */
  int pos = S.nmonths;
  while(pos > 0 && S.months[pos-1].ym > ym) pos--;
  memmove(&S.months[pos+1], &S.months[pos], (size_t)(S.nmonths - pos) * sizeof(sp_month_t));
  memset(&S.months[pos], 0, sizeof(sp_month_t));
  S.months[pos].ym = ym;
  S.nmonths++;
  return &S.months[pos];
}


static sp_top_t *
top_get_locked(int ym, int create) {
  for(int i=0; i<S.ntops; i++) if(S.tops[i].ym == ym) return &S.tops[i];
  if(!create || S.ntops >= SP_MAX_MONTHS) return NULL;
  int pos = S.ntops;
  while(pos > 0 && S.tops[pos-1].ym > ym) pos--;
  memmove(&S.tops[pos+1], &S.tops[pos], (size_t)(S.ntops - pos) * sizeof(sp_top_t));
  memset(&S.tops[pos], 0, sizeof(sp_top_t));
  S.tops[pos].ym = ym;
  S.ntops++;
  return &S.tops[pos];
}


static int
top_scope_ok_locked(void) {
  return strstr(S.scopes, "user-top-read") && strstr(S.scopes, "user-read-recently-played");
}


/* ------------------------------------------------------------------ */
/* Persistencia                                                        */
/* ------------------------------------------------------------------ */

static void
clean_field(char *s) {
  for(; *s; s++) if(*s == '\t' || *s == '\n' || *s == '\r') *s = ' ';
}


static void
save_locked(void) {
  char path[PATH_MAX], tmp[PATH_MAX + 8];
  snprintf(path, sizeof(path), "%s/spotify.conf", g_dir);
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE *f = fopen(tmp, "w");
  if(!f) {
    LOG_PERROR(tmp);
    return;
  }
  clean_field(S.user_name);
  clean_field(S.message);
  fprintf(f, "set\tclient_id\t%s\n", S.client_id);
  fprintf(f, "set\trefresh\t%s\n", S.refresh_enc);
  fprintf(f, "set\tuser_id\t%s\n", S.user_id);
  fprintf(f, "set\tuser_name\t%s\n", S.user_name);
  fprintf(f, "set\tstart\t%04d-%02d\n", S.start_ym / 12, S.start_ym % 12 + 1);
  fprintf(f, "set\tmusic_dir\t%s\n", S.music_dir);
  fprintf(f, "set\tinterval\t%d\n", S.interval_h);
  fprintf(f, "set\tenabled\t%d\n", S.enabled);
  fprintf(f, "set\tconnected_at\t%lld\n", (long long)S.connected_at);
  fprintf(f, "set\tlast_sync\t%lld\n", (long long)S.last_sync);
  fprintf(f, "set\tlast_ok\t%d\n", S.last_ok);
  fprintf(f, "set\tmessage\t%s\n", S.message);
  fprintf(f, "set\ttop_enabled\t%d\n", S.top_enabled);
  fprintf(f, "set\ttop_size\t%d\n", S.top_size);
  fprintf(f, "set\tscopes\t%s\n", S.scopes);
  fprintf(f, "set\thist_last\t%lld\n", S.hist_last_ms);
  for(int i=0; i<S.ntops; i++) {
    const sp_top_t *t = &S.tops[i];
    fprintf(f, "top\t%04d-%02d\t%s\t%d\t%u\n", t->ym / 12, t->ym % 12 + 1, t->pid, t->final, t->hash);
  }
  for(int i=0; i<S.nmonths; i++) {
    const sp_month_t *m = &S.months[i];
    if(!m->pid[0]) continue;
    fprintf(f, "pl\t%04d-%02d\t%s\t%d\n", m->ym / 12, m->ym % 12 + 1, m->pid, m->synced);
  }
  if(fclose(f) || rename(tmp, path)) LOG_PERROR(path);
}


static void
load(void) {
  char path[PATH_MAX], line[2048];
  snprintf(path, sizeof(path), "%s/spotify.conf", g_dir);
  FILE *f = fopen(path, "r");
  if(!f) return;
  while(fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\r\n")] = 0;
    char *fld[5] = {0};
    int n = 0;
    for(char *p = line, *t; n < 5 && (t = strsep(&p, "\t")); ) fld[n++] = t;
    if(n >= 3 && !strcmp(fld[0], "set")) {
      const char *k = fld[1], *v = fld[2];
      if(!strcmp(k, "client_id")) snprintf(S.client_id, sizeof(S.client_id), "%s", v);
      else if(!strcmp(k, "refresh")) snprintf(S.refresh_enc, sizeof(S.refresh_enc), "%s", v);
      else if(!strcmp(k, "user_id")) snprintf(S.user_id, sizeof(S.user_id), "%s", v);
      else if(!strcmp(k, "user_name")) snprintf(S.user_name, sizeof(S.user_name), "%s", v);
      else if(!strcmp(k, "start") && parse_ym(v) >= 0) S.start_ym = parse_ym(v);
      else if(!strcmp(k, "music_dir") && v[0]) snprintf(S.music_dir, sizeof(S.music_dir), "%s", v);
      else if(!strcmp(k, "interval") && atoi(v) > 0) S.interval_h = atoi(v);
      else if(!strcmp(k, "enabled")) S.enabled = atoi(v);
      else if(!strcmp(k, "connected_at")) S.connected_at = (time_t)atoll(v);
      else if(!strcmp(k, "last_sync")) S.last_sync = (time_t)atoll(v);
      else if(!strcmp(k, "last_ok")) S.last_ok = atoi(v);
      else if(!strcmp(k, "message")) snprintf(S.message, sizeof(S.message), "%s", v);
      else if(!strcmp(k, "top_enabled")) S.top_enabled = atoi(v);
      else if(!strcmp(k, "top_size") && atoi(v) >= 5 && atoi(v) <= 100) S.top_size = atoi(v);
      else if(!strcmp(k, "scopes")) snprintf(S.scopes, sizeof(S.scopes), "%s", v);
      else if(!strcmp(k, "hist_last")) S.hist_last_ms = atoll(v);
    } else if(n >= 5 && !strcmp(fld[0], "top") && parse_ym(fld[1]) >= 0) {
      sp_top_t *t = top_get_locked(parse_ym(fld[1]), 1);
      if(t) {
        snprintf(t->pid, sizeof(t->pid), "%s", fld[2]);
        t->final = atoi(fld[3]);
        t->hash = (uint32_t)strtoul(fld[4], NULL, 10);
      }
    } else if(n >= 3 && !strcmp(fld[0], "pl") && parse_ym(fld[1]) >= 0) {
      sp_month_t *m = month_get_locked(parse_ym(fld[1]), 1);
      if(m) {
        snprintf(m->pid, sizeof(m->pid), "%s", fld[2]);
        m->synced = n >= 4 ? atoi(fld[3]) : 0;
      }
    }
  }
  fclose(f);
}


/* Caché de canciones (para montar las listas sin conexión). */
static void
save_tracks(const lib_track_t *t, int n) {
  char path[PATH_MAX], tmp[PATH_MAX + 8];
  snprintf(path, sizeof(path), "%s/spotify-tracks.tsv", g_dir);
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE *f = fopen(tmp, "w");
  if(!f) return;
  for(int i=0; i<n; i++) {
    fprintf(f, "%d\t%s\t%s\t%d\t%s\t%s\t%s\n", t[i].ym, t[i].added_at, t[i].uri,
            t[i].duration_ms, t[i].artist, t[i].title, t[i].album);
  }
  if(fclose(f) || rename(tmp, path)) LOG_PERROR(path);
}


static lib_track_t *
load_tracks(int *count) {
  char path[PATH_MAX], line[2048];
  lib_track_t *t = NULL;
  int n = 0, cap = 0;
  *count = 0;
  snprintf(path, sizeof(path), "%s/spotify-tracks.tsv", g_dir);
  FILE *f = fopen(path, "r");
  if(!f) return NULL;
  while(fgets(line, sizeof(line), f) && n < SP_MAX_TRACKS) {
    line[strcspn(line, "\r\n")] = 0;
    char *fld[7] = {0};
    int k = 0;
    for(char *p = line, *x; k < 7 && (x = strsep(&p, "\t")); ) fld[k++] = x;
    if(k < 7) continue;
    if(n == cap) {
      cap = cap ? cap * 2 : 512;
      lib_track_t *nt = realloc(t, (size_t)cap * sizeof(*nt));
      if(!nt) break;
      t = nt;
    }
    lib_track_t *x = &t[n++];
    x->ym = atoi(fld[0]);
    snprintf(x->added_at, sizeof(x->added_at), "%s", fld[1]);
    snprintf(x->uri, sizeof(x->uri), "%s", fld[2]);
    x->duration_ms = atoi(fld[3]);
    snprintf(x->artist, sizeof(x->artist), "%s", fld[4]);
    snprintf(x->title, sizeof(x->title), "%s", fld[5]);
    snprintf(x->album, sizeof(x->album), "%s", fld[6]);
  }
  fclose(f);
  *count = n;
  return t;
}


/* ------------------------------------------------------------------ */
/* OAuth                                                               */
/* ------------------------------------------------------------------ */

static void
b64url(const uint8_t *in, size_t n, char *out) {
  static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  size_t o = 0;
  for(size_t i=0; i<n; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16 | (i+1 < n ? in[i+1] << 8 : 0) | (i+2 < n ? in[i+2] : 0);
    out[o++] = T[(v >> 18) & 63];
    out[o++] = T[(v >> 12) & 63];
    if(i+1 < n) out[o++] = T[(v >> 6) & 63];
    if(i+2 < n) out[o++] = T[v & 63];
  }
  out[o] = 0;
}


/* Petición al servicio de cuentas.  Rellena el token de acceso y, si llega,
   el nuevo token de refresco (Spotify puede rotarlo). */
static int
token_request(const char *form, int *invalid_grant, char *err, size_t errlen) {
  char url[256];
  https_resp_t r;
  int ret = -1;
  *invalid_grant = 0;
  snprintf(url, sizeof(url), "%s/api/token", accounts_base());
  if(https_request("POST", url, "Content-Type: application/x-www-form-urlencoded\r\n",
                   form, strlen(form), &r, err, errlen)) return -1;
  jv_t *j = json_parse(r.body, r.len);
  if(r.status != 200 || !j) {
    const char *e = json_str(json_get(j, "error"));
    const char *d = json_str(json_get(j, "error_description"));
    *invalid_grant = !strcmp(e, "invalid_grant");
    snprintf(err, errlen, "Spotify rechazó el acceso (%d %s%s%s)", r.status, e, d[0] ? ": " : "", d);
    goto out;
  }
  const char *acc = json_str(json_get(j, "access_token"));
  const char *ref = json_str(json_get(j, "refresh_token"));
  const char *scope = json_str(json_get(j, "scope"));
  int exp = (int)json_num(json_get(j, "expires_in"));
  if(!acc[0]) {
    snprintf(err, errlen, "Spotify no devolvió un token");
    goto out;
  }
  pthread_mutex_lock(&g_lock);
  snprintf(S.access, sizeof(S.access), "%s", acc);
  S.access_exp = time(NULL) + (exp > 120 ? exp - 60 : 300);
  if(scope[0]) snprintf(S.scopes, sizeof(S.scopes), "%s", scope);
  if(ref[0]) {
    char enc[CRYPT_SEAL_HEX + 1];
    if(cfg_seal(SP_AAD, ref, strlen(ref), enc, sizeof(enc))) {
      pthread_mutex_unlock(&g_lock);
      snprintf(err, errlen, "No se pudo guardar el token de Spotify");
      goto out;
    }
    memcpy(S.refresh_enc, enc, sizeof(enc));
    save_locked();
  }
  pthread_mutex_unlock(&g_lock);
  ret = 0;
 out:
  json_free(j);
  https_resp_free(&r);
  return ret;
}


static int
ensure_token(int force, char *err, size_t errlen) {
  char refresh[CRYPT_SEAL_MAX + 1], cid[80], f1[400], f2[120], form[700];
  int invalid;

  pthread_mutex_lock(&g_lock);
  int valid = S.access[0] && time(NULL) < S.access_exp;
  snprintf(cid, sizeof(cid), "%s", S.client_id);
  int have = S.refresh_enc[0] && !cfg_unseal(SP_AAD, S.refresh_enc, refresh, sizeof(refresh));
  pthread_mutex_unlock(&g_lock);
  if(valid && !force) return 0;
  if(!have) {
    snprintf(err, errlen, "Spotify no está conectado");
    return -1;
  }
  net_urlencode(refresh, f1, sizeof(f1));
  net_urlencode(cid, f2, sizeof(f2));
  snprintf(form, sizeof(form), "grant_type=refresh_token&refresh_token=%s&client_id=%s", f1, f2);
  memset(refresh, 0, sizeof(refresh));
  memset(f1, 0, sizeof(f1));
  int r = token_request(form, &invalid, err, errlen);
  memset(form, 0, sizeof(form));
  if(r && invalid) {
    pthread_mutex_lock(&g_lock);
    S.refresh_enc[0] = 0;
    S.access[0] = 0;
    save_locked();
    pthread_mutex_unlock(&g_lock);
    snprintf(err, errlen, "La conexión con Spotify ha caducado: vuelve a conectar la cuenta en el panel");
    notify("PS5NAS: vuelve a conectar Spotify en el panel web");
  }
  return r;
}


int
spotify_login_url(char *out, size_t outlen, char *err, size_t errlen) {
  static const char CH[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  uint8_t rnd[64], hash[32];
  char verifier[65], challenge[64], state[33], cid[160], redir[160];

  pthread_mutex_lock(&g_lock);
  if(!S.client_id[0]) {
    pthread_mutex_unlock(&g_lock);
    snprintf(err, errlen, "Primero guarda el Client ID de tu app de Spotify");
    return -1;
  }
  cfg_random(rnd, sizeof(rnd));
  for(int i=0; i<64; i++) verifier[i] = CH[rnd[i] % (sizeof(CH) - 1)];
  verifier[64] = 0;
  cfg_random_hex(state, 16);
  wc_Sha256Hash((const byte*)verifier, 64, hash);
  b64url(hash, 32, challenge);
  memcpy(S.verifier, verifier, sizeof(verifier));
  snprintf(S.state, sizeof(S.state), "%s", state);
  S.login_at = time(NULL);
  net_urlencode(S.client_id, cid, sizeof(cid));
  pthread_mutex_unlock(&g_lock);

  char scopes[200];
  net_urlencode(SP_SCOPES, scopes, sizeof(scopes));
  net_urlencode(SPOTIFY_REDIRECT_URI, redir, sizeof(redir));
  snprintf(out, outlen, "%s/authorize?client_id=%s&response_type=code&redirect_uri=%s"
           "&code_challenge_method=S256&code_challenge=%s&scope=%s&state=%s",
           accounts_base(), cid, redir, challenge, scopes, state);
  return 0;
}


/* Saca NAME=valor de una URL o de un «a=b&c=d». */
static int
query_value(const char *s, const char *name, char *out, size_t outlen) {
  size_t nl = strlen(name);
  for(const char *p = s; (p = strstr(p, name)); p++) {
    if((p == s || p[-1] == '?' || p[-1] == '&' || p[-1] == '#') && p[nl] == '=') {
      const char *v = p + nl + 1;
      size_t o = 0;
      while(*v && *v != '&' && *v != '#' && !strchr(" \r\n", *v) && o + 1 < outlen) {
        if(*v == '%' && v[1] && v[2]) {
          char h[3] = {v[1], v[2], 0};
          out[o++] = (char)strtol(h, NULL, 16);
          v += 3;
        } else {
          out[o++] = *v++;
        }
      }
      out[o] = 0;
      return 0;
    }
  }
  return -1;
}


/* GET /v1/me con el token recién obtenido. */
static int fetch_me(char *err, size_t errlen);


int
spotify_finish_login(const char *pasted, char *err, size_t errlen) {
  char code[1024] = "", state[64] = "", e[128] = "", verifier[80], cid[80];

  while(*pasted == ' ' || *pasted == '\n' || *pasted == '\r' || *pasted == '\t') pasted++;
  if(!query_value(pasted, "error", e, sizeof(e))) {
    snprintf(err, errlen, "Spotify no dio permiso (%s)", e);
    return -1;
  }
  if(query_value(pasted, "code", code, sizeof(code))) {
    if(strchr(pasted, '=') || strchr(pasted, '/') || !pasted[0]) {
      snprintf(err, errlen, "La dirección pegada no contiene «code=»");
      return -1;
    }
    snprintf(code, sizeof(code), "%s", pasted);     /* solo el código */
    code[strcspn(code, " \r\n\t")] = 0;
  }
  query_value(pasted, "state", state, sizeof(state));

  pthread_mutex_lock(&g_lock);
  int stale = !S.verifier[0] || time(NULL) - S.login_at > SP_LOGIN_TTL;
  int bad_state = state[0] && strcmp(state, S.state);
  memcpy(verifier, S.verifier, sizeof(verifier));
  memcpy(cid, S.client_id, sizeof(cid));
  pthread_mutex_unlock(&g_lock);
  if(stale) {
    snprintf(err, errlen, "El intento de conexión ha caducado: vuelve a pulsar «Conectar con Spotify»");
    return -1;
  }
  if(bad_state) {
    snprintf(err, errlen, "Esa dirección es de un intento anterior: usa la del último «Conectar»");
    return -1;
  }

  char f_code[1200], f_redir[160], f_cid[160], form[2000];
  int invalid;
  net_urlencode(code, f_code, sizeof(f_code));
  net_urlencode(SPOTIFY_REDIRECT_URI, f_redir, sizeof(f_redir));
  net_urlencode(cid, f_cid, sizeof(f_cid));
  snprintf(form, sizeof(form), "grant_type=authorization_code&code=%s&redirect_uri=%s"
           "&client_id=%s&code_verifier=%s", f_code, f_redir, f_cid, verifier);
  int r = token_request(form, &invalid, err, errlen);
  memset(form, 0, sizeof(form));
  if(r) return -1;

  pthread_mutex_lock(&g_lock);
  S.verifier[0] = S.state[0] = 0;
  S.connected_at = time(NULL);
  S.user_id[0] = 0;
  save_locked();
  pthread_mutex_unlock(&g_lock);
  if(fetch_me(err, errlen)) return -1;
  set_msg(1, "Conectado. Preparando las playlists…");
  spotify_request_sync();
  return 0;
}


void
spotify_disconnect(void) {
  pthread_mutex_lock(&g_lock);
  S.refresh_enc[0] = 0;
  S.access[0] = 0;
  S.user_id[0] = S.user_name[0] = 0;
  S.connected_at = 0;
  S.scopes[0] = 0;
  snprintf(S.message, sizeof(S.message), "Desconectado");
  save_locked();
  pthread_mutex_unlock(&g_lock);
}


/* ------------------------------------------------------------------ */
/* Web API                                                             */
/* ------------------------------------------------------------------ */

/* Petición autenticada.  Reintenta con 429 (Retry-After), 401 y 5xx.
   Devuelve 0 con 2xx; si no, -1 con ERR (y R->status relleno si hubo respuesta). */
static int
api(const char *method, const char *path, const char *json, https_resp_t *r,
    char *err, size_t errlen) {
  char url[2048], hdr[700];
  memset(r, 0, sizeof(*r));
  if(!strncmp(path, "https://", 8)) snprintf(url, sizeof(url), "%s", path);
  else snprintf(url, sizeof(url), "%s%s", api_base(), path);

  for(int attempt = 0; attempt < 5; attempt++) {
    if(ensure_token(0, err, errlen)) return -1;
    pthread_mutex_lock(&g_lock);
    snprintf(hdr, sizeof(hdr), "Authorization: Bearer %s\r\n%s", S.access,
             json ? "Content-Type: application/json\r\n" : "");
    pthread_mutex_unlock(&g_lock);
    int rc = https_request(method, url, hdr, json, json ? strlen(json) : 0, r, err, errlen);
    memset(hdr, 0, sizeof(hdr));
    if(rc) {
      if(attempt < 2) { sleep(3); continue; }
      return -1;
    }
    if(r->status >= 200 && r->status < 300) return 0;
    if(r->status == 429 && attempt < 4) {
      int wait = r->retry_after > 0 ? r->retry_after : 5;
      https_resp_free(r);
      if(wait > 120) {
        snprintf(err, errlen, "Spotify pide esperar %d s (límite de peticiones)", wait);
        return -1;
      }
      sleep((unsigned)wait);
      continue;
    }
    if(r->status == 401 && attempt == 0) {
      https_resp_free(r);
      if(ensure_token(1, err, errlen)) return -1;
      continue;
    }
    if(r->status >= 500 && attempt < 2) {
      https_resp_free(r);
      sleep(3);
      continue;
    }
    jv_t *j = json_parse(r->body, r->len);
    const char *m = json_str(json_path(j, "error.message"));
    if(r->status == 403) {
      snprintf(err, errlen, "Spotify denegó %s %s (403%s%s). ¿Está tu cuenta en la lista de "
               "usuarios de la app (modo desarrollo) y tiene Premium?", method, path,
               m[0] ? ": " : "", m);
    } else {
      snprintf(err, errlen, "Spotify respondió %d a %s %s%s%s", r->status, method, path,
               m[0] ? ": " : "", m);
    }
    json_free(j);
    return -1;
  }
  snprintf(err, errlen, "Spotify no responde");
  return -1;
}


static int
fetch_me(char *err, size_t errlen) {
  https_resp_t r;
  if(api("GET", "/v1/me", NULL, &r, err, errlen)) {
    https_resp_free(&r);
    return -1;
  }
  jv_t *j = json_parse(r.body, r.len);
  pthread_mutex_lock(&g_lock);
  snprintf(S.user_id, sizeof(S.user_id), "%s", json_str(json_get(j, "id")));
  snprintf(S.user_name, sizeof(S.user_name), "%s", json_str(json_get(j, "display_name")));
  if(!S.user_name[0]) snprintf(S.user_name, sizeof(S.user_name), "%s", S.user_id);
  save_locked();
  pthread_mutex_unlock(&g_lock);
  json_free(j);
  https_resp_free(&r);
  return 0;
}


/* Título, artistas, álbum y duración de un objeto «track». */
static void
parse_track(const jv_t *tr, lib_track_t *x) {
  snprintf(x->uri, sizeof(x->uri), "%s", json_str(json_get(tr, "uri")));
  snprintf(x->title, sizeof(x->title), "%s", json_str(json_get(tr, "name")));
  snprintf(x->album, sizeof(x->album), "%s", json_str(json_path(tr, "album.name")));
  x->duration_ms = (int)json_num(json_get(tr, "duration_ms"));
  jv_t *ar = json_get(tr, "artists");
  size_t o = 0;
  for(jv_t *a = ar ? ar->child : NULL; a && o + 3 < sizeof(x->artist); a = a->next) {
    o += (size_t)snprintf(x->artist + o, sizeof(x->artist) - o, "%s%s", o ? ", " : "",
          json_str(json_get(a, "name")));
  }
  if(o >= sizeof(x->artist)) x->artist[sizeof(x->artist) - 1] = 0;
  clean_field(x->title);
  clean_field(x->album);
  clean_field(x->artist);
}


/* «Me gusta» desde START_YM, en orden cronológico. */
static lib_track_t *
fetch_liked(int start_ym, int *count, char *err, size_t errlen) {
  char next[2048];
  lib_track_t *t = NULL;
  int n = 0, cap = 0, done = 0;
  *count = 0;
  snprintf(next, sizeof(next), "/v1/me/tracks?limit=50&offset=0");

  while(!done && next[0]) {
    https_resp_t r;
    if(api("GET", next, NULL, &r, err, errlen)) {
      https_resp_free(&r);
      free(t);
      return NULL;
    }
    jv_t *j = json_parse(r.body, r.len);
    https_resp_free(&r);
    if(!j) {
      snprintf(err, errlen, "Respuesta no válida de Spotify (me/tracks)");
      free(t);
      return NULL;
    }
    jv_t *items = json_get(j, "items");
    for(jv_t *it = items ? items->child : NULL; it && !done; it = it->next) {
      const char *added = json_str(json_get(it, "added_at"));
      int ym = parse_ym(added);
      if(ym < 0) continue;
      if(ym < start_ym) { done = 1; break; }   /* vienen de la más nueva a la más antigua */
      jv_t *tr = json_get(it, "track");
      if(!tr || tr->type != J_OBJ) tr = json_get(it, "item");
      const char *uri = json_str(json_get(tr, "uri"));
      if(strncmp(uri, "spotify:track:", 14)) continue;   /* archivos locales, episodios... */
      if(n == cap) {
        cap = cap ? cap * 2 : 512;
        lib_track_t *nt = realloc(t, (size_t)cap * sizeof(*nt));
        if(!nt) { done = 1; break; }
        t = nt;
      }
      lib_track_t *x = &t[n++];
      memset(x, 0, sizeof(*x));
      x->ym = ym;
      snprintf(x->added_at, sizeof(x->added_at), "%s", added);
      snprintf(x->uri, sizeof(x->uri), "%s", uri);
      parse_track(tr, x);
      if(n >= SP_MAX_TRACKS) done = 1;
    }
    snprintf(next, sizeof(next), "%s", json_str(json_get(j, "next")));
    json_free(j);
  }
  /* de la más antigua a la más nueva */
  for(int i=0; i<n/2; i++) {
    lib_track_t tmp = t[i];
    t[i] = t[n-1-i];
    t[n-1-i] = tmp;
  }
  *count = n;
  return t;
}


typedef struct named { char name[160]; char id[64]; } named_t;


/* Playlists del usuario (para adoptar las «pl M/AAAA» que ya existan). */
static named_t *
fetch_playlists(int *count, char *err, size_t errlen) {
  char next[2048];
  named_t *v = NULL;
  int n = 0, cap = 0;
  *count = 0;
  snprintf(next, sizeof(next), "/v1/me/playlists?limit=50&offset=0");
  while(next[0] && n < 5000) {
    https_resp_t r;
    if(api("GET", next, NULL, &r, err, errlen)) {
      https_resp_free(&r);
      free(v);
      return NULL;
    }
    jv_t *j = json_parse(r.body, r.len);
    https_resp_free(&r);
    jv_t *items = json_get(j, "items");
    for(jv_t *it = items ? items->child : NULL; it; it = it->next) {
      const char *name = json_str(json_get(it, "name"));
      if(strncmp(name, "pl ", 3) && strncmp(name, "top ", 4)) continue;
      if(n == cap) {
        cap = cap ? cap * 2 : 64;
        named_t *nv = realloc(v, (size_t)cap * sizeof(*nv));
        if(!nv) break;
        v = nv;
      }
      snprintf(v[n].name, sizeof(v[n].name), "%s", name);
      snprintf(v[n].id, sizeof(v[n].id), "%s", json_str(json_get(it, "id")));
      n++;
    }
    snprintf(next, sizeof(next), "%s", json_str(json_get(j, "next")));
    json_free(j);
  }
  *count = n;
  return v;
}


static int
create_playlist(int ym, char *id, size_t idlen, char *err, size_t errlen) {
  char body[512];
  https_resp_t r;
  int y = ym / 12, m = ym % 12 + 1;
  snprintf(body, sizeof(body),
           "{\"name\":\"pl %d/%d\",\"public\":false,"
           "\"description\":\"Canciones que añadí a Me gusta en %s de %d (PS5NAS)\"}",
           m, y, lib_month_name(m), y);
  if(api("POST", "/v1/me/playlists", body, &r, err, errlen)) {
    https_resp_free(&r);
    return -1;
  }
  jv_t *j = json_parse(r.body, r.len);
  snprintf(id, idlen, "%s", json_str(json_get(j, "id")));
  json_free(j);
  https_resp_free(&r);
  if(!id[0]) {
    snprintf(err, errlen, "Spotify no devolvió el id de la playlist nueva");
    return -1;
  }
  LOG_PRINTF("ps5share: playlist «pl %d/%d» creada\n", m, y);
  return 0;
}


/* URIs que ya tiene la playlist.  *GONE = 1 si ya no existe. */
static char **
playlist_uris(const char *id, int *count, int *gone, char *err, size_t errlen) {
  char next[2048];
  char **v = NULL;
  int n = 0, cap = 0;
  *count = 0;
  *gone = 0;
  snprintf(next, sizeof(next), "/v1/playlists/%s/items?limit=100&offset=0", id);
  while(next[0]) {
    https_resp_t r;
    if(api("GET", next, NULL, &r, err, errlen)) {
      if(r.status == 404) *gone = 1;
      https_resp_free(&r);
      for(int i=0; i<n; i++) free(v[i]);
      free(v);
      return NULL;
    }
    jv_t *j = json_parse(r.body, r.len);
    https_resp_free(&r);
    jv_t *items = json_get(j, "items");
    for(jv_t *it = items ? items->child : NULL; it; it = it->next) {
      jv_t *tr = json_get(it, "item");
      if(!tr || tr->type != J_OBJ) tr = json_get(it, "track");
      const char *uri = json_str(json_get(tr, "uri"));
      if(!uri[0]) continue;
      if(n == cap) {
        cap = cap ? cap * 2 : 128;
        char **nv = realloc(v, (size_t)cap * sizeof(*nv));
        if(!nv) break;
        v = nv;
      }
      v[n++] = strdup(uri);
    }
    snprintf(next, sizeof(next), "%s", json_str(json_get(j, "next")));
    json_free(j);
  }
  *count = n;
  return v;
}


static int
add_items(const char *id, const char **uris, int n, char *err, size_t errlen) {
  for(int i=0; i<n; i += 100) {
    jb_t b = {0};
    char path[160];
    jb_printf(&b, "{\"uris\":[");
    for(int k=i; k<n && k<i+100; k++) jb_printf(&b, "%s\"%s\"", k > i ? "," : "", uris[k]);
    jb_printf(&b, "]}");
    snprintf(path, sizeof(path), "/v1/playlists/%s/items", id);
    https_resp_t r = {0};
    int rc = b.p ? api("POST", path, b.p, &r, err, errlen) : -1;
    https_resp_free(&r);
    free(b.p);
    if(rc) return -1;
  }
  return 0;
}


/* ------------------------------------------------------------------ */
/* Lo más escuchado del mes                                            */
/* ------------------------------------------------------------------ */
/* La Web API no da escuchas por mes: /me/player/recently-played solo
   devuelve las 50 últimas.  Se consulta cada 20 minutos y se guardan en
   spotify-plays.tsv para contarlas.  Si faltan datos (la consola estuvo
   apagada), se completa con /me/top/tracks?time_range=short_term (unas 4
   semanas) tomado durante ese mes.  */

typedef struct play {
  long long   ms;
  lib_track_t t;
} play_t;


static int
ym_of_ms(long long ms) {
  time_t t = (time_t)(ms / 1000);
  struct tm tm;
  gmtime_r(&t, &tm);
  return (tm.tm_year + 1900) * 12 + tm.tm_mon;
}


static int
current_ym(void) {
  return ym_of_ms((long long)time(NULL) * 1000);
}


/* "2026-11-15T20:01:02.123Z" -> milisegundos */
static long long
iso_ms(const char *s) {
  struct tm tm = {0};
  int ms = 0;
  if(sscanf(s, "%d-%d-%dT%d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
            &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) return -1;
  const char *dot = strchr(s, '.');
  if(dot) {
    int d = 0;
    for(const char *p = dot + 1; *p >= '0' && *p <= '9' && d < 3; p++, d++) ms = ms * 10 + (*p - '0');
    while(d++ < 3) ms *= 10;
  }
  tm.tm_year -= 1900;
  tm.tm_mon -= 1;
  return (long long)timegm(&tm) * 1000 + ms;
}


static play_t *
load_plays(int *count) {
  char path[PATH_MAX], line[2048];
  play_t *v = NULL;
  int n = 0, cap = 0;
  *count = 0;
  snprintf(path, sizeof(path), "%s/spotify-plays.tsv", g_dir);
  FILE *f = fopen(path, "r");
  if(!f) return NULL;
  while(fgets(line, sizeof(line), f) && n < 200000) {
    line[strcspn(line, "\r\n")] = 0;
    char *fld[6] = {0};
    int k = 0;
    for(char *p = line, *x; k < 6 && (x = strsep(&p, "\t")); ) fld[k++] = x;
    if(k < 6) continue;
    if(n == cap) {
      cap = cap ? cap * 2 : 1024;
      play_t *nv = realloc(v, (size_t)cap * sizeof(*nv));
      if(!nv) break;
      v = nv;
    }
    play_t *x = &v[n++];
    memset(x, 0, sizeof(*x));
    x->ms = atoll(fld[0]);
    x->t.ym = ym_of_ms(x->ms);
    snprintf(x->t.uri, sizeof(x->t.uri), "%s", fld[1]);
    x->t.duration_ms = atoi(fld[2]);
    snprintf(x->t.artist, sizeof(x->t.artist), "%s", fld[3]);
    snprintf(x->t.title, sizeof(x->t.title), "%s", fld[4]);
    snprintf(x->t.album, sizeof(x->t.album), "%s", fld[5]);
  }
  fclose(f);
  *count = n;
  return v;
}


static int
save_plays(const play_t *v, int n) {
  char path[PATH_MAX], tmp[PATH_MAX + 8];
  snprintf(path, sizeof(path), "%s/spotify-plays.tsv", g_dir);
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE *f = fopen(tmp, "w");
  if(!f) return -1;
  for(int i=0; i<n; i++) {
    fprintf(f, "%lld\t%s\t%d\t%s\t%s\t%s\n", v[i].ms, v[i].t.uri, v[i].t.duration_ms,
            v[i].t.artist, v[i].t.title, v[i].t.album);
  }
  if(fclose(f) || rename(tmp, path)) { LOG_PERROR(path); return -1; }
  return 0;
}


/* Guarda las escuchas nuevas.  Devuelve cuántas o -1. */
static int
poll_history(char *err, size_t errlen) {
  https_resp_t r;
  if(api("GET", "/v1/me/player/recently-played?limit=50", NULL, &r, err, errlen)) {
    https_resp_free(&r);
    return -1;
  }
  jv_t *j = json_parse(r.body, r.len);
  https_resp_free(&r);
  if(!j) {
    snprintf(err, errlen, "Respuesta no válida de Spotify (recently-played)");
    return -1;
  }
  pthread_mutex_lock(&g_lock);
  long long last = S.hist_last_ms;
  pthread_mutex_unlock(&g_lock);

  play_t fresh[50];
  int nf = 0;
  jv_t *items = json_get(j, "items");
  for(jv_t *it = items ? items->child : NULL; it && nf < 50; it = it->next) {
    long long ms = iso_ms(json_str(json_get(it, "played_at")));
    jv_t *tr = json_get(it, "track");
    if(!tr || tr->type != J_OBJ) tr = json_get(it, "item");
    if(ms <= last || !tr) continue;
    play_t *x = &fresh[nf];
    memset(x, 0, sizeof(*x));
    x->ms = ms;
    parse_track(tr, &x->t);
    if(strncmp(x->t.uri, "spotify:track:", 14)) continue;
    nf++;
  }
  json_free(j);
  if(!nf) return 0;

  int n;
  play_t *all = load_plays(&n);
  play_t *nv = realloc(all, (size_t)(n + nf) * sizeof(play_t));
  if(!nv) {
    free(all);
    snprintf(err, errlen, "Sin memoria");
    return -1;
  }
  all = nv;
  long long newest = last, cut = (long long)time(NULL) * 1000 - SP_HIST_KEEP;
  int o = 0;
  for(int i=0; i<n; i++) if(all[i].ms >= cut) all[o++] = all[i];
  /* vienen de la más nueva a la más antigua */
  for(int i=nf-1; i>=0; i--) {
    all[o++] = fresh[i];
    if(fresh[i].ms > newest) newest = fresh[i].ms;
  }
  int rc = save_plays(all, o);
  free(all);
  if(rc) {
    snprintf(err, errlen, "No se pudo guardar el historial de escuchas");
    return -1;
  }
  pthread_mutex_lock(&g_lock);
  S.hist_last_ms = newest;
  save_locked();
  pthread_mutex_unlock(&g_lock);
  return nf;
}


/* Top de ~4 semanas según Spotify; se guarda una foto por mes (la última de ese mes). */
static int
snapshot_top(char *err, size_t errlen) {
  https_resp_t r;
  char path[PATH_MAX], tmp[PATH_MAX + 8];
  if(api("GET", "/v1/me/top/tracks?time_range=short_term&limit=50", NULL, &r, err, errlen)) {
    https_resp_free(&r);
    return -1;
  }
  jv_t *j = json_parse(r.body, r.len);
  https_resp_free(&r);
  jv_t *items = json_get(j, "items");
  if(!items) {
    json_free(j);
    snprintf(err, errlen, "Respuesta no válida de Spotify (top/tracks)");
    return -1;
  }
  int cur = current_ym();
  snprintf(path, sizeof(path), "%s/spotify-top-%04d-%02d.tsv", g_dir, cur / 12, cur % 12 + 1);
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE *f = fopen(tmp, "w");
  if(!f) {
    json_free(j);
    return -1;
  }
  fprintf(f, "ym\t%d\n", cur);
  for(jv_t *it = items->child; it; it = it->next) {
    lib_track_t x;
    memset(&x, 0, sizeof(x));
    parse_track(it, &x);
    if(strncmp(x.uri, "spotify:track:", 14)) continue;
    fprintf(f, "%s\t%d\t%s\t%s\t%s\n", x.uri, x.duration_ms, x.artist, x.title, x.album);
  }
  json_free(j);
  if(fclose(f) || rename(tmp, path)) return -1;
  return 0;
}


/* Top tomado durante el mes YM (NULL si no hay). */
static lib_track_t *
load_snapshot(int ym, int *count) {
  char path[PATH_MAX], line[2048];
  lib_track_t *v = NULL;
  int n = 0;
  *count = 0;
  snprintf(path, sizeof(path), "%s/spotify-top-%04d-%02d.tsv", g_dir, ym / 12, ym % 12 + 1);
  FILE *f = fopen(path, "r");
  if(!f) return NULL;
  if(!fgets(line, sizeof(line), f) || strncmp(line, "ym\t", 3) || atoi(line + 3) != ym ||
     !(v = calloc(50, sizeof(*v)))) {
    fclose(f);
    return NULL;
  }
  while(n < 50 && fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\r\n")] = 0;
    char *fld[5] = {0};
    int k = 0;
    for(char *p = line, *x; k < 5 && (x = strsep(&p, "\t")); ) fld[k++] = x;
    if(k < 5) continue;
    lib_track_t *x = &v[n++];
    x->ym = ym;
    snprintf(x->uri, sizeof(x->uri), "%s", fld[0]);
    x->duration_ms = atoi(fld[1]);
    snprintf(x->artist, sizeof(x->artist), "%s", fld[2]);
    snprintf(x->title, sizeof(x->title), "%s", fld[3]);
    snprintf(x->album, sizeof(x->album), "%s", fld[4]);
  }
  fclose(f);
  *count = n;
  return v;
}


typedef struct agg {
  lib_track_t t;
  int         count;
  int         snap;      /* puesto en el top de Spotify (999 = no está) */
  long long   last;
} agg_t;


static int
agg_cmp(const void *a, const void *b) {
  const agg_t *x = a, *y = b;
  if(x->count != y->count) return y->count - x->count;
  if(x->snap != y->snap) return x->snap - y->snap;
  return (y->last > x->last) - (y->last < x->last);
}


/* Ranking del mes YM con PLAYS (todas) y la foto del top de ese mes.
   Devuelve hasta SIZE canciones (malloc) y en *NPLAYS las escuchas del mes. */
static lib_track_t *
rank_month(int ym, int size, const play_t *plays, int np, int *count, int *nplays) {
  int ns;
  lib_track_t *snap = load_snapshot(ym, &ns);
  agg_t *a = calloc((size_t)(np + ns + 1), sizeof(*a));
  int na = 0, pc = 0;
  *count = 0;
  if(!a) {
    free(snap);
    return NULL;
  }
  for(int i=0; i<np; i++) {
    if(plays[i].t.ym != ym) continue;
    pc++;
    int k;
    for(k=0; k<na && strcmp(a[k].t.uri, plays[i].t.uri); k++) {}
    if(k == na) {
      a[na].t = plays[i].t;
      a[na].snap = 999;
      na++;
    }
    a[k].count++;
    if(plays[i].ms > a[k].last) a[k].last = plays[i].ms;
  }
  for(int i=0; i<ns; i++) {
    int k;
    for(k=0; k<na && strcmp(a[k].t.uri, snap[i].uri); k++) {}
    if(k == na) {
      a[na].t = snap[i];
      na++;
    }
    a[k].snap = i;
  }
  free(snap);
  qsort(a, (size_t)na, sizeof(*a), agg_cmp);
  if(na > size) na = size;
  lib_track_t *out = calloc((size_t)(na ? na : 1), sizeof(*out));
  for(int i=0; out && i<na; i++) {
    out[i] = a[i].t;
    out[i].ym = ym;
  }
  free(a);
  *count = out ? na : 0;
  *nplays = pc;
  return out;
}


static uint32_t
list_hash(const lib_track_t *t, int n) {
  uint32_t h = 2166136261u;
  for(int i=0; i<n; i++) {
    for(const char *p = t[i].uri; *p; p++) h = (h ^ (uint8_t)*p) * 16777619u;
    h = (h ^ ',') * 16777619u;
  }
  return h ? h : 1;
}


/* Sustituye el contenido de la playlist (máx. 100). */
static int
replace_items(const char *id, const lib_track_t *t, int n, int *gone, char *err, size_t errlen) {
  jb_t b = {0};
  char path[160];
  https_resp_t r = {0};
  jb_printf(&b, "{\"uris\":[");
  for(int i=0; i<n && i<100; i++) jb_printf(&b, "%s\"%s\"", i ? "," : "", t[i].uri);
  jb_printf(&b, "]}");
  snprintf(path, sizeof(path), "/v1/playlists/%s/items", id);
  int rc = b.p ? api("PUT", path, b.p, &r, err, errlen) : -1;
  *gone = rc && r.status == 404;
  https_resp_free(&r);
  free(b.p);
  return rc;
}


static int
create_named(const char *name, const char *desc, char *id, size_t idlen, char *err, size_t errlen) {
  jb_t b = {0};
  https_resp_t r;
  jb_printf(&b, "{\"name\":");
  jb_str(&b, name);
  jb_printf(&b, ",\"public\":false,\"description\":");
  jb_str(&b, desc);
  jb_printf(&b, "}");
  int rc = b.p ? api("POST", "/v1/me/playlists", b.p, &r, err, errlen) : -1;
  free(b.p);
  if(rc) {
    https_resp_free(&r);
    return -1;
  }
  jv_t *j = json_parse(r.body, r.len);
  snprintf(id, idlen, "%s", json_str(json_get(j, "id")));
  json_free(j);
  https_resp_free(&r);
  if(!id[0]) {
    snprintf(err, errlen, "Spotify no devolvió el id de la playlist nueva");
    return -1;
  }
  LOG_PRINTF("ps5share: playlist «%s» creada\n", name);
  return 0;
}


/* Crea o actualiza las «top M/AAAA».  Los meses pasados se cierran. */
static int
sync_tops(char *err, size_t errlen) {
  int np, cur = current_ym(), ret = 0, npl = 0, fetched = 0;
  named_t *pls = NULL;
  play_t *plays = load_plays(&np);

  pthread_mutex_lock(&g_lock);
  int size = S.top_size, start = S.start_ym;
  /* meses con escuchas y el actual */
  if(cur >= start) top_get_locked(cur, 1);
  for(int i=0; i<np; i++) if(plays[i].t.ym >= start) top_get_locked(plays[i].t.ym, 1);
  int nt = S.ntops;
  sp_top_t tops[SP_MAX_MONTHS];
  memcpy(tops, S.tops, (size_t)nt * sizeof(sp_top_t));
  pthread_mutex_unlock(&g_lock);

  for(int i=0; i<nt; i++) {
    sp_top_t *t = &tops[i];
    if(t->final || t->ym < start) continue;
    int n, pc;
    lib_track_t *list = rank_month(t->ym, size, plays, np, &n, &pc);
    if(!list) continue;
    if(!n) {           /* aún nada que poner */
      free(list);
      continue;
    }
    int y = t->ym / 12, m = t->ym % 12 + 1;
    char name[40], desc[200];
    snprintf(name, sizeof(name), "top %d/%d", m, y);
    snprintf(desc, sizeof(desc), "Mis %d canciones más escuchadas en %s de %d (PS5NAS)", n,
             lib_month_name(m), y);
    uint32_t h = list_hash(list, n);
    int rc = 0, gone = 0;
    if(!t->pid[0]) {
      if(!fetched) {
        pls = fetch_playlists(&npl, err, errlen);
        if(!pls && err[0]) { free(list); ret = -1; break; }
        fetched = 1;
      }
      for(int k=0; k<npl; k++) if(!strcmp(pls[k].name, name)) { snprintf(t->pid, sizeof(t->pid), "%s", pls[k].id); break; }
      if(!t->pid[0]) rc = create_named(name, desc, t->pid, sizeof(t->pid), err, errlen);
      t->hash = 0;
    }
    if(!rc && h != t->hash) {
      rc = replace_items(t->pid, list, n, &gone, err, errlen);
      if(rc && gone) {         /* la borraron: se vuelve a crear */
        err[0] = 0;
        t->pid[0] = 0;
        rc = create_named(name, desc, t->pid, sizeof(t->pid), err, errlen);
        if(!rc) rc = replace_items(t->pid, list, n, &gone, err, errlen);
      }
      if(!rc) {
        t->hash = h;
        LOG_PRINTF("ps5share: «%s» actualizada (%d canciones)\n", name, n);
      }
    }
    free(list);
    if(rc) { ret = -1; break; }
    if(t->ym < cur) t->final = 1;

    pthread_mutex_lock(&g_lock);
    sp_top_t *st = top_get_locked(t->ym, 1);
    if(st) {
      snprintf(st->pid, sizeof(st->pid), "%s", t->pid);
      st->hash = t->hash;
      st->final = t->final;
    }
    save_locked();
    pthread_mutex_unlock(&g_lock);
  }
  free(pls);
  free(plays);
  return ret;
}


/* Escuchas + top + playlists.  No interrumpe la sincronización principal. */
static void
top_pass(int full) {
  char err[512] = "";
  pthread_mutex_lock(&g_lock);
  int on = S.top_enabled, scope = top_scope_ok_locked(), conn = S.refresh_enc[0] != 0;
  pthread_mutex_unlock(&g_lock);
  if(!on || !conn) return;
  if(!scope) {
    pthread_mutex_lock(&g_lock);
    snprintf(S.top_msg, sizeof(S.top_msg), "Falta permiso: pulsa «Volver a conectar» para activar lo más escuchado");
    pthread_mutex_unlock(&g_lock);
    return;
  }
  int got = poll_history(err, sizeof(err));
  pthread_mutex_lock(&g_lock);
  S.hist_at = time(NULL);
  pthread_mutex_unlock(&g_lock);
  if(got >= 0 && full && !snapshot_top(err, sizeof(err)) && !sync_tops(err, sizeof(err))) err[0] = 0;
  pthread_mutex_lock(&g_lock);
  snprintf(S.top_msg, sizeof(S.top_msg), "%s", got >= 0 && !err[0] ? "OK" : err);
  pthread_mutex_unlock(&g_lock);
  if(err[0]) LOG_PRINTF("ps5share: Spotify (lo más escuchado): %s\n", err);
}


/* ------------------------------------------------------------------ */
/* Sincronización                                                      */
/* ------------------------------------------------------------------ */

static void
library_pass(void) {
  char dir[PATH_MAX];
  int n, nm;
  lib_month_t *months;

  pthread_mutex_lock(&g_lock);
  snprintf(dir, sizeof(dir), "%s", S.music_dir);
  nm = S.nmonths;
  months = calloc((size_t)(nm ? nm : 1), sizeof(*months));
  for(int i=0; months && i<nm; i++) months[i].ym = S.months[i].ym;
  pthread_mutex_unlock(&g_lock);
  if(!months) return;

  int moved = lib_ingest(dir);
  if(moved) LOG_PRINTF("ps5share: %d canciones nuevas colocadas en %s\n", moved, dir);
  lib_track_t *t = load_tracks(&n);

  /* listas «top» */
  int np, ntop = 0, size;
  play_t *plays = load_plays(&np);
  pthread_mutex_lock(&g_lock);
  int nt = S.top_enabled ? S.ntops : 0, start = S.start_ym;
  size = S.top_size;
  int tym[SP_MAX_MONTHS];
  for(int i=0; i<nt; i++) tym[i] = S.tops[i].ym;
  pthread_mutex_unlock(&g_lock);
  lib_list_t *lists = calloc((size_t)(nt ? nt : 1), sizeof(*lists));
  int *tplays = calloc((size_t)(nt ? nt : 1), sizeof(int));
  for(int i=0; lists && tplays && i<nt; i++) {
    if(tym[i] < start) continue;
    int c, pc;
    lib_track_t *list = rank_month(tym[i], size, plays, np, &c, &pc);
    if(!list) continue;
    lib_list_t *l = &lists[ntop];
    int y = tym[i] / 12, m = tym[i] % 12 + 1;
    snprintf(l->file, sizeof(l->file), "Top %04d-%02d %s %d", y, m, lib_month_name(m), y);
    snprintf(l->title, sizeof(l->title), "top %d/%d", m, y);
    l->tracks = list;
    l->n = c;
    tplays[ntop] = pc;
    ntop++;
  }
  free(plays);

  if(lib_build(dir, t, n, months, nm, lists, ntop)) {
    for(int i=0; i<ntop; i++) lists[i].have = 0;
    /* sin carpeta de música (¿USB desconectado?): al menos los totales */
    for(int i=0; i<nm; i++) {
      months[i].total = months[i].have = 0;
      for(int k=0; k<n; k++) months[i].total += t[k].ym == months[i].ym;
    }
  }
  {
    pthread_mutex_lock(&g_lock);
    for(int i=0; i<nm; i++) {
      sp_month_t *m = month_get_locked(months[i].ym, 0);
      if(m) { m->total = months[i].total; m->have = months[i].have; }
    }
    for(int i=0; i<ntop; i++) {
      int y, mo;
      sscanf(lists[i].title, "top %d/%d", &mo, &y);
      sp_top_t *tp = top_get_locked(y * 12 + mo - 1, 0);
      if(tp) { tp->n = lists[i].n; tp->have = lists[i].have; tp->plays = tplays[i]; }
    }
    pthread_mutex_unlock(&g_lock);
  }
  for(int i=0; lists && i<ntop; i++) free((void*)lists[i].tracks);
  free(lists);
  free(tplays);
  free(t);
  free(months);
}


static int
do_sync(char *err, size_t errlen) {
  int n = 0, npl = 0, added = 0, ret = -1, fetched_pl = 0;
  named_t *pls = NULL;

  pthread_mutex_lock(&g_lock);
  int start = S.start_ym;
  int need_me = !S.user_id[0];
  pthread_mutex_unlock(&g_lock);

  if(need_me && fetch_me(err, errlen)) return -1;
  lib_track_t *t = fetch_liked(start, &n, err, errlen);
  if(!t && n == 0 && err[0]) return -1;
  save_tracks(t, n);

  /* meses con canciones */
  for(int i=0; i<n; ) {
    int ym = t[i].ym, j = i;
    while(j < n && t[j].ym == ym) j++;
    int cnt = j - i;

    char pid[64];
    int synced;
    pthread_mutex_lock(&g_lock);
    sp_month_t *m = month_get_locked(ym, 1);
    snprintf(pid, sizeof(pid), "%s", m ? m->pid : "");
    synced = m ? m->synced : 0;
    pthread_mutex_unlock(&g_lock);
    if(!m) break;
    if(pid[0] && synced == cnt) { i = j; continue; }   /* nada nuevo ese mes */

    int y = ym / 12, mo = ym % 12 + 1;
    if(!pid[0]) {
      char want[40];
      snprintf(want, sizeof(want), "pl %d/%d", mo, y);
      if(!fetched_pl) {
        pls = fetch_playlists(&npl, err, errlen);
        if(!pls && err[0]) goto out;
        fetched_pl = 1;
      }
      for(int k=0; k<npl; k++) if(!strcmp(pls[k].name, want)) { snprintf(pid, sizeof(pid), "%s", pls[k].id); break; }
      if(pid[0]) {
        LOG_PRINTF("ps5share: adoptada la playlist existente «%s»\n", want);
      } else if(create_playlist(ym, pid, sizeof(pid), err, errlen)) goto out;
    }

    int have_n = 0, gone = 0;
    char **have = playlist_uris(pid, &have_n, &gone, err, errlen);
    if(!have && gone) {
      /* la borraron en Spotify: se vuelve a crear */
      err[0] = 0;
      if(create_playlist(ym, pid, sizeof(pid), err, errlen)) goto out;
    } else if(!have && err[0]) {
      goto out;
    }
    const char **missing = calloc((size_t)cnt, sizeof(char*));
    int nmiss = 0;
    for(int k=i; missing && k<j; k++) {
      int found = 0;
      for(int h=0; h<have_n && !found; h++) found = !strcmp(have[h], t[k].uri);
      for(int h=0; h<nmiss && !found; h++) found = !strcmp(missing[h], t[k].uri);
      if(!found) missing[nmiss++] = t[k].uri;
    }
    for(int h=0; h<have_n; h++) free(have[h]);
    free(have);
    int rc = missing ? add_items(pid, missing, nmiss, err, errlen) : -1;
    free(missing);
    if(rc) goto out;
    added += nmiss;
    if(nmiss) LOG_PRINTF("ps5share: %d canciones añadidas a «pl %d/%d»\n", nmiss, mo, y);

    pthread_mutex_lock(&g_lock);
    m = month_get_locked(ym, 1);
    if(m) {
      snprintf(m->pid, sizeof(m->pid), "%s", pid);
      m->synced = cnt;
    }
    save_locked();
    pthread_mutex_unlock(&g_lock);
    i = j;
  }
  if(added) notify("Spotify: %d canción%s nueva%s en tus playlists mensuales", added,
                   added == 1 ? "" : "es", added == 1 ? "" : "s");
  snprintf(err, errlen, "%d canciones en «Me gusta» desde el inicio; %d añadidas ahora", n, added);
  ret = 0;
 out:
  free(pls);
  free(t);
  return ret;
}


static void*
sync_thread(void *arg) {
  (void)arg;
  time_t last_lib = 0, last_hist = 0;
  for(;;) {
    pthread_mutex_lock(&g_lock);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 30;
    if(!S.want_sync) pthread_cond_timedwait(&g_wake, &g_lock, &ts);
    time_t now = time(NULL);
    int connected = S.refresh_enc[0] != 0;
    int run = S.want_sync || (S.enabled && connected && S.client_id[0] && now >= S.next_sync);
    S.want_sync = 0;
    if(run) S.syncing = 1;
    pthread_mutex_unlock(&g_lock);

    if(run) {
      char msg[512] = "";
      int rc = connected ? do_sync(msg, sizeof(msg))
                         : (snprintf(msg, sizeof(msg), "Spotify no está conectado"), -1);
      if(rc) LOG_PRINTF("ps5share: Spotify: %s\n", msg);
      pthread_mutex_lock(&g_lock);
      S.syncing = 0;
      S.last_sync = time(NULL);
      S.next_sync = S.last_sync + (rc ? SP_RETRY_FAIL : S.interval_h * 3600);
      S.last_ok = !rc;
      snprintf(S.message, sizeof(S.message), "%s", msg);
      save_locked();
      pthread_mutex_unlock(&g_lock);
    }
    if(run || now - last_hist >= SP_HIST_EVERY) {
      top_pass(run);
      last_hist = time(NULL);
    }
    if(run || now - last_lib >= SP_LIB_EVERY) {
      library_pass();
      last_lib = time(NULL);
    }
  }
  return NULL;
}


/* ------------------------------------------------------------------ */
/* Interfaz pública                                                    */
/* ------------------------------------------------------------------ */

int
spotify_init(const char *confdir) {
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);

  snprintf(g_dir, sizeof(g_dir), "%s", confdir);
  pthread_mutex_lock(&g_lock);
  S.start_ym = (tm.tm_year + 1900) * 12 + tm.tm_mon;
  snprintf(S.music_dir, sizeof(S.music_dir), "%s", SPOTIFY_DEFAULT_DIR);
  S.interval_h = 1;
  S.enabled = 1;
  S.top_enabled = 1;
  S.top_size = 50;
  load();
  S.next_sync = S.last_sync + 60;    /* tras arrancar, en cuanto haya red */
  pthread_mutex_unlock(&g_lock);

  pthread_t t;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, 1024 * 1024);
  int r = pthread_create(&t, &attr, sync_thread, NULL);
  pthread_attr_destroy(&attr);
  return r ? -1 : 0;
}


void
spotify_request_sync(void) {
  pthread_mutex_lock(&g_lock);
  S.want_sync = 1;
  pthread_cond_signal(&g_wake);
  pthread_mutex_unlock(&g_lock);
}


int
spotify_configure(const char *client_id, const char *start, const char *music_dir,
                  int interval_h, int enabled, int top_enabled, int top_size,
                  char *err, size_t errlen) {
  int ym = -1;
  if(start && start[0] && (ym = parse_ym(start)) < 0) {
    snprintf(err, errlen, "Mes de inicio no válido (usa AAAA-MM)");
    return -1;
  }
  if(client_id) {
    for(const char *p = client_id; *p; p++) {
      if(!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9'))) {
        snprintf(err, errlen, "El Client ID solo lleva letras y números");
        return -1;
      }
    }
    if(strlen(client_id) >= sizeof(S.client_id)) {
      snprintf(err, errlen, "Client ID demasiado largo");
      return -1;
    }
  }
  if(music_dir && (music_dir[0] != '/' || strstr(music_dir, "/../") || strlen(music_dir) >= PATH_MAX - 64)) {
    snprintf(err, errlen, "La carpeta de música debe ser una ruta absoluta");
    return -1;
  }
  if(top_size >= 0 && (top_size < 5 || top_size > 100)) {
    snprintf(err, errlen, "El top debe tener entre 5 y 100 canciones");
    return -1;
  }
  if(interval_h == 0 || interval_h > 24 * 7) {
    snprintf(err, errlen, "Intervalo no válido (1 a 168 horas)");
    return -1;
  }

  pthread_mutex_lock(&g_lock);
  if(client_id && strcmp(client_id, S.client_id)) {
    /* otra app: el token anterior ya no vale */
    snprintf(S.client_id, sizeof(S.client_id), "%s", client_id);
    S.refresh_enc[0] = 0;
    S.access[0] = 0;
    S.user_id[0] = S.user_name[0] = 0;
    S.scopes[0] = 0;
  }
  if(ym >= 0 && ym != S.start_ym) {
    S.start_ym = ym;
    for(int i=0; i<S.nmonths; i++) S.months[i].synced = 0;  /* recomprobar */
  }
  if(music_dir && music_dir[0]) {
    snprintf(S.music_dir, sizeof(S.music_dir), "%s", music_dir);
    size_t l = strlen(S.music_dir);
    while(l > 1 && S.music_dir[l-1] == '/') S.music_dir[--l] = 0;
  }
  if(interval_h > 0) {
    S.interval_h = interval_h;
    S.next_sync = S.last_sync + interval_h * 3600;
  }
  if(enabled >= 0) S.enabled = enabled;
  if(top_enabled >= 0) S.top_enabled = top_enabled;
  if(top_size > 0 && top_size != S.top_size) {
    S.top_size = top_size;
    for(int i=0; i<S.ntops; i++) if(!S.tops[i].final) S.tops[i].hash = 0;
  }
  save_locked();
  pthread_mutex_unlock(&g_lock);
  return 0;
}


char *
spotify_status_json(void) {
  jb_t b = {0};
  struct stat st;
  pthread_mutex_lock(&g_lock);
  int music_ok = !stat(S.music_dir, &st) && S_ISDIR(st.st_mode);
  int connected = S.refresh_enc[0] != 0;
  jb_printf(&b, "{\"client_id\":");
  jb_str(&b, S.client_id);
  jb_printf(&b, ",\"redirect_uri\":");
  jb_str(&b, SPOTIFY_REDIRECT_URI);
  jb_printf(&b, ",\"connected\":%s,\"user\":", connected ? "true" : "false");
  jb_str(&b, S.user_name);
  jb_printf(&b, ",\"start\":\"%04d-%02d\",\"music_dir\":", S.start_ym / 12, S.start_ym % 12 + 1);
  jb_str(&b, S.music_dir);
  jb_printf(&b, ",\"music_ok\":%s,\"interval\":%d,\"enabled\":%s,\"syncing\":%s,"
            "\"last_sync\":%lld,\"next_sync\":%lld,\"expires\":%lld,\"ok\":%s,\"message\":",
            music_ok ? "true" : "false", S.interval_h, S.enabled ? "true" : "false",
            S.syncing ? "true" : "false", (long long)S.last_sync, (long long)S.next_sync,
            connected && S.connected_at ? (long long)(S.connected_at + SP_REFRESH_LIFE) : 0LL,
            S.last_ok ? "true" : "false");
  jb_str(&b, S.message);
  jb_printf(&b, ",\"months\":[");
  int first = 1;
  for(int i=S.nmonths - 1; i>=0; i--) {
    const sp_month_t *m = &S.months[i];
    if(m->ym < S.start_ym) continue;
    jb_printf(&b, "%s{\"month\":\"%04d-%02d\",\"name\":\"pl %d/%d\",\"label\":\"%s %d\",\"playlist\":",
              first ? "" : ",", m->ym / 12, m->ym % 12 + 1, m->ym % 12 + 1, m->ym / 12,
              lib_month_name(m->ym % 12 + 1), m->ym / 12);
    jb_str(&b, m->pid);
    jb_printf(&b, ",\"total\":%d,\"have\":%d}", m->total, m->have);
    first = 0;
  }
  jb_printf(&b, "],\"top_enabled\":%s,\"top_size\":%d,\"top_scope_ok\":%s,\"hist_at\":%lld,\"top_message\":",
            S.top_enabled ? "true" : "false", S.top_size, top_scope_ok_locked() ? "true" : "false",
            (long long)S.hist_at);
  jb_str(&b, S.top_msg);
  jb_printf(&b, ",\"tops\":[");
  first = 1;
  for(int i=S.ntops - 1; i>=0; i--) {
    const sp_top_t *t = &S.tops[i];
    if(t->ym < S.start_ym) continue;
    jb_printf(&b, "%s{\"month\":\"%04d-%02d\",\"name\":\"top %d/%d\",\"label\":\"%s %d\",\"playlist\":",
              first ? "" : ",", t->ym / 12, t->ym % 12 + 1, t->ym % 12 + 1, t->ym / 12,
              lib_month_name(t->ym % 12 + 1), t->ym / 12);
    jb_str(&b, t->pid);
    jb_printf(&b, ",\"final\":%s,\"plays\":%d,\"n\":%d,\"have\":%d}", t->final ? "true" : "false",
              t->plays, t->n, t->have);
    first = 0;
  }
  jb_printf(&b, "]}");
  pthread_mutex_unlock(&g_lock);
  return b.p;
}
