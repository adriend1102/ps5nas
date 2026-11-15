/* ps5share - configuración, usuarios y contraseñas
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __PROSPERO__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#include "config.h"
#include "crypt.h"
#include "log.h"
#include "sha256.h"
#include "totp.h"


static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char       g_path[PATH_MAX];
static char       g_dir[PATH_MAX];
static uint8_t    g_master[32];       /* clave maestra: cifra contraseñas guardadas */
static int        g_master_ok = 0;
static settings_t g_settings;
static user_t     g_users[CFG_MAX_USERS];
static int        g_nusers = 0;
static link_t     g_links[CFG_MAX_LINKS];
static int        g_nlinks = 0;


const char *cfg_dir(void) { return g_dir; }
void cfg_lock(void)   { pthread_mutex_lock(&g_lock); }
void cfg_unlock(void) { pthread_mutex_unlock(&g_lock); }
settings_t *cfg_settings(void) { return &g_settings; }
int cfg_nusers(void) { return g_nusers; }
user_t *cfg_user_at(int i) { return (i >= 0 && i < g_nusers) ? &g_users[i] : NULL; }


/* ------------------------------------------------------------------ */
/* Criptografía: HMAC-SHA256 + PBKDF2 (un solo bloque de 32 bytes)     */
/* ------------------------------------------------------------------ */

static void
hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen,
            uint8_t out[32]) {
  uint8_t k[64] = {0};
  uint8_t ipad[64], opad[64];
  uint8_t inner[32];
  SHA256_CTX ctx;

  if(keylen > 64) {
    sha256_init(&ctx);
    sha256_update(&ctx, key, keylen);
    sha256_final(&ctx, k);
  } else {
    memcpy(k, key, keylen);
  }
  for(int i=0; i<64; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }

  sha256_init(&ctx);
  sha256_update(&ctx, ipad, 64);
  sha256_update(&ctx, msg, msglen);
  sha256_final(&ctx, inner);

  sha256_init(&ctx);
  sha256_update(&ctx, opad, 64);
  sha256_update(&ctx, inner, 32);
  sha256_final(&ctx, out);
}


static void
pbkdf2_sha256(const char *pass, const uint8_t *salt, size_t saltlen,
              int iter, uint8_t out[32]) {
  uint8_t buf[128];
  uint8_t u[32], t[32];
  size_t plen = strlen(pass);

  if(saltlen > sizeof(buf) - 4) saltlen = sizeof(buf) - 4;
  memcpy(buf, salt, saltlen);
  buf[saltlen+0] = 0; buf[saltlen+1] = 0; buf[saltlen+2] = 0; buf[saltlen+3] = 1;

  hmac_sha256((const uint8_t*)pass, plen, buf, saltlen + 4, u);
  memcpy(t, u, 32);
  for(int i=1; i<iter; i++) {
    hmac_sha256((const uint8_t*)pass, plen, u, 32, u);
    for(int j=0; j<32; j++) t[j] ^= u[j];
  }
  memcpy(out, t, 32);
}


static void
to_hex(const uint8_t *in, size_t n, char *out) {
  static const char hx[] = "0123456789abcdef";
  for(size_t i=0; i<n; i++) {
    out[i*2]   = hx[in[i] >> 4];
    out[i*2+1] = hx[in[i] & 15];
  }
  out[n*2] = 0;
}


static int
from_hex(const char *in, uint8_t *out, size_t n) {
  for(size_t i=0; i<n; i++) {
    unsigned v;
    if(sscanf(in + i*2, "%2x", &v) != 1) return -1;
    out[i] = (uint8_t)v;
  }
  return 0;
}


/* Bytes aleatorios criptográficos.  En PS5 se piden al kernel
   (kern.arandom) y, si no, a /dev/urandom; el arc4random de la libc del SDK
   es el antiguo basado en RC4 y solo se usa como último recurso. */
static void
random_bytes(uint8_t *buf, size_t n) {
#ifdef __PROSPERO__
  int mib[2] = {CTL_KERN, KERN_ARND};
  size_t done = 0;
  while(done < n) {
    size_t len = n - done;
    if(sysctl(mib, 2, buf + done, &len, NULL, 0) || !len) break;
    done += len;
  }
  if(done == n) return;

  int fd = open("/dev/urandom", O_RDONLY);
  if(fd >= 0) {
    done = 0;
    while(done < n) {
      ssize_t r = read(fd, buf + done, n - done);
      if(r <= 0) break;
      done += (size_t)r;
    }
    close(fd);
    if(done == n) return;
  }
  LOG_PUTS("ps5share: aviso, usando arc4random como fuente aleatoria");
#endif
  arc4random_buf(buf, n);
}


void
cfg_random(uint8_t *buf, size_t n) {
  random_bytes(buf, n);
}


int
ps5share_rand_seed(unsigned char *out, unsigned int sz) {
  random_bytes(out, sz);
  return 0;
}


void
cfg_random_hex(char *out, size_t nbytes) {
  uint8_t buf[64];
  if(nbytes > sizeof(buf)) nbytes = sizeof(buf);
  random_bytes(buf, nbytes);
  to_hex(buf, nbytes, out);
}


int
cfg_consttime_eq(const char *a, const char *b) {
  size_t la = strlen(a), lb = strlen(b);
  unsigned char d = (la != lb);
  size_t n = la < lb ? la : lb;
  for(size_t i=0; i<n; i++) d |= (unsigned char)(a[i] ^ b[i]);
  return d == 0;
}


static void
hash_password(const char *salt_hex, const char *pass, char *hash_hex) {
  uint8_t salt[CFG_SALT_HEX/2];
  uint8_t dk[32];
  if(from_hex(salt_hex, salt, sizeof(salt))) memset(salt, 0, sizeof(salt));
  pbkdf2_sha256(pass, salt, sizeof(salt), CFG_PBKDF2_ITER, dk);
  to_hex(dk, 32, hash_hex);
}


void
cfg_set_password(user_t *u, const char *pass) {
  cfg_random_hex(u->salt, CFG_SALT_HEX/2);
  hash_password(u->salt, pass, u->hash);
}


/* ------------------------------------------------------------------ */
/* Contraseñas recuperables                                            */
/* ------------------------------------------------------------------ */

static void
pw_aad(const char *name, char *aad, size_t n) {
  snprintf(aad, n, "ps5share-pw|%s", name);
}


/* Cifra PASS para el usuario NAME en OUT (vacío si no se puede). */
static void
seal_pw(const char *name, const char *pass, char out[CRYPT_SEAL_HEX + 1]) {
  char aad[CFG_NAME_MAX + 16];
  out[0] = 0;
  if(!g_master_ok || strlen(pass) > CRYPT_SEAL_MAX) return;
  pw_aad(name, aad, sizeof(aad));
  if(crypt_seal(g_master, aad, pass, strlen(pass), out, CRYPT_SEAL_HEX + 1)) out[0] = 0;
}


static int
open_pw(const user_t *u, char *out, size_t outlen) {
  char aad[CFG_NAME_MAX + 16];
  if(!g_master_ok || !u->pwenc[0]) return -1;
  pw_aad(u->name, aad, sizeof(aad));
  return crypt_open(g_master, aad, u->pwenc, out, outlen);
}


int
cfg_get_password(const char *name, char *out, size_t outlen) {
  user_t u;
  if(cfg_get_user(name, &u)) return -1;
  int r = open_pw(&u, out, outlen);
  memset(&u, 0, sizeof(u));
  return r;
}


int
cfg_smtp_password(char *out, size_t outlen) {
  char hex[CRYPT_SEAL_HEX + 1];
  cfg_lock();
  memcpy(hex, g_settings.smtp_passenc, sizeof(hex));
  cfg_unlock();
  out[0] = 0;
  if(!g_master_ok || !hex[0]) return -1;
  return crypt_open(g_master, "ps5share-smtp", hex, out, outlen);
}


int
cfg_set_smtp_password(settings_t *st, const char *pass) {
  st->smtp_passenc[0] = 0;
  if(!pass[0]) return 0;
  if(!g_master_ok || strlen(pass) > CRYPT_SEAL_MAX) return -1;
  return crypt_seal(g_master, "ps5share-smtp", pass, strlen(pass), st->smtp_passenc,
                    sizeof(st->smtp_passenc));
}


int
cfg_valid_email(const char *s) {
  size_t n = strlen(s);
  if(n < 3 || n > CFG_EMAIL_MAX) return 0;
  const char *at = strchr(s, '@');
  if(!at || at == s || strchr(at + 1, '@') || !strchr(at + 1, '.')) return 0;
  if(at[1] == '.' || s[n-1] == '.') return 0;
  for(size_t i=0; i<n; i++) {
    unsigned char c = (unsigned char)s[i];
    if(c <= 0x20 || c == 0x7f || c == '<' || c == '>' || c == ',' || c == ';' ||
       c == '"' || c == '\\' || c == '(' || c == ')') return 0;
  }
  return 1;
}


/* ------------------------------------------------------------------ */
/* Validaciones                                                        */
/* ------------------------------------------------------------------ */

int
cfg_valid_username(const char *s) {
  size_t n = strlen(s);
  if(n < 1 || n > 32) return 0;
  for(size_t i=0; i<n; i++) {
    char c = s[i];
    if(!((c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') ||
         c=='.' || c=='_' || c=='-')) return 0;
  }
  return s[0] != '.';
}


int
cfg_valid_mountname(const char *s) {
  size_t n = strlen(s);
  if(n < 1 || n > CFG_NAME_MAX) return 0;
  if(!strcmp(s, ".") || !strcmp(s, "..")) return 0;
  if(s[0] == ' ' || s[n-1] == ' ') return 0;
  for(size_t i=0; i<n; i++) {
    unsigned char c = (unsigned char)s[i];
    if(c < 0x20 || c == 0x7f || c == '/' || c == '\\' || c == '\t') return 0;
  }
  return 1;
}


static int
valid_realpath(const char *p) {
  size_t n = strlen(p);
  if(n < 1 || n >= PATH_MAX - 256 || p[0] != '/') return 0;
  for(size_t i=0; i<n; i++) {
    unsigned char c = (unsigned char)p[i];
    if(c < 0x20 || c == 0x7f) return 0;
  }
  /* sin componentes ".." */
  const char *q = p;
  while((q = strstr(q, "..")) != NULL) {
    int start = (q == p) || q[-1] == '/';
    int end = q[2] == 0 || q[2] == '/';
    if(start && end) return 0;
    q += 2;
  }
  return 1;
}


/* ------------------------------------------------------------------ */
/* Lectura / escritura del fichero                                     */
/* ------------------------------------------------------------------ */

static void
defaults(settings_t *s) {
  memset(s, 0, sizeof(*s));
  s->ftp_port = 2121;
  s->http_port = 8000;   /* 8080 lo usa websrv */
  s->pasv_min = 50000;
  s->pasv_max = 50099;
  s->sftp_port = 2222;
  s->sftp_enabled = 1;
  s->ftp_enabled = 0;
  snprintf(s->smtp_host, sizeof(s->smtp_host), "smtp.gmail.com");
  s->smtp_port = 465;
  snprintf(s->smtp_from_name, sizeof(s->smtp_from_name), "PS5NAS");
  s->recover_email = 1;
  s->recover_admin = 1;
  s->vault_enabled = 1;
  snprintf(s->vault_domain, sizeof(s->vault_domain), "ps5nas.local");
  s->https_enabled = 1;
  s->https_port = 8443;
}


static int
split_tabs(char *line, char **fields, int max) {
  int n = 0;
  char *p = line;
  while(n < max) {
    fields[n++] = p;
    char *t = strchr(p, '\t');
    if(!t) break;
    *t = 0;
    p = t + 1;
  }
  return n;
}


static int
load_file(const char *path) {
  FILE *f = fopen(path, "r");
  char line[PATH_MAX + 256];
  char *fld[10];

  if(!f) return -1;

  while(fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\r\n")] = 0;
    if(!line[0] || line[0] == '#') continue;

    int n = split_tabs(line, fld, 10);
    if(!strcmp(fld[0], "set") && n >= 3) {
      const char *k = fld[1], *v = fld[2];
      if(!strcmp(k, "ftp_port")) g_settings.ftp_port = atoi(v);
      else if(!strcmp(k, "http_port")) g_settings.http_port = atoi(v);
      else if(!strcmp(k, "pasv_min")) g_settings.pasv_min = atoi(v);
      else if(!strcmp(k, "pasv_max")) g_settings.pasv_max = atoi(v);
      /* "kill_ftpsrv" (versiones anteriores) se ignora */
      else if(!strcmp(k, "sftp_port")) g_settings.sftp_port = atoi(v);
      else if(!strcmp(k, "sftp_enabled")) g_settings.sftp_enabled = atoi(v);
      else if(!strcmp(k, "ftp_enabled")) g_settings.ftp_enabled = atoi(v);
      else if(!strcmp(k, "pasv_address"))
        snprintf(g_settings.pasv_address, sizeof(g_settings.pasv_address), "%s", v);
      else if(!strcmp(k, "smtp_host"))
        snprintf(g_settings.smtp_host, sizeof(g_settings.smtp_host), "%s", v);
      else if(!strcmp(k, "smtp_port")) g_settings.smtp_port = atoi(v);
      else if(!strcmp(k, "smtp_user"))
        snprintf(g_settings.smtp_user, sizeof(g_settings.smtp_user), "%s", v);
      else if(!strcmp(k, "smtp_pass"))
        snprintf(g_settings.smtp_passenc, sizeof(g_settings.smtp_passenc), "%s", v);
      else if(!strcmp(k, "smtp_from_name"))
        snprintf(g_settings.smtp_from_name, sizeof(g_settings.smtp_from_name), "%s", v);
      else if(!strcmp(k, "recover_email")) g_settings.recover_email = atoi(v);
      else if(!strcmp(k, "recover_admin")) g_settings.recover_admin = atoi(v);
      else if(!strcmp(k, "app_lang") && strlen(v) == 2)
        snprintf(g_settings.app_lang, sizeof(g_settings.app_lang), "%s", v);
      else if(!strcmp(k, "vault_enabled")) g_settings.vault_enabled = atoi(v);
      else if(!strcmp(k, "vault_dir")) {
        if(!v[0] || valid_realpath(v))
          snprintf(g_settings.vault_dir, sizeof(g_settings.vault_dir), "%s", v);
      }
      else if(!strcmp(k, "vault_domain")) {
        if(cfg_valid_hostname_list(v) && !strchr(v, ' ') && v[0])
          snprintf(g_settings.vault_domain, sizeof(g_settings.vault_domain), "%s", v);
      }
      else if(!strcmp(k, "gw_enabled")) g_settings.gw_enabled = atoi(v);
      else if(!strcmp(k, "gw_domain")) {
        if(!v[0] || cfg_valid_domain(v))
          snprintf(g_settings.gw_domain, sizeof(g_settings.gw_domain), "%s", v);
      }
      else if(!strcmp(k, "gw_secret") && strlen(v) == 64)
        snprintf(g_settings.gw_secret, sizeof(g_settings.gw_secret), "%s", v);
      else if(!strcmp(k, "https_enabled")) g_settings.https_enabled = atoi(v);
      else if(!strcmp(k, "https_port")) g_settings.https_port = atoi(v);
      else if(!strcmp(k, "tls_names")) {
        if(cfg_valid_hostname_list(v))
          snprintf(g_settings.tls_names, sizeof(g_settings.tls_names), "%s", v);
      }
    } else if(!strcmp(fld[0], "user") && n >= 6) {
      if(g_nusers >= CFG_MAX_USERS || !cfg_valid_username(fld[1])) continue;
      if(cfg_find_user_locked(fld[1])) continue;
      user_t *u = &g_users[g_nusers++];
      memset(u, 0, sizeof(*u));
      snprintf(u->name, sizeof(u->name), "%s", fld[1]);
      snprintf(u->salt, sizeof(u->salt), "%s", fld[2]);
      snprintf(u->hash, sizeof(u->hash), "%s", fld[3]);
      u->admin = atoi(fld[4]) != 0;
      u->enabled = atoi(fld[5]) != 0;
      u->can_chpass = n >= 7 && atoi(fld[6]) != 0;
      u->must_chpass = n >= 8 && atoi(fld[7]) != 0;
    } else if(!strcmp(fld[0], "ukey") && n >= 4) {
      user_t *u = cfg_find_user_locked(fld[1]);
      if(!u || strlen(fld[2]) != CFG_SALT_HEX || strlen(fld[3]) != CRYPT_WRAP_HEX) continue;
      snprintf(u->ksalt, sizeof(u->ksalt), "%s", fld[2]);
      snprintf(u->kwrap, sizeof(u->kwrap), "%s", fld[3]);
    } else if(!strcmp(fld[0], "pw") && n >= 3) {
      user_t *u = cfg_find_user_locked(fld[1]);
      if(u && strlen(fld[2]) < sizeof(u->pwenc))
        snprintf(u->pwenc, sizeof(u->pwenc), "%s", fld[2]);
    } else if(!strcmp(fld[0], "vault") && n >= 2) {
      user_t *u = cfg_find_user_locked(fld[1]);
      if(u) u->vault = 1;
    } else if(!strcmp(fld[0], "totp") && n >= 3) {
      user_t *u = cfg_find_user_locked(fld[1]);
      if(u && strlen(fld[2]) < sizeof(u->totp)) {
        snprintf(u->totp, sizeof(u->totp), "%s", fld[2]);
        u->totp_since = n >= 4 ? atoll(fld[3]) : 0;
      }
    } else if(!strcmp(fld[0], "rcode") && n >= 3) {
      user_t *u = cfg_find_user_locked(fld[1]);
      if(u && u->nrcodes < CFG_RCODES && strlen(fld[2]) == 32)
        snprintf(u->rcodes[u->nrcodes++], sizeof(u->rcodes[0]), "%s", fld[2]);
    } else if(!strcmp(fld[0], "apppw") && n >= 6) {
      user_t *u = cfg_find_user_locked(fld[1]);
      if(!u || u->napppw >= CFG_MAX_APPPW || strlen(fld[2]) != 8 || strlen(fld[3]) > CFG_APPPW_LABEL ||
         strlen(fld[4]) != 16 || strlen(fld[5]) != 64) continue;
      apppw_t *a = &u->apppw[u->napppw++];
      memset(a, 0, sizeof(*a));
      snprintf(a->id, sizeof(a->id), "%s", fld[2]);
      snprintf(a->label, sizeof(a->label), "%s", fld[3]);
      snprintf(a->salt, sizeof(a->salt), "%s", fld[4]);
      snprintf(a->hash, sizeof(a->hash), "%s", fld[5]);
      a->created = n >= 7 ? atoll(fld[6]) : 0;
      a->used = n >= 8 ? atoll(fld[7]) : 0;
    } else if(!strcmp(fld[0], "email") && n >= 3) {
      user_t *u = cfg_find_user_locked(fld[1]);
      if(u && cfg_valid_email(fld[2])) snprintf(u->email, sizeof(u->email), "%s", fld[2]);
    } else if(!strcmp(fld[0], "link") && n >= 5) {
      if(g_nlinks >= CFG_MAX_LINKS || strlen(fld[1]) != 16 || strlen(fld[3]) > CFG_LINK_NAME ||
         strlen(fld[4]) > CFG_LINK_TARGET) continue;
      link_t *l = &g_links[g_nlinks++];
      memset(l, 0, sizeof(*l));
      snprintf(l->id, sizeof(l->id), "%s", fld[1]);
      l->all = atoi(fld[2]) != 0;
      snprintf(l->name, sizeof(l->name), "%s", fld[3]);
      snprintf(l->target, sizeof(l->target), "%s", fld[4]);
      if(n >= 6 && strlen(fld[5]) <= CFG_LINK_SUB) snprintf(l->sub, sizeof(l->sub), "%s", fld[5]);
    } else if(!strcmp(fld[0], "linkuser") && n >= 3) {
      for(int i=0; i<g_nlinks; i++) {
        link_t *l = &g_links[i];
        if(strcmp(l->id, fld[1]) || l->nusers >= CFG_MAX_USERS || !cfg_valid_username(fld[2])) continue;
        snprintf(l->users[l->nusers++], CFG_NAME_MAX + 1, "%s", fld[2]);
      }
    } else if(!strcmp(fld[0], "mount") && n >= 5) {
      user_t *u = cfg_find_user_locked(fld[1]);
      if(!u || u->nmounts >= CFG_MAX_MOUNTS) continue;
      if(!cfg_valid_mountname(fld[3]) || !valid_realpath(fld[4])) continue;
      mount_t *m = &u->mounts[u->nmounts++];
      m->enc = !strcmp(fld[2], "enc");
      m->rw = m->enc || !strcmp(fld[2], "rw");
      snprintf(m->name, sizeof(m->name), "%s", fld[3]);
      snprintf(m->path, sizeof(m->path), "%s", fld[4]);
    }
  }

  fclose(f);
  return 0;
}


int
cfg_save_locked(void) {
  char tmp[PATH_MAX + 8];
  FILE *f;

  snprintf(tmp, sizeof(tmp), "%s.tmp", g_path);
  if(!(f = fopen(tmp, "w"))) {
    LOG_PERROR("fopen");
    return -1;
  }

  fprintf(f, "# ps5share - configuración (separada por tabuladores).\n");
  fprintf(f, "# Se recomienda editarla desde la web de administración.\n");
  fprintf(f, "set\tftp_port\t%u\n", g_settings.ftp_port);
  fprintf(f, "set\thttp_port\t%u\n", g_settings.http_port);
  fprintf(f, "set\tpasv_min\t%u\n", g_settings.pasv_min);
  fprintf(f, "set\tpasv_max\t%u\n", g_settings.pasv_max);
  fprintf(f, "set\tpasv_address\t%s\n", g_settings.pasv_address);
  fprintf(f, "set\tsftp_port\t%u\n", g_settings.sftp_port);
  fprintf(f, "set\tsftp_enabled\t%d\n", g_settings.sftp_enabled);
  fprintf(f, "set\tftp_enabled\t%d\n", g_settings.ftp_enabled);
  fprintf(f, "set\tsmtp_host\t%s\n", g_settings.smtp_host);
  fprintf(f, "set\tsmtp_port\t%u\n", g_settings.smtp_port);
  fprintf(f, "set\tsmtp_user\t%s\n", g_settings.smtp_user);
  fprintf(f, "set\tsmtp_pass\t%s\n", g_settings.smtp_passenc);
  fprintf(f, "set\tsmtp_from_name\t%s\n", g_settings.smtp_from_name);
  fprintf(f, "set\trecover_email\t%d\n", g_settings.recover_email);
  fprintf(f, "set\trecover_admin\t%d\n", g_settings.recover_admin);
  if(g_settings.app_lang[0]) fprintf(f, "set\tapp_lang\t%s\n", g_settings.app_lang);
  fprintf(f, "set\tvault_enabled\t%d\n", g_settings.vault_enabled);
  fprintf(f, "set\tvault_dir\t%s\n", g_settings.vault_dir);
  fprintf(f, "set\tvault_domain\t%s\n", g_settings.vault_domain);
  fprintf(f, "set\thttps_enabled\t%d\n", g_settings.https_enabled);
  fprintf(f, "set\thttps_port\t%u\n", g_settings.https_port);
  fprintf(f, "set\ttls_names\t%s\n", g_settings.tls_names);
  fprintf(f, "set\tgw_enabled\t%d\n", g_settings.gw_enabled);
  fprintf(f, "set\tgw_domain\t%s\n", g_settings.gw_domain);
  fprintf(f, "set\tgw_secret\t%s\n", g_settings.gw_secret);

  for(int i=0; i<g_nusers; i++) {
    user_t *u = &g_users[i];
    fprintf(f, "user\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n", u->name, u->salt, u->hash,
            u->admin, u->enabled, u->can_chpass, u->must_chpass);
    for(int j=0; j<u->nmounts; j++) {
      fprintf(f, "mount\t%s\t%s\t%s\t%s\n", u->name,
              u->mounts[j].enc ? "enc" : (u->mounts[j].rw ? "rw" : "ro"),
              u->mounts[j].name, u->mounts[j].path);
    }
    if(u->kwrap[0]) fprintf(f, "ukey\t%s\t%s\t%s\n", u->name, u->ksalt, u->kwrap);
    if(u->pwenc[0]) fprintf(f, "pw\t%s\t%s\n", u->name, u->pwenc);
    if(u->email[0]) fprintf(f, "email\t%s\t%s\n", u->name, u->email);
    if(u->vault) fprintf(f, "vault\t%s\n", u->name);
    if(u->totp[0]) fprintf(f, "totp\t%s\t%s\t%lld\n", u->name, u->totp, u->totp_since);
    for(int j=0; j<u->nrcodes; j++) fprintf(f, "rcode\t%s\t%s\n", u->name, u->rcodes[j]);
    for(int j=0; j<u->napppw; j++) {
      const apppw_t *a = &u->apppw[j];
      fprintf(f, "apppw\t%s\t%s\t%s\t%s\t%s\t%lld\t%lld\n", u->name, a->id, a->label,
              a->salt, a->hash, a->created, a->used);
    }
  }
  for(int i=0; i<g_nlinks; i++) {
    link_t *l = &g_links[i];
    fprintf(f, "link\t%s\t%d\t%s\t%s\t%s\n", l->id, l->all, l->name, l->target, l->sub);
    for(int j=0; j<l->nusers; j++) fprintf(f, "linkuser\t%s\t%s\n", l->id, l->users[j]);
  }

  if(fflush(f) || fsync(fileno(f))) {
    LOG_PERROR("fsync");
  }
  if(fclose(f)) {
    LOG_PERROR("fclose");
    return -1;
  }
  if(rename(tmp, g_path)) {
    LOG_PERROR("rename");
    return -1;
  }
  chmod(g_path, 0600);
  return 0;
}


static void
mkdir_p(const char *dir) {
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf), "%s", dir);
  for(char *p = buf + 1; *p; p++) {
    if(*p == '/') {
      *p = 0;
      mkdir(buf, 0755);
      *p = '/';
    }
  }
  mkdir(buf, 0755);
}


static void
load_master_key(void) {
  char path[PATH_MAX + 16];
  snprintf(path, sizeof(path), "%s/master.key", g_dir);
  int fd = open(path, O_RDONLY);
  if(fd < 0 && errno != ENOENT) {
    LOG_PERROR("master.key");
    return;
  }
  if(fd >= 0) {
    ssize_t n = read(fd, g_master, sizeof(g_master));
    close(fd);
    if(n == (ssize_t)sizeof(g_master)) {
      g_master_ok = 1;
      return;
    }
    LOG_PRINTF("ps5share: %s está dañada; se crea otra\n", path);
  }
  random_bytes(g_master, sizeof(g_master));
  char tmp[PATH_MAX + 32];
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if(fd < 0 || write(fd, g_master, sizeof(g_master)) != (ssize_t)sizeof(g_master) ||
     fsync(fd) || close(fd) || rename(tmp, path)) {
    LOG_PERROR("master.key");
    if(fd >= 0) close(fd);
    return;
  }
  g_master_ok = 1;
}


int
cfg_init(const char *dir) {
  mkdir_p(dir);
  snprintf(g_dir, sizeof(g_dir), "%s", dir);
  snprintf(g_path, sizeof(g_path), "%s/users.conf", dir);
  load_master_key();

  cfg_lock();
  defaults(&g_settings);
  g_nusers = 0;
  if(load_file(g_path)) {
    LOG_PRINTF("ps5share: creando %s\n", g_path);
    cfg_save_locked();
  }
  cfg_unlock();
  return 0;
}


/* ------------------------------------------------------------------ */
/* Consultas y modificaciones                                          */
/* ------------------------------------------------------------------ */

user_t *
cfg_find_user_locked(const char *name) {
  for(int i=0; i<g_nusers; i++) {
    if(!strcmp(g_users[i].name, name)) return &g_users[i];
  }
  return NULL;
}


int
cfg_get_user(const char *name, user_t *out) {
  int r = -1;
  cfg_lock();
  user_t *u = cfg_find_user_locked(name);
  if(u) {
    memcpy(out, u, sizeof(*out));
    r = 0;
  }
  cfg_unlock();
  return r;
}


int
cfg_authenticate(const char *name, const char *pass, user_t *out) {
  user_t u;
  char hash[CFG_HASH_HEX+1];
  int found = (cfg_get_user(name, &u) == 0);

  /* Calcula el hash aunque el usuario no exista, para no filtrar
     por tiempo de respuesta qué usuarios existen. */
  hash_password(found ? u.salt : "00000000000000000000000000000000", pass, hash);
  if(!found || !u.enabled || !u.hash[0]) return -1;
  if(!cfg_consttime_eq(hash, u.hash)) return -1;

  /* Usuarios de versiones anteriores: se guarda su contraseña (cifrada con
     la clave maestra) la primera vez que entran. */
  if(!u.pwenc[0] && g_master_ok) {
    char enc[CRYPT_SEAL_HEX + 1];
    seal_pw(name, pass, enc);
    if(enc[0]) {
      cfg_lock();
      user_t *p = cfg_find_user_locked(name);
      if(p && !p->pwenc[0] && !strcmp(p->hash, u.hash)) {
        memcpy(p->pwenc, enc, sizeof(p->pwenc));
        cfg_save_locked();
        memcpy(u.pwenc, enc, sizeof(u.pwenc));
      }
      cfg_unlock();
    }
  }
  if(out) memcpy(out, &u, sizeof(u));
  return 0;
}


/* ¿A está dentro de B (o son la misma ruta)? */
static int
path_within(const char *a, const char *b) {
  size_t la = strlen(a), lb = strlen(b);
  while(la > 1 && a[la-1] == '/') la--;
  while(lb > 1 && b[lb-1] == '/') lb--;
  if(lb == 1 && b[0] == '/') return 1;
  if(la < lb || strncmp(a, b, lb)) return 0;
  return la == lb || a[lb] == '/';
}


static int
dir_is_empty(const char *path) {
  DIR *d = opendir(path);
  struct dirent *e;
  int empty = 1;
  if(!d) return -1;
  while((e = readdir(d))) {
    if(strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
      empty = 0;
      break;
    }
  }
  closedir(d);
  return empty;
}


/* Reglas de las carpetas cifradas (con el lock tomado).  NU es el usuario
   nuevo y OLD el que había (o NULL). */
static int
check_enc_mounts_locked(user_t *nu, const user_t *old, char *err, size_t errlen) {
  for(int i=0; i<nu->nmounts; i++) {
    mount_t *m = &nu->mounts[i];

    /* ¿Ya era cifrada esta misma ruta para este usuario? */
    int was_enc = 0, was_plain = 0;
    for(int j=0; old && j<old->nmounts; j++) {
      if(!strcmp(old->mounts[j].path, m->path)) {
        if(old->mounts[j].enc) was_enc = 1;
        else was_plain = 1;
      }
    }

    if(!m->enc) {
      if(was_enc && dir_is_empty(m->path) == 0) {
        snprintf(err, errlen, "La carpeta '%s' es privada y tiene archivos cifrados: "
                 "no se puede dejar de cifrar (vacíala antes)", m->name);
        return -1;
      }
      /* Tampoco se puede montar por dentro la carpeta privada de otro. */
      for(int k=0; k<g_nusers; k++) {
        const user_t *o = &g_users[k];
        if(!strcmp(o->name, nu->name)) continue;
        for(int j=0; j<o->nmounts; j++) {
          if(o->mounts[j].enc && path_within(m->path, o->mounts[j].path)) {
            snprintf(err, errlen, "'%s' está dentro de la carpeta privada de '%s'",
                     m->name, o->name);
            return -1;
          }
        }
      }
      continue;
    }

    /* Ninguna otra carpeta de nadie puede apuntar a la misma ruta, ni otra
       cifrada solaparse con ella. */
    for(int k=0; k<g_nusers; k++) {
      const user_t *o = &g_users[k];
      int same_user = !strcmp(o->name, nu->name);
      for(int j=0; j<o->nmounts; j++) {
        if(same_user) continue;
        const mount_t *om = &o->mounts[j];
        if(!strcmp(om->path, m->path) ||
           (om->enc && (path_within(om->path, m->path) || path_within(m->path, om->path)))) {
          snprintf(err, errlen, "La carpeta privada '%s' coincide con una carpeta de '%s'. "
                   "Cada carpeta privada debe ser solo de un usuario", m->name, o->name);
          return -1;
        }
      }
    }
    for(int j=0; j<nu->nmounts; j++) {
      if(j != i && (path_within(nu->mounts[j].path, m->path) ||
                    path_within(m->path, nu->mounts[j].path))) {
        snprintf(err, errlen, "La carpeta privada '%s' se solapa con '%s'",
                 m->name, nu->mounts[j].name);
        return -1;
      }
    }

    if(was_enc) continue;
    struct stat st;
    if(stat(m->path, &st)) {
      if(errno != ENOENT || mkdir(m->path, 0777)) {
        snprintf(err, errlen, "No se pudo crear la carpeta privada '%s': %s",
                 m->path, strerror(errno));
        return -1;
      }
    } else if(!S_ISDIR(st.st_mode) || dir_is_empty(m->path) != 1) {
      snprintf(err, errlen, "Para hacer privada '%s' la carpeta tiene que estar vacía o no "
               "existir (se crea sola). Elige una carpeta nueva%s", m->name,
               was_plain ? " o vacía esta antes" : "");
      return -1;
    }
  }
  return 0;
}


int
cfg_user_has_enc(const user_t *u) {
  for(int i=0; i<u->nmounts; i++) if(u->mounts[i].enc) return 1;
  return 0;
}


static void
derive_kek(const char *pass, const char *salt_hex, uint8_t kek[32]) {
  uint8_t salt[CFG_SALT_HEX/2];
  if(from_hex(salt_hex, salt, sizeof(salt))) memset(salt, 0, sizeof(salt));
  pbkdf2_sha256(pass, salt, sizeof(salt), CFG_PBKDF2_ITER, kek);
}


void
cfg_unlock_key(const char *name, const char *pass, struct ukey *key) {
  user_t u;
  uint8_t kek[32], dek[32];

  memset(key, 0, sizeof(*key));
  if(cfg_get_user(name, &u) || u.must_chpass) return;

  if(u.kwrap[0]) {
    derive_kek(pass, u.ksalt, kek);
    if(crypt_unwrap(kek, u.kwrap, dek)) {
      LOG_PRINTF("ps5share: no se pudo abrir la clave de cifrado de '%s'\n", name);
    } else {
      crypt_key_init(key, dek);
    }
  } else if(cfg_user_has_enc(&u)) {
    /* Primera vez: se crea su clave, envuelta con su contraseña. */
    char ksalt[CFG_SALT_HEX+1], kwrap[CRYPT_WRAP_HEX+1];
    cfg_random(dek, sizeof(dek));
    cfg_random_hex(ksalt, CFG_SALT_HEX/2);
    derive_kek(pass, ksalt, kek);
    if(!crypt_wrap(kek, dek, kwrap)) {
      cfg_lock();
      user_t *p = cfg_find_user_locked(name);
      if(p && !p->kwrap[0]) {
        memcpy(p->ksalt, ksalt, sizeof(p->ksalt));
        memcpy(p->kwrap, kwrap, sizeof(p->kwrap));
        if(!cfg_save_locked()) {
          crypt_key_init(key, dek);
          LOG_PRINTF("ps5share: creada la clave de cifrado de '%s'\n", name);
        }
      }
      cfg_unlock();
      /* Si otra sesión la creó a la vez, se usa esa. */
      if(!key->ok) {
        user_t again;
        if(!cfg_get_user(name, &again) && again.kwrap[0]) {
          derive_kek(pass, again.ksalt, kek);
          if(!crypt_unwrap(kek, again.kwrap, dek)) crypt_key_init(key, dek);
        }
      }
    }
  }
  memset(kek, 0, sizeof(kek));
  memset(dek, 0, sizeof(dek));
}


static int
count_admins_except(const char *name) {
  int n = 0;
  for(int i=0; i<g_nusers; i++) {
    if(g_users[i].admin && g_users[i].enabled && strcmp(g_users[i].name, name)) n++;
  }
  return n;
}


int
cfg_upsert_user(const user_t *in, const char *newpass, char *err, size_t errlen) {
  user_t tmp;
  int r = -1;

  if(!cfg_valid_username(in->name)) {
    snprintf(err, errlen, "Nombre de usuario no válido (letras, números, . _ -; máx. 32)");
    return -1;
  }
  if(in->nmounts < 0 || in->nmounts > CFG_MAX_MOUNTS) {
    snprintf(err, errlen, "Demasiadas carpetas (máx. %d)", CFG_MAX_MOUNTS);
    return -1;
  }
  for(int i=0; i<in->nmounts; i++) {
    if(!cfg_valid_mountname(in->mounts[i].name)) {
      snprintf(err, errlen, "Nombre de carpeta no válido: '%s'", in->mounts[i].name);
      return -1;
    }
    if(!valid_realpath(in->mounts[i].path)) {
      snprintf(err, errlen, "Ruta no válida: '%s' (debe ser absoluta, sin '..')",
               in->mounts[i].path);
      return -1;
    }
    for(int j=0; j<i; j++) {
      if(!strcmp(in->mounts[i].name, in->mounts[j].name)) {
        snprintf(err, errlen, "Carpeta repetida: '%s'", in->mounts[i].name);
        return -1;
      }
    }
  }
  if(newpass && newpass[0] && strlen(newpass) < 6) {
    snprintf(err, errlen, "La contraseña debe tener al menos 6 caracteres");
    return -1;
  }
  if(newpass && strlen(newpass) > CFG_PASS_MAX) {
    snprintf(err, errlen, "La contraseña es demasiado larga (máx. %d)", CFG_PASS_MAX);
    return -1;
  }
  if(in->email[0] && !cfg_valid_email(in->email)) {
    snprintf(err, errlen, "Correo de recuperación no válido");
    return -1;
  }

  memcpy(&tmp, in, sizeof(tmp));
  tmp.ksalt[0] = tmp.kwrap[0] = tmp.pwenc[0] = 0;
  /* La verificación en dos pasos y las contraseñas de aplicación solo se
     cambian con sus funciones propias: aquí se conservan las que hubiera. */
  tmp.totp[0] = 0;
  tmp.totp_since = 0;
  tmp.totp_last = 0;
  tmp.nrcodes = tmp.napppw = 0;
  for(int i=0; i<tmp.nmounts; i++) {
    if(tmp.mounts[i].enc) tmp.mounts[i].rw = 1;
  }

  /* Contraseña nueva puesta por el administrador.  Si se conocía la
     anterior, su clave de cifrado se vuelve a envolver con la nueva y no
     pierde nada.  Todo lo lento (PBKDF2) se hace fuera del lock. */
  user_t old;
  int have_old = !cfg_get_user(in->name, &old);
  int rewrapped = 0;
  if(newpass && newpass[0]) {
    cfg_set_password(&tmp, newpass);
    seal_pw(tmp.name, newpass, tmp.pwenc);
    if(have_old && old.kwrap[0]) {
      char oldpass[CRYPT_SEAL_MAX + 1];
      uint8_t kek[32], dek[32];
      if(!open_pw(&old, oldpass, sizeof(oldpass))) {
        derive_kek(oldpass, old.ksalt, kek);
        if(!crypt_unwrap(kek, old.kwrap, dek)) {
          cfg_random_hex(tmp.ksalt, CFG_SALT_HEX/2);
          derive_kek(newpass, tmp.ksalt, kek);
          if(!crypt_wrap(kek, dek, tmp.kwrap)) rewrapped = 1;
          else tmp.ksalt[0] = tmp.kwrap[0] = 0;
        }
      }
      memset(oldpass, 0, sizeof(oldpass));
      memset(kek, 0, sizeof(kek));
      memset(dek, 0, sizeof(dek));
    }
  }
  memset(&old, 0, sizeof(old));

  cfg_lock();
  user_t *u = cfg_find_user_locked(in->name);
  if(check_enc_mounts_locked(&tmp, u, err, errlen)) goto out;
  if(!u) {
    if(!(newpass && newpass[0])) {
      snprintf(err, errlen, "Un usuario nuevo necesita contraseña");
      goto out;
    }
    if(g_nusers >= CFG_MAX_USERS) {
      snprintf(err, errlen, "Máximo de usuarios alcanzado");
      goto out;
    }
    u = &g_users[g_nusers++];
    memcpy(u, &tmp, sizeof(*u));
  } else {
    if(u->admin && (!tmp.admin || !tmp.enabled) && count_admins_except(u->name) == 0) {
      snprintf(err, errlen, "Debe quedar al menos un administrador activo");
      goto out;
    }
    if(!(newpass && newpass[0])) {
      memcpy(tmp.salt, u->salt, sizeof(tmp.salt));
      memcpy(tmp.hash, u->hash, sizeof(tmp.hash));
      memcpy(tmp.pwenc, u->pwenc, sizeof(tmp.pwenc));
      memcpy(tmp.ksalt, u->ksalt, sizeof(tmp.ksalt));
      memcpy(tmp.kwrap, u->kwrap, sizeof(tmp.kwrap));
    } else if(u->kwrap[0] && !rewrapped) {
      /* No se conocía su contraseña anterior: la clave no se puede abrir. */
      LOG_PRINTF("ps5share: el administrador cambió la contraseña de '%s'; "
                 "sus archivos cifrados anteriores ya no se pueden abrir\n", u->name);
    }
    memcpy(tmp.totp, u->totp, sizeof(tmp.totp));
    tmp.totp_since = u->totp_since;
    tmp.totp_last = u->totp_last;
    tmp.nrcodes = u->nrcodes;
    memcpy(tmp.rcodes, u->rcodes, sizeof(tmp.rcodes));
    tmp.napppw = u->napppw;
    memcpy(tmp.apppw, u->apppw, sizeof(tmp.apppw));
    memcpy(u, &tmp, sizeof(*u));
  }

  if(cfg_save_locked()) {
    snprintf(err, errlen, "No se pudo guardar la configuración: %s", strerror(errno));
    goto out;
  }
  r = 0;

 out:
  cfg_unlock();
  return r;
}


int
cfg_change_own_password(const char *name, const char *oldpass, const char *newpass,
                        char *err, size_t errlen) {
  user_t cur, tmp;
  int r = -1;

  if(cfg_authenticate(name, oldpass, &cur)) {
    snprintf(err, errlen, "La contraseña actual no es correcta");
    return -1;
  }
  if(!cur.can_chpass && !cur.must_chpass) {
    snprintf(err, errlen, "El administrador no te permite cambiar la contraseña");
    return -1;
  }
  if(strlen(newpass) < 6) {
    snprintf(err, errlen, "La contraseña debe tener al menos 6 caracteres");
    return -1;
  }
  if(strlen(newpass) > CFG_PASS_MAX) {
    snprintf(err, errlen, "La contraseña es demasiado larga (máx. %d)", CFG_PASS_MAX);
    return -1;
  }
  if(!strcmp(oldpass, newpass)) {
    snprintf(err, errlen, "La nueva contraseña debe ser distinta de la actual");
    return -1;
  }

  memset(&tmp, 0, sizeof(tmp));
  cfg_set_password(&tmp, newpass);   /* PBKDF2 fuera del lock */
  seal_pw(name, newpass, tmp.pwenc);

  /* Vuelve a envolver su clave de cifrado con la contraseña nueva. */
  if(cur.kwrap[0]) {
    uint8_t kek[32], dek[32];
    derive_kek(oldpass, cur.ksalt, kek);
    if(crypt_unwrap(kek, cur.kwrap, dek)) {
      snprintf(err, errlen, "No se pudo abrir tu clave de cifrado");
      return -1;
    }
    cfg_random_hex(tmp.ksalt, CFG_SALT_HEX/2);
    derive_kek(newpass, tmp.ksalt, kek);
    int w = crypt_wrap(kek, dek, tmp.kwrap);
    memset(kek, 0, sizeof(kek));
    memset(dek, 0, sizeof(dek));
    if(w) {
      snprintf(err, errlen, "No se pudo proteger tu clave de cifrado");
      return -1;
    }
  }

  cfg_lock();
  user_t *u = cfg_find_user_locked(name);
  if(!u) {
    snprintf(err, errlen, "No existe el usuario");
  } else if(strcmp(u->kwrap, cur.kwrap)) {
    snprintf(err, errlen, "Tu cuenta cambió mientras tanto; inténtalo otra vez");
  } else {
    memcpy(u->salt, tmp.salt, sizeof(u->salt));
    memcpy(u->hash, tmp.hash, sizeof(u->hash));
    memcpy(u->pwenc, tmp.pwenc, sizeof(u->pwenc));
    if(cur.kwrap[0]) {
      memcpy(u->ksalt, tmp.ksalt, sizeof(u->ksalt));
      memcpy(u->kwrap, tmp.kwrap, sizeof(u->kwrap));
    }
    u->must_chpass = 0;
    if(cfg_save_locked()) snprintf(err, errlen, "No se pudo guardar la configuración");
    else r = 0;
  }
  cfg_unlock();
  return r;
}


int
cfg_set_email(const char *name, const char *email, char *err, size_t errlen) {
  int r = -1;
  if(email[0] && !cfg_valid_email(email)) {
    snprintf(err, errlen, "Correo no válido");
    return -1;
  }
  cfg_lock();
  user_t *u = cfg_find_user_locked(name);
  if(!u) {
    snprintf(err, errlen, "No existe el usuario");
  } else {
    snprintf(u->email, sizeof(u->email), "%s", email);
    if(cfg_save_locked()) snprintf(err, errlen, "No se pudo guardar la configuración");
    else r = 0;
  }
  cfg_unlock();
  return r;
}


int
cfg_delete_user(const char *name, char *err, size_t errlen) {
  int r = -1;
  cfg_lock();
  for(int i=0; i<g_nusers; i++) {
    if(strcmp(g_users[i].name, name)) continue;
    if(g_users[i].admin && count_admins_except(name) == 0) {
      snprintf(err, errlen, "No puedes borrar el último administrador");
      goto out;
    }
    for(int k=0; k<g_nlinks; k++) {
      link_t *l = &g_links[k];
      for(int j=0; j<l->nusers; j++) {
        if(strcmp(l->users[j], name)) continue;
        memmove(l->users[j], l->users[j+1], (size_t)(l->nusers - j - 1) * sizeof(l->users[0]));
        l->nusers--;
        break;
      }
    }
    memmove(&g_users[i], &g_users[i+1], sizeof(user_t) * (g_nusers - i - 1));
    g_nusers--;
    if(cfg_save_locked()) {
      snprintf(err, errlen, "No se pudo guardar la configuración");
      goto out;
    }
    r = 0;
    goto out;
  }
  snprintf(err, errlen, "No existe el usuario");
 out:
  cfg_unlock();
  return r;
}


int
cfg_update_settings(const settings_t *s, char *err, size_t errlen) {
  int r = -1;
  if(!s->ftp_port || !s->http_port || !s->sftp_port || s->ftp_port == s->http_port ||
     s->sftp_port == s->http_port || s->sftp_port == s->ftp_port || !s->https_port ||
     s->https_port == s->http_port || s->https_port == s->sftp_port ||
     s->https_port == s->ftp_port) {
    snprintf(err, errlen, "Puertos no válidos o repetidos");
    return -1;
  }
  if(s->pasv_min > s->pasv_max || (s->pasv_min && s->pasv_min < 1024)) {
    snprintf(err, errlen, "Rango pasivo no válido");
    return -1;
  }
  for(const char *p = s->pasv_address; *p; p++) {
    if(!((*p >= '0' && *p <= '9') || *p == '.')) {
      snprintf(err, errlen, "La IP pasiva debe ser IPv4 (p. ej. 100.x.y.z) o vacía");
      return -1;
    }
  }
  if(s->smtp_port == 0 || strchr(s->smtp_host, '\t') || strchr(s->smtp_user, '\t') ||
     strchr(s->smtp_from_name, '\t') || strchr(s->smtp_from_name, '\n') ||
     strchr(s->smtp_from_name, '\r')) {
    snprintf(err, errlen, "Ajustes de correo no válidos");
    return -1;
  }
  if(s->vault_dir[0] && !valid_realpath(s->vault_dir)) {
    snprintf(err, errlen, "Carpeta del gestor no válida (ruta absoluta, sin '..')");
    return -1;
  }
  if(!s->vault_domain[0] || strchr(s->vault_domain, ' ') ||
     !cfg_valid_hostname_list(s->vault_domain) || !strchr(s->vault_domain, '.')) {
    snprintf(err, errlen, "Dominio del gestor no válido (p. ej. ps5nas.local)");
    return -1;
  }
  if(!cfg_valid_hostname_list(s->tls_names)) {
    snprintf(err, errlen, "Nombres del certificado no válidos (separados por espacios)");
    return -1;
  }
  if(s->smtp_user[0] && !cfg_valid_email(s->smtp_user)) {
    snprintf(err, errlen, "La cuenta de correo no es válida");
    return -1;
  }
  cfg_lock();
  memcpy(&g_settings, s, sizeof(g_settings));
  if(cfg_save_locked()) {
    snprintf(err, errlen, "No se pudo guardar la configuración");
  } else {
    r = 0;
  }
  cfg_unlock();
  return r;
}


void
cfg_unlock_key_stored(const char *name, struct ukey *key) {
  char pass[CRYPT_SEAL_MAX + 1];
  memset(key, 0, sizeof(*key));
  if(cfg_get_password(name, pass, sizeof(pass))) return;
  cfg_unlock_key(name, pass, key);
  memset(pass, 0, sizeof(pass));
}


int
cfg_seal(const char *aad, const void *plain, size_t len, char *out_hex, size_t outlen) {
  if(!g_master_ok) return -1;
  return crypt_seal(g_master, aad, plain, len, out_hex, outlen);
}


int
cfg_unseal(const char *aad, const char *hex, void *out, size_t outlen) {
  if(!g_master_ok) return -1;
  return crypt_open(g_master, aad, hex, out, outlen);
}


void
cfg_vault_dir(char *out, size_t outlen) {
  cfg_lock();
  if(g_settings.vault_dir[0]) snprintf(out, outlen, "%s", g_settings.vault_dir);
  else snprintf(out, outlen, "%s/vault", g_dir);
  cfg_unlock();
}


/* Lista de nombres de equipo o IPv4 separados por espacios (puede ser vacía). */
int
cfg_valid_hostname_list(const char *s) {
  if(strlen(s) > 255) return 0;
  for(const char *p = s; *p; p++) {
    char c = *p;
    if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
         c == '.' || c == '-' || c == ' ')) return 0;
  }
  return 1;
}


/* ------------------------------------------------------------------ */
/* Accesos directos a otras webs de la consola                         */
/* ------------------------------------------------------------------ */

static int
link_visible(const link_t *l, const user_t *u) {
  if(!u || u->admin || l->all) return 1;
  for(int j=0; j<l->nusers; j++) if(!strcmp(l->users[j], u->name)) return 1;
  return 0;
}


int
cfg_links(link_t *out, int max, const user_t *user) {
  int n = 0;
  cfg_lock();
  for(int i=0; i<g_nlinks && n < max; i++) {
    if(link_visible(&g_links[i], user)) memcpy(&out[n++], &g_links[i], sizeof(link_t));
  }
  cfg_unlock();
  return n;
}


static int
valid_link_text(const char *s, size_t max) {
  size_t n = strlen(s);
  if(!n || n > max) return 0;
  for(size_t i=0; i<n; i++) {
    unsigned char c = (unsigned char)s[i];
    if(c < 0x20 || c == 0x7f) return 0;
  }
  return 1;
}


/* Destino: un puerto (con ruta opcional) o una URL http(s). */
static int
valid_link_target(const char *t) {
  if(!valid_link_text(t, CFG_LINK_TARGET)) return 0;
  for(const char *p = t; *p; p++) {
    if(*p == ' ' || *p == '"' || *p == '\'' || *p == '<' || *p == '>' || *p == '\\' || *p == '`')
      return 0;
  }
  if(!strncmp(t, "http://", 7) || !strncmp(t, "https://", 8)) return 1;
  long port = 0;
  const char *p = t;
  while(*p >= '0' && *p <= '9' && port < 100000) port = port * 10 + (*p++ - '0');
  if(p == t || port < 1 || port > 65535) return 0;
  return *p == 0 || *p == '/';
}


int
cfg_link_save(link_t *in, char *err, size_t errlen) {
  int r = -1;
  /* Se admite ":8080" escrito con dos puntos delante. */
  if(in->target[0] == ':') memmove(in->target, in->target + 1, strlen(in->target));
  if(!valid_link_text(in->name, CFG_LINK_NAME)) {
    snprintf(err, errlen, "Pon un nombre (máx. %d caracteres)", CFG_LINK_NAME);
    return -1;
  }
  if(in->sub[0]) {
    int ok = strlen(in->sub) <= CFG_LINK_SUB && in->sub[0] != '-' && in->sub[strlen(in->sub)-1] != '-';
    for(const char *p = in->sub; *p && ok; p++) ok = (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-';
    if(!ok) {
      snprintf(err, errlen, "Subdominio no válido: solo minúsculas, números y guiones (máx. %d)", CFG_LINK_SUB);
      return -1;
    }
    if(cfg_link_port(in, NULL, 0) <= 0) {
      snprintf(err, errlen, "Para publicar una app en internet, su destino tiene que ser un puerto de la consola");
      return -1;
    }
  }
  if(!valid_link_target(in->target)) {
    snprintf(err, errlen, "Destino no válido: pon un puerto (p. ej. 7860 o 8090/ruta) "
             "o una dirección http(s)://...");
    return -1;
  }
  cfg_lock();
  for(int j=0; j<in->nusers; j++) {
    if(!cfg_find_user_locked(in->users[j])) {
      snprintf(err, errlen, "No existe el usuario %s", in->users[j]);
      goto out;
    }
  }
  for(int i=0; in->sub[0] && i<g_nlinks; i++) {
    if(!strcmp(g_links[i].sub, in->sub) && strcmp(g_links[i].id, in->id)) {
      snprintf(err, errlen, "Ese subdominio ya lo usa «%s»", g_links[i].name);
      goto out;
    }
  }
  link_t *l = NULL;
  if(in->id[0]) {
    for(int i=0; i<g_nlinks; i++) if(!strcmp(g_links[i].id, in->id)) l = &g_links[i];
    if(!l) {
      snprintf(err, errlen, "Ese acceso ya no existe");
      goto out;
    }
  } else {
    if(g_nlinks >= CFG_MAX_LINKS) {
      snprintf(err, errlen, "Demasiados accesos (máx. %d)", CFG_MAX_LINKS);
      goto out;
    }
    cfg_random_hex(in->id, 8);
    l = &g_links[g_nlinks++];
  }
  memcpy(l, in, sizeof(*l));
  if(cfg_save_locked()) snprintf(err, errlen, "No se pudo guardar la configuración");
  else r = 0;
 out:
  cfg_unlock();
  return r;
}


int
cfg_link_delete(const char *id, char *err, size_t errlen) {
  int r = -1;
  cfg_lock();
  for(int i=0; i<g_nlinks; i++) {
    if(strcmp(g_links[i].id, id)) continue;
    memmove(&g_links[i], &g_links[i+1], sizeof(link_t) * (size_t)(g_nlinks - i - 1));
    g_nlinks--;
    if(cfg_save_locked()) snprintf(err, errlen, "No se pudo guardar la configuración");
    else r = 0;
    goto out;
  }
  snprintf(err, errlen, "Ese acceso ya no existe");
 out:
  cfg_unlock();
  return r;
}



int
cfg_link_port(const link_t *l, char *path, size_t pathlen) {
  const char *t = l->target;
  if(*t == ':') t++;
  long port = 0;
  const char *p = t;
  while(*p >= '0' && *p <= '9' && port < 100000) port = port * 10 + (*p++ - '0');
  if(p == t || port < 1 || port > 65535 || (*p && *p != '/')) return 0;
  if(path && pathlen) snprintf(path, pathlen, "%s", *p ? p : "/");
  return (int)port;
}


int
cfg_link_by_sub(const char *sub, link_t *out) {
  int r = -1;
  if(!sub || !sub[0]) return -1;
  cfg_lock();
  for(int i=0; i<g_nlinks; i++) {
    if(!strcmp(g_links[i].sub, sub)) {
      memcpy(out, &g_links[i], sizeof(*out));
      r = 0;
      break;
    }
  }
  cfg_unlock();
  return r;
}


/* Nombre de dominio con al menos un punto: letras, números, guiones y puntos. */
int
cfg_valid_domain(const char *s) {
  size_t n = strlen(s);
  if(n < 3 || n > 127 || !strchr(s, '.') || s[0] == '.' || s[n-1] == '.' || s[0] == '-') return 0;
  for(size_t i=0; i<n; i++) {
    char c = s[i];
    if(!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return 0;
    if(c == '.' && s[i+1] == '.') return 0;
  }
  return 1;
}


/* ------------------------------------------------------------------ */
/* Verificación en dos pasos y contraseñas de aplicación               */
/* ------------------------------------------------------------------ */

/* Sin 0/O ni 1/I/L para que no se confundan al copiarlos a mano. */
static const char RC_ALPHA[] = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";


static void
sha256_hex(const char *a, const char *b, const char *c, char out[65]) {
  uint8_t d[32];
  SHA256_CTX x;
  sha256_init(&x);
  sha256_update(&x, (const uint8_t*)a, strlen(a));
  sha256_update(&x, (const uint8_t*)"|", 1);
  sha256_update(&x, (const uint8_t*)b, strlen(b));
  sha256_update(&x, (const uint8_t*)"|", 1);
  sha256_update(&x, (const uint8_t*)c, strlen(c));
  sha256_final(&x, d);
  to_hex(d, 32, out);
  memset(d, 0, sizeof(d));
}


static void
totp_aad(const char *name, char *aad, size_t n) {
  snprintf(aad, n, "ps5nas-totp|%s", name);
}


/* Quita guiones y espacios y pasa a mayúsculas (o minúsculas). */
static int
normalize_code(const char *in, char *out, size_t outlen, int upper) {
  size_t n = 0;
  for(const char *p = in; *p; p++) {
    if(*p == '-' || *p == ' ') continue;
    if(n + 1 >= outlen) return -1;
    char c = *p;
    if(upper && c >= 'a' && c <= 'z') c = (char)(c - 32);
    if(!upper && c >= 'A' && c <= 'Z') c = (char)(c + 32);
    out[n++] = c;
  }
  out[n] = 0;
  return (int)n;
}


static void
random_code(char *out, size_t len, int upper) {
  uint8_t r[64];
  size_t alen = sizeof(RC_ALPHA) - 1;
  size_t n = 0;
  while(n < len) {
    cfg_random(r, sizeof(r));
    for(size_t i=0; i<sizeof(r) && n < len; i++) {
      if(r[i] >= 256 - (256 % alen)) continue;   /* sin sesgo */
      char c = RC_ALPHA[r[i] % alen];
      out[n++] = (!upper && c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
  }
  out[len] = 0;
  memset(r, 0, sizeof(r));
}


static void
rcode_hash(const char *name, const char *code, char out[33]) {
  char h[65];
  sha256_hex("ps5nas-rc", name, code, h);
  memcpy(out, h, 32);
  out[32] = 0;
}


/* Genera los códigos de recuperación de U (con el lock tomado). */
static void
new_codes_locked(user_t *u, char codes[CFG_RCODES][CFG_RCODE_LEN+2]) {
  for(int i=0; i<CFG_RCODES; i++) {
    char c[CFG_RCODE_LEN + 1];
    random_code(c, CFG_RCODE_LEN, 1);
    rcode_hash(u->name, c, u->rcodes[i]);
    snprintf(codes[i], CFG_RCODE_LEN + 2, "%.4s-%s", c, c + 4);
    memset(c, 0, sizeof(c));
  }
  u->nrcodes = CFG_RCODES;
}


int
cfg_totp_enabled(const user_t *u) {
  return u && u->totp[0];
}


void
cfg_totp_tag(const user_t *u, char out[17]) {
  char h[65];
  sha256_hex("ps5nas-tag", u->name, u->totp, h);
  memcpy(out, h, 16);
  out[16] = 0;
}


int
cfg_totp_enable(const char *name, const uint8_t *key, uint64_t step,
                char codes[CFG_RCODES][CFG_RCODE_LEN+2], char *err, size_t errlen) {
  char b32[TOTP_B32_LEN + 1], aad[CFG_NAME_MAX + 16], sealed[CRYPT_SEAL_HEX + 1];
  int r = -1;
  if(!g_master_ok) {
    snprintf(err, errlen, "La consola no tiene clave maestra: no se puede guardar el secreto");
    return -1;
  }
  base32_encode(key, TOTP_SECRET_LEN, b32, sizeof(b32));
  totp_aad(name, aad, sizeof(aad));
  int sr = crypt_seal(g_master, aad, b32, strlen(b32), sealed, sizeof(sealed));
  memset(b32, 0, sizeof(b32));
  if(sr) {
    snprintf(err, errlen, "No se pudo cifrar el secreto");
    return -1;
  }
  cfg_lock();
  user_t *u = cfg_find_user_locked(name);
  if(!u) {
    snprintf(err, errlen, "No existe el usuario");
  } else {
    memcpy(u->totp, sealed, sizeof(u->totp));
    u->totp_since = (long long)time(NULL);
    u->totp_last = step;   /* el código con el que se activó ya no vale */
    new_codes_locked(u, codes);
    if(cfg_save_locked()) snprintf(err, errlen, "No se pudo guardar la configuración");
    else r = 0;
  }
  cfg_unlock();
  return r;
}


int
cfg_totp_disable(const char *name, char *err, size_t errlen) {
  int r = -1;
  cfg_lock();
  user_t *u = cfg_find_user_locked(name);
  if(!u) {
    snprintf(err, errlen, "No existe el usuario");
  } else {
    memset(u->totp, 0, sizeof(u->totp));
    memset(u->rcodes, 0, sizeof(u->rcodes));
    u->totp_since = 0;
    u->totp_last = 0;
    u->nrcodes = 0;
    if(cfg_save_locked()) snprintf(err, errlen, "No se pudo guardar la configuración");
    else r = 0;
  }
  cfg_unlock();
  return r;
}


int
cfg_totp_new_codes(const char *name, char codes[CFG_RCODES][CFG_RCODE_LEN+2],
                   char *err, size_t errlen) {
  int r = -1;
  cfg_lock();
  user_t *u = cfg_find_user_locked(name);
  if(!u || !u->totp[0]) {
    snprintf(err, errlen, "La verificación en dos pasos no está activada");
  } else {
    new_codes_locked(u, codes);
    if(cfg_save_locked()) snprintf(err, errlen, "No se pudo guardar la configuración");
    else r = 0;
  }
  cfg_unlock();
  return r;
}


/* Fallos de código por usuario (además del límite por IP): 5 seguidos
   bloquean la verificación de esa cuenta 15 minutos. */
#define TOTP_MAX_FAILS 5
#define TOTP_LOCK_SECS 900
static struct { char name[CFG_NAME_MAX + 1]; int fails; time_t first; } g_tfail[CFG_MAX_USERS];


static int
tfail_slot_locked(const char *name) {
  int free_i = -1;
  for(int i=0; i<CFG_MAX_USERS; i++) {
    if(!strcmp(g_tfail[i].name, name)) return i;
    if(free_i < 0 && (!g_tfail[i].name[0] || time(NULL) - g_tfail[i].first > TOTP_LOCK_SECS)) free_i = i;
  }
  if(free_i < 0) free_i = 0;
  memset(&g_tfail[free_i], 0, sizeof(g_tfail[0]));
  snprintf(g_tfail[free_i].name, sizeof(g_tfail[0].name), "%s", name);
  return free_i;
}


int
cfg_totp_locked_out(const char *name) {
  int r = 0;
  cfg_lock();
  for(int i=0; i<CFG_MAX_USERS; i++) {
    if(!strcmp(g_tfail[i].name, name) && g_tfail[i].fails >= TOTP_MAX_FAILS &&
       time(NULL) - g_tfail[i].first < TOTP_LOCK_SECS) r = 1;
  }
  cfg_unlock();
  return r;
}


int
cfg_totp_check(const char *name, const char *code, int allow_recovery, int *used_recovery) {
  char sealed[CRYPT_SEAL_HEX + 1], aad[CFG_NAME_MAX + 16], b32[CRYPT_SEAL_MAX + 1];
  uint8_t key[TOTP_SECRET_LEN + 8];
  uint64_t last;
  int r = -1;

  if(used_recovery) *used_recovery = 0;
  if(!code || !code[0] || strlen(code) > 32) return -1;

  cfg_lock();
  user_t *u = cfg_find_user_locked(name);
  if(!u || !u->totp[0]) {
    cfg_unlock();
    return -1;
  }
  memcpy(sealed, u->totp, sizeof(sealed));
  last = u->totp_last;
  cfg_unlock();
  if(cfg_totp_locked_out(name)) return -2;

  totp_aad(name, aad, sizeof(aad));
  if(!g_master_ok || crypt_open(g_master, aad, sealed, b32, sizeof(b32))) return -1;
  int kl = base32_decode(b32, key, sizeof(key));
  memset(b32, 0, sizeof(b32));
  if(kl <= 0) return -1;

  uint64_t step = totp_verify(key, (size_t)kl, code, (uint64_t)time(NULL), last);
  memset(key, 0, sizeof(key));

  cfg_lock();
  u = cfg_find_user_locked(name);
  if(!u || strcmp(u->totp, sealed)) {
    r = -1;
  } else if(step) {
    if(step > u->totp_last) {
      u->totp_last = step;
      r = 0;
    }
  } else if(allow_recovery) {
    char norm[CFG_RCODE_LEN + 4], h[33];
    if(normalize_code(code, norm, sizeof(norm), 1) == CFG_RCODE_LEN) {
      rcode_hash(name, norm, h);
      for(int i=0; i<u->nrcodes; i++) {
        if(!cfg_consttime_eq(h, u->rcodes[i])) continue;
        memmove(u->rcodes[i], u->rcodes[i+1], (size_t)(u->nrcodes - i - 1) * sizeof(u->rcodes[0]));
        u->nrcodes--;
        memset(u->rcodes[u->nrcodes], 0, sizeof(u->rcodes[0]));
        cfg_save_locked();
        if(used_recovery) *used_recovery = 1;
        r = 0;
        break;
      }
    }
  }
  if(u) {
    int t = tfail_slot_locked(name);
    if(r) {
      if(time(NULL) - g_tfail[t].first > TOTP_LOCK_SECS) {
        g_tfail[t].fails = 0;
        g_tfail[t].first = time(NULL);
      }
      g_tfail[t].fails++;
    } else {
      memset(&g_tfail[t], 0, sizeof(g_tfail[0]));
    }
  }
  cfg_unlock();
  return r;
}


static int
valid_label(const char *s) {
  size_t n = strlen(s);
  if(!n || n > CFG_APPPW_LABEL) return 0;
  for(const char *p = s; *p; p++) {
    if((unsigned char)*p < 0x20 || *p == 0x7f) return 0;
  }
  return 1;
}


int
cfg_apppw_add(const char *name, const char *label, char pass_out[CFG_APPPW_LEN+4],
              char id_out[9], char *err, size_t errlen) {
  char pass[CFG_APPPW_LEN + 1];
  apppw_t a;
  int r = -1;

  if(!valid_label(label)) {
    snprintf(err, errlen, "Pon un nombre para identificarla (máx. %d caracteres)", CFG_APPPW_LABEL);
    return -1;
  }
  memset(&a, 0, sizeof(a));
  cfg_random_hex(a.id, 4);
  cfg_random_hex(a.salt, 8);
  snprintf(a.label, sizeof(a.label), "%s", label);
  random_code(pass, CFG_APPPW_LEN, 0);
  sha256_hex("ps5nas-app", a.salt, pass, a.hash);
  a.created = (long long)time(NULL);

  cfg_lock();
  user_t *u = cfg_find_user_locked(name);
  if(!u) {
    snprintf(err, errlen, "No existe el usuario");
  } else if(u->napppw >= CFG_MAX_APPPW) {
    snprintf(err, errlen, "Ya tienes %d contraseñas de aplicación: borra alguna que no uses", CFG_MAX_APPPW);
  } else {
    memcpy(&u->apppw[u->napppw++], &a, sizeof(a));
    if(cfg_save_locked()) {
      u->napppw--;
      snprintf(err, errlen, "No se pudo guardar la configuración");
    } else {
      r = 0;
    }
  }
  cfg_unlock();
  if(!r) {
    snprintf(pass_out, CFG_APPPW_LEN + 4, "%.4s-%.4s-%.4s-%.4s", pass, pass + 4, pass + 8, pass + 12);
    memcpy(id_out, a.id, 9);
  }
  memset(pass, 0, sizeof(pass));
  return r;
}


int
cfg_apppw_delete(const char *name, const char *id, char *err, size_t errlen) {
  int r = -1;
  cfg_lock();
  user_t *u = cfg_find_user_locked(name);
  if(!u) {
    snprintf(err, errlen, "No existe el usuario");
    goto out;
  }
  for(int i=0; i<u->napppw; i++) {
    if(strcmp(u->apppw[i].id, id)) continue;
    memmove(&u->apppw[i], &u->apppw[i+1], (size_t)(u->napppw - i - 1) * sizeof(apppw_t));
    u->napppw--;
    memset(&u->apppw[u->napppw], 0, sizeof(apppw_t));
    if(cfg_save_locked()) snprintf(err, errlen, "No se pudo guardar la configuración");
    else r = 0;
    goto out;
  }
  snprintf(err, errlen, "Esa contraseña de aplicación ya no existe");
 out:
  cfg_unlock();
  return r;
}


int
cfg_authenticate_service(const char *name, const char *pass, user_t *out, int *via_app) {
  user_t u;
  char norm[CFG_APPPW_LEN + 8];
  int match = -1;

  if(via_app) *via_app = 0;
  if(cfg_get_user(name, &u)) {
    cfg_authenticate(name, pass, NULL);   /* mismo tiempo que si existiera */
    return -1;
  }
  if(u.enabled && normalize_code(pass, norm, sizeof(norm), 0) == CFG_APPPW_LEN) {
    for(int i=0; i<u.napppw; i++) {
      char h[65];
      sha256_hex("ps5nas-app", u.apppw[i].salt, norm, h);
      if(cfg_consttime_eq(h, u.apppw[i].hash)) match = i;
    }
  }
  memset(norm, 0, sizeof(norm));

  if(match >= 0) {
    long long now = (long long)time(NULL);
    if(now - u.apppw[match].used > 3600) {
      /* La última vez que se usó (como mucho una escritura por hora). */
      cfg_lock();
      user_t *p = cfg_find_user_locked(name);
      for(int i=0; p && i<p->napppw; i++) {
        if(!strcmp(p->apppw[i].id, u.apppw[match].id)) {
          p->apppw[i].used = now;
          cfg_save_locked();
        }
      }
      cfg_unlock();
    }
    if(out) memcpy(out, &u, sizeof(u));
    if(via_app) *via_app = 1;
    memset(&u, 0, sizeof(u));
    return 0;
  }
  if(u.totp[0]) {
    /* Con la verificación en dos pasos la contraseña normal no vale aquí. */
    char tmp[CFG_HASH_HEX + 1];
    hash_password(u.salt, pass, tmp);
    memset(&u, 0, sizeof(u));
    return -1;
  }
  memset(&u, 0, sizeof(u));
  return cfg_authenticate(name, pass, out);
}
