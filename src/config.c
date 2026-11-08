/* ps5share - configuración, usuarios y contraseñas
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __PROSPERO__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#include "config.h"
#include "crypt.h"
#include "log.h"
#include "sha256.h"


static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char       g_path[PATH_MAX];
static settings_t g_settings;
static user_t     g_users[CFG_MAX_USERS];
static int        g_nusers = 0;


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
  char *fld[8];

  if(!f) return -1;

  while(fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\r\n")] = 0;
    if(!line[0] || line[0] == '#') continue;

    int n = split_tabs(line, fld, 8);
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


int
cfg_init(const char *dir) {
  mkdir_p(dir);
  snprintf(g_path, sizeof(g_path), "%s/users.conf", dir);

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

  memcpy(&tmp, in, sizeof(tmp));
  tmp.ksalt[0] = tmp.kwrap[0] = 0;
  for(int i=0; i<tmp.nmounts; i++) {
    if(tmp.mounts[i].enc) tmp.mounts[i].rw = 1;
  }
  if(newpass && newpass[0]) {
    cfg_set_password(&tmp, newpass);   /* PBKDF2 fuera del lock */
  }

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
      /* Sin cambio de contraseña se conserva su clave de cifrado.  Si el
         administrador le pone otra contraseña, la clave anterior no se
         puede volver a envolver (no conoce la antigua): se pierde. */
      memcpy(tmp.ksalt, u->ksalt, sizeof(tmp.ksalt));
      memcpy(tmp.kwrap, u->kwrap, sizeof(tmp.kwrap));
    } else if(u->kwrap[0]) {
      LOG_PRINTF("ps5share: el administrador cambió la contraseña de '%s'; "
                 "sus archivos cifrados anteriores ya no se pueden abrir\n", u->name);
    }
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
  if(!strcmp(oldpass, newpass)) {
    snprintf(err, errlen, "La nueva contraseña debe ser distinta de la actual");
    return -1;
  }

  memset(&tmp, 0, sizeof(tmp));
  cfg_set_password(&tmp, newpass);   /* PBKDF2 fuera del lock */

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
cfg_delete_user(const char *name, char *err, size_t errlen) {
  int r = -1;
  cfg_lock();
  for(int i=0; i<g_nusers; i++) {
    if(strcmp(g_users[i].name, name)) continue;
    if(g_users[i].admin && count_admins_except(name) == 0) {
      snprintf(err, errlen, "No puedes borrar el último administrador");
      goto out;
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
     s->sftp_port == s->http_port || s->sftp_port == s->ftp_port) {
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
