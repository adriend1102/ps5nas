/* ps5share - gestor de contraseñas compatible con Bitwarden
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Implementa la parte de la API de Bitwarden que usan las apps oficiales
   (Android, iOS), la extensión de navegador, la app de escritorio y la CLI
   para una cuenta personal: inicio de sesión, sincronización, elementos,
   carpetas e importación.  No hay organizaciones, adjuntos, Send ni 2FA.
   Formatos de respuesta comprobados contra Vaultwarden.  */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "bwcrypto.h"
#include "config.h"
#include "log.h"
#include "vault.h"

#define BW_SERVER_VERSION "2026.6.0"
#define ACCESS_TTL        7200
#define MAX_DEVICES       40

static pthread_mutex_t g_vlock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_jwt_key[32];
static int     g_ready = 0;

static const char *TYPEKEYS[] = {NULL, "login", "secureNote", "card", "identity", "sshKey",
                                 "bankAccount", "driversLicense", "passport"};
#define NTYPES 8


void vault_lock(void)   { pthread_mutex_lock(&g_vlock); }
void vault_unlock(void) { pthread_mutex_unlock(&g_vlock); }


/* ------------------------------------------------------------------ */
/* Utilidades                                                          */
/* ------------------------------------------------------------------ */

static void
to_hex(const uint8_t *in, size_t n, char *out) {
  static const char hx[] = "0123456789abcdef";
  for(size_t i=0; i<n; i++) {
    out[i*2] = hx[in[i] >> 4];
    out[i*2+1] = hx[in[i] & 15];
  }
  out[n*2] = 0;
}


static const char *
jstr(const cJSON *o, const char *k) {
  const cJSON *i = cJSON_GetObjectItem(o, k);
  return cJSON_IsString(i) ? i->valuestring : NULL;
}


static long long
jnum(const cJSON *o, const char *k, long long def) {
  const cJSON *i = cJSON_GetObjectItem(o, k);
  if(cJSON_IsNumber(i)) return (long long)i->valuedouble;
  if(cJSON_IsString(i) && i->valuestring[0]) return atoll(i->valuestring);
  return def;
}


static int
jbool(const cJSON *o, const char *k) {
  const cJSON *i = cJSON_GetObjectItem(o, k);
  return cJSON_IsTrue(i) || (cJSON_IsNumber(i) && i->valuedouble != 0) ||
         (cJSON_IsString(i) && !strcasecmp(i->valuestring, "true"));
}


static void
jset(cJSON *o, const char *k, cJSON *v) {
  if(cJSON_GetObjectItemCaseSensitive(o, k)) cJSON_ReplaceItemInObjectCaseSensitive(o, k, v);
  else cJSON_AddItemToObject(o, k, v);
}


static void
jset_str(cJSON *o, const char *k, const char *s) {
  jset(o, k, s ? cJSON_CreateString(s) : cJSON_CreateNull());
}


static void
jset_num(cJSON *o, const char *k, double d) {
  jset(o, k, cJSON_CreateNumber(d));
}


static void
jset_iso(cJSON *o, const char *k, long long us) {
  char d[40];
  if(us <= 0) {
    jset(o, k, cJSON_CreateNull());
    return;
  }
  bw_iso(us, d);
  jset(o, k, cJSON_CreateString(d));
}


cJSON *
vault_find_id(cJSON *arr, const char *id) {
  cJSON *it;
  if(!id) return NULL;
  cJSON_ArrayForEach(it, arr) {
    const char *x = jstr(it, "id");
    if(x && !strcasecmp(x, id)) return it;
  }
  return NULL;
}


static void
lower(char *s) {
  for(; *s; s++) if(*s >= 'A' && *s <= 'Z') *s = (char)(*s + 32);
}


static void
user_aad(const char *user, char *out, size_t outlen) {
  snprintf(out, outlen, "ps5nas-vault:%s", user);
}


/* ------------------------------------------------------------------ */
/* Almacenamiento                                                      */
/* ------------------------------------------------------------------ */

static void
vault_path(const char *user, char *out, size_t outlen) {
  char dir[PATH_MAX];
  cfg_vault_dir(dir, sizeof(dir));
  snprintf(out, outlen, "%s/%s.json", dir, user);
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
  mkdir(buf, 0700);
}


cJSON *
vault_load(const char *user) {
  char path[PATH_MAX + 64];
  struct stat st;
  vault_path(user, path, sizeof(path));
  int fd = open(path, O_RDONLY);
  if(fd < 0) return NULL;
  if(fstat(fd, &st) || st.st_size <= 0 || st.st_size > 64 * 1024 * 1024) {
    close(fd);
    return NULL;
  }
  char *buf = malloc((size_t)st.st_size + 1);
  if(!buf) {
    close(fd);
    return NULL;
  }
  size_t have = 0;
  while(have < (size_t)st.st_size) {
    ssize_t n = read(fd, buf + have, (size_t)st.st_size - have);
    if(n <= 0) break;
    have += (size_t)n;
  }
  close(fd);
  buf[have] = 0;
  cJSON *v = cJSON_Parse(buf);
  free(buf);
  if(!v) LOG_PRINTF("ps5share: la bóveda de '%s' está dañada (%s)\n", user, path);
  return v;
}


int
vault_save(const char *user, cJSON *v) {
  char path[PATH_MAX + 64], tmp[PATH_MAX + 80], dir[PATH_MAX];
  cfg_vault_dir(dir, sizeof(dir));
  mkdir_p(dir);
  vault_path(user, path, sizeof(path));
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  char *s = cJSON_PrintUnformatted(v);
  if(!s) return -1;
  size_t len = strlen(s);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  int ok = fd >= 0 && write(fd, s, len) == (ssize_t)len && !fsync(fd);
  if(fd >= 0) close(fd);
  free(s);
  if(!ok || rename(tmp, path)) {
    LOG_PRINTF("ps5share: no se pudo guardar la bóveda de '%s': %s\n", user, strerror(errno));
    unlink(tmp);
    return -1;
  }
  chmod(path, 0600);
  return 0;
}


void
vault_touch(cJSON *v) {
  jset_num(v, "rev", (double)bw_now_us());
}


int
vault_user_key(const cJSON *v, const char *user, uint8_t key[64]) {
  char aad[96], out[80];
  const char *ukm = jstr(v, "ukm");
  if(!ukm) return -1;
  user_aad(user, aad, sizeof(aad));
  if(cfg_unseal(aad, ukm, out, sizeof(out))) return -1;
  memcpy(key, out, 64);
  memset(out, 0, sizeof(out));
  return 0;
}


/* ------------------------------------------------------------------ */
/* Cuentas                                                             */
/* ------------------------------------------------------------------ */

void
vault_init(const char *confdir) {
  char path[PATH_MAX + 32];
  snprintf(path, sizeof(path), "%s/vault-jwt.key", confdir);
  int fd = open(path, O_RDONLY);
  if(fd >= 0) {
    ssize_t n = read(fd, g_jwt_key, sizeof(g_jwt_key));
    close(fd);
    if(n == (ssize_t)sizeof(g_jwt_key)) {
      g_ready = 1;
      return;
    }
  }
  bw_random(g_jwt_key, sizeof(g_jwt_key));
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if(fd >= 0) {
    if(write(fd, g_jwt_key, sizeof(g_jwt_key)) != (ssize_t)sizeof(g_jwt_key)) {
      LOG_PERROR("vault-jwt.key");
    }
    fsync(fd);
    close(fd);
  }
  g_ready = 1;
}


/* Rellena en V la clave protegida con la contraseña y el hash de
   verificación.  PBKDF2 de 600 000 iteraciones: tarda. */
static int
set_master(cJSON *v, const char *password, const uint8_t ukey[64]) {
  const char *email = jstr(v, "email");
  uint32_t iter = (uint32_t)jnum(v, "iter", BW_KDF_ITER);
  uint8_t mk[32], st[64], salt[16], hb[40], mph[32];
  char hash[64], hx[65];
  if(!email) return -1;

  bw_master_key(password, email, iter, mk);
  bw_master_hash(mk, password, hash);
  bw_stretch(mk, st);
  char *key = bw_enc(st, ukey, 64);
  int hl = bw_b64_dec(hash, strlen(hash), hb, sizeof(hb));
  bw_random(salt, sizeof(salt));
  bw_hmac256(salt, sizeof(salt), hb, (size_t)hl, mph);
  memset(mk, 0, sizeof(mk));
  memset(st, 0, sizeof(st));
  memset(hb, 0, sizeof(hb));
  memset(hash, 0, sizeof(hash));
  if(!key) return -1;
  jset_str(v, "key", key);
  free(key);
  to_hex(salt, sizeof(salt), hx);
  jset_str(v, "mphSalt", hx);
  to_hex(mph, sizeof(mph), hx);
  jset_str(v, "mph", hx);
  char ss[37];
  bw_uuid(ss);
  jset_str(v, "sstamp", ss);           /* invalida los tokens anteriores */
  jset(v, "devices", cJSON_CreateArray());
  vault_touch(v);
  return 0;
}


/* Comprueba el hash de la contraseña maestra que envía un cliente. */
static int
check_master_hash(const cJSON *v, const char *hash_b64) {
  uint8_t hb[40], salt[16], mph[32], want[32];
  const char *ms = jstr(v, "mphSalt"), *mh = jstr(v, "mph");
  if(!hash_b64 || !ms || !mh || strlen(ms) != 32 || strlen(mh) != 64) return -1;
  int hl = bw_b64_dec(hash_b64, strlen(hash_b64), hb, sizeof(hb));
  if(hl != 32) return -1;
  for(int i=0; i<16; i++) sscanf(ms + i*2, "%2hhx", &salt[i]);
  for(int i=0; i<32; i++) sscanf(mh + i*2, "%2hhx", &want[i]);
  bw_hmac256(salt, sizeof(salt), hb, 32, mph);
  return bw_consttime_eq(mph, want, 32) ? 0 : -1;
}


int
vault_has_account_in(const char *dir, const char *user) {
  char path[PATH_MAX + 64];
  struct stat st;
  snprintf(path, sizeof(path), "%s/%s.json", dir, user);
  return !stat(path, &st);
}


int
vault_has_account(const char *user) {
  char path[PATH_MAX + 64];
  struct stat st;
  vault_path(user, path, sizeof(path));
  return !stat(path, &st);
}


void
vault_login_email(const char *user, char *out, size_t outlen) {
  out[0] = 0;
  vault_lock();
  cJSON *v = vault_load(user);
  if(v && jstr(v, "email")) snprintf(out, outlen, "%s", jstr(v, "email"));
  cJSON_Delete(v);
  vault_unlock();
  if(!out[0]) {
    char lu[CFG_NAME_MAX + 1];
    snprintf(lu, sizeof(lu), "%s", user);
    lower(lu);
    cfg_lock();
    snprintf(out, outlen, "%s@%s", lu, cfg_settings()->vault_domain);
    cfg_unlock();
  }
}


int
vault_count_items(const char *user) {
  int n = 0;
  vault_lock();
  cJSON *v = vault_load(user);
  cJSON *it;
  if(v) cJSON_ArrayForEach(it, cJSON_GetObjectItem(v, "ciphers")) {
    if(jnum(it, "deleted", 0) <= 0) n++;
  }
  cJSON_Delete(v);
  vault_unlock();
  return n;
}


int
vault_ensure(const char *user, const char *password) {
  user_t u;
  if(!password || !password[0] || cfg_get_user(user, &u) || !u.vault) return -1;
  memset(&u, 0, sizeof(u));
  if(vault_has_account(user)) return 0;

  char email[CFG_NAME_MAX + 80], lu[CFG_NAME_MAX + 1], id[37], aad[96];
  char sealed[CRYPT_SEAL_HEX + 1];
  uint8_t ukey[64], *p8 = NULL;
  size_t p8len = 0;
  char *pub = NULL, *priv = NULL;
  int r = -1;

  snprintf(lu, sizeof(lu), "%s", user);
  lower(lu);
  cfg_lock();
  snprintf(email, sizeof(email), "%s@%s", lu, cfg_settings()->vault_domain);
  cfg_unlock();

  cJSON *v = cJSON_CreateObject();
  bw_uuid(id);
  jset_num(v, "v", 1);
  jset_str(v, "id", id);
  jset_str(v, "name", user);
  jset_str(v, "email", email);
  jset_num(v, "kdf", 0);
  jset_num(v, "iter", BW_KDF_ITER);
  jset_num(v, "created", (double)bw_now_us());
  bw_random(ukey, sizeof(ukey));
  if(set_master(v, password, ukey)) goto out;
  if(bw_rsa_keypair(&p8, &p8len, &pub)) goto out;
  if(!(priv = bw_enc(ukey, p8, p8len))) goto out;
  jset_str(v, "pub", pub);
  jset_str(v, "priv", priv);
  user_aad(user, aad, sizeof(aad));
  if(cfg_seal(aad, ukey, sizeof(ukey), sealed, sizeof(sealed))) goto out;
  jset_str(v, "ukm", sealed);
  jset(v, "folders", cJSON_CreateArray());
  jset(v, "ciphers", cJSON_CreateArray());

  vault_lock();
  if(vault_has_account(user)) r = 0;            /* otra petición la creó a la vez */
  else r = vault_save(user, v);
  vault_unlock();
  if(!r) LOG_PRINTF("ps5share: creado el gestor de contraseñas de '%s' (%s)\n", user, email);
 out:
  memset(ukey, 0, sizeof(ukey));
  if(p8) {
    memset(p8, 0, p8len);
    free(p8);
  }
  free(pub);
  free(priv);
  cJSON_Delete(v);
  return r;
}


int
vault_ensure_stored(const char *user) {
  char pass[CRYPT_SEAL_MAX + 1];
  if(vault_has_account(user)) return 0;
  if(cfg_get_password(user, pass, sizeof(pass))) return -1;
  int r = vault_ensure(user, pass);
  memset(pass, 0, sizeof(pass));
  return r;
}


void
vault_password_changed(const char *user, const char *newpass) {
  uint8_t ukey[64];
  if(!newpass || !newpass[0]) return;
  vault_lock();
  cJSON *v = vault_load(user);
  vault_unlock();
  if(!v) {
    vault_ensure(user, newpass);
    return;
  }
  if(vault_user_key(v, user, ukey)) {
    LOG_PRINTF("ps5share: no se pudo abrir la clave del gestor de '%s'\n", user);
    cJSON_Delete(v);
    return;
  }
  cJSON *tmp = cJSON_Duplicate(v, 1);
  int ok = !set_master(tmp, newpass, ukey);        /* lento: fuera del lock */
  memset(ukey, 0, sizeof(ukey));
  if(ok) {
    vault_lock();
    cJSON *cur = vault_load(user);
    if(cur) {
      const char *fields[] = {"key", "mphSalt", "mph", "sstamp", "devices", "rev"};
      for(size_t i=0; i<sizeof(fields)/sizeof(fields[0]); i++) {
        jset(cur, fields[i], cJSON_Duplicate(cJSON_GetObjectItem(tmp, fields[i]), 1));
      }
      vault_save(user, cur);
      cJSON_Delete(cur);
    }
    vault_unlock();
  }
  cJSON_Delete(tmp);
  cJSON_Delete(v);
}


void
vault_user_deleted(const char *user) {
  char path[PATH_MAX + 64], bak[PATH_MAX + 80];
  vault_lock();
  vault_path(user, path, sizeof(path));
  snprintf(bak, sizeof(bak), "%s.borrado", path);
  rename(path, bak);      /* se conserva por si fue un error */
  vault_unlock();
}


static int
copy_file(const char *from, const char *to) {
  int in = open(from, O_RDONLY), out = -1, r = -1;
  char buf[65536];
  if(in < 0) return -1;
  out = open(to, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if(out < 0) goto done;
  for(;;) {
    ssize_t n = read(in, buf, sizeof(buf));
    if(n < 0) goto done;
    if(n == 0) break;
    if(write(out, buf, (size_t)n) != n) goto done;
  }
  r = fsync(out);
 done:
  close(in);
  if(out >= 0) close(out);
  if(r) unlink(to);
  return r;
}


int
vault_move_dir(const char *from, const char *to, char *err, size_t errlen) {
  DIR *d;
  struct dirent *e;
  int moved = 0;
  if(!strcmp(from, to)) return 0;
  mkdir_p(to);
  struct stat st;
  if(stat(to, &st) || !S_ISDIR(st.st_mode)) {
    snprintf(err, errlen, "No se pudo crear la carpeta '%s': %s", to, strerror(errno));
    return -1;
  }
  vault_lock();
  if(!(d = opendir(from))) {
    vault_unlock();
    return 0;          /* nada que mover */
  }
  while((e = readdir(d))) {
    size_t l = strlen(e->d_name);
    if(l < 6 || strcmp(e->d_name + l - 5, ".json")) continue;
    char a[PATH_MAX * 2], b[PATH_MAX * 2];
    snprintf(a, sizeof(a), "%s/%s", from, e->d_name);
    snprintf(b, sizeof(b), "%s/%s", to, e->d_name);
    if(!stat(b, &st)) continue;      /* ya existe en el destino: no se pisa */
    if(rename(a, b) && (copy_file(a, b) || unlink(a))) {
      snprintf(err, errlen, "No se pudo mover '%s': %s", e->d_name, strerror(errno));
      closedir(d);
      vault_unlock();
      return -1;
    }
    moved++;
  }
  closedir(d);
  vault_unlock();
  if(moved) LOG_PRINTF("ps5share: %d bóveda(s) movidas a %s\n", moved, to);
  return 0;
}


/* ------------------------------------------------------------------ */
/* Respuestas de la API                                                */
/* ------------------------------------------------------------------ */

static int
bw_send(req_t *r, int code, cJSON *j) {
  char *s = cJSON_PrintUnformatted(j);
  cJSON_Delete(j);
  if(!s) return send_err(r, 500, "Sin memoria");
  int ret = send_body(r, code, "application/json; charset=utf-8", s, strlen(s), NULL);
  free(s);
  return ret;
}


static int
bw_fail(req_t *r, int code, const char *msg) {
  cJSON *j = cJSON_CreateObject();
  jset_str(j, "message", msg);
  cJSON *ve = cJSON_CreateObject();
  cJSON *arr = cJSON_CreateArray();
  cJSON_AddItemToArray(arr, cJSON_CreateString(msg));
  cJSON_AddItemToObject(ve, "", arr);
  jset(j, "validationErrors", ve);
  cJSON *em = cJSON_CreateObject();
  jset_str(em, "message", msg);
  jset_str(em, "object", "error");
  jset(j, "errorModel", em);
  jset_str(j, "error", "");
  jset_str(j, "error_description", "");
  jset(j, "exceptionMessage", cJSON_CreateNull());
  jset(j, "exceptionStackTrace", cJSON_CreateNull());
  jset(j, "innerExceptionMessage", cJSON_CreateNull());
  jset_str(j, "object", "error");
  return bw_send(r, code, j);
}


/* Error de /identity/connect/token (OAuth). */
static int
bw_grant_fail(req_t *r, const char *msg) {
  cJSON *j = cJSON_CreateObject();
  jset_str(j, "error", "invalid_grant");
  jset_str(j, "error_description", "invalid_username_or_password");
  cJSON *em = cJSON_CreateObject();
  jset_str(em, "Message", msg);
  jset_str(em, "Object", "error");
  jset(j, "ErrorModel", em);
  jset_str(j, "message", msg);
  return bw_send(r, 400, j);
}


static int
bw_empty(req_t *r) {
  return send_body(r, 200, "application/json; charset=utf-8", "", 0, NULL);
}


static int
bw_list(req_t *r, cJSON *arr) {
  cJSON *j = cJSON_CreateObject();
  jset(j, "data", arr ? arr : cJSON_CreateArray());
  jset_str(j, "object", "list");
  jset(j, "continuationToken", cJSON_CreateNull());
  return bw_send(r, 200, j);
}


/* ------------------------------------------------------------------ */
/* Objetos de la API                                                   */
/* ------------------------------------------------------------------ */

static cJSON *
profile_json(const cJSON *v) {
  cJSON *p = cJSON_CreateObject();
  jset_num(p, "_status", 0);
  cJSON *ak = cJSON_CreateObject();
  cJSON *kp = cJSON_CreateObject();
  jset_str(kp, "wrappedPrivateKey", jstr(v, "priv"));
  jset_str(kp, "publicKey", jstr(v, "pub"));
  jset(kp, "signedPublicKey", cJSON_CreateNull());
  jset_str(kp, "object", "publicKeyEncryptionKeyPair");
  jset(ak, "publicKeyEncryptionKeyPair", kp);
  jset(ak, "securityState", cJSON_CreateNull());
  jset(ak, "signatureKeyPair", cJSON_CreateNull());
  jset_str(ak, "object", "privateKeys");
  jset(p, "accountKeys", ak);
  jset_str(p, "id", jstr(v, "id"));
  jset_str(p, "name", jstr(v, "name"));
  jset_str(p, "email", jstr(v, "email"));
  jset(p, "emailVerified", cJSON_CreateTrue());
  jset(p, "premium", cJSON_CreateTrue());
  jset(p, "premiumFromOrganization", cJSON_CreateFalse());
  jset_str(p, "culture", "es-ES");
  jset(p, "twoFactorEnabled", cJSON_CreateFalse());
  jset_str(p, "key", jstr(v, "key"));
  jset_str(p, "privateKey", jstr(v, "priv"));
  jset_str(p, "securityStamp", jstr(v, "sstamp"));
  jset(p, "organizations", cJSON_CreateArray());
  jset(p, "organizationsNew", cJSON_CreateArray());
  jset(p, "providers", cJSON_CreateArray());
  jset(p, "providerOrganizations", cJSON_CreateArray());
  jset(p, "forcePasswordReset", cJSON_CreateFalse());
  jset(p, "avatarColor", cJSON_CreateNull());
  jset(p, "usesKeyConnector", cJSON_CreateFalse());
  jset_iso(p, "creationDate", jnum(v, "created", 0));
  jset_str(p, "object", "profile");
  return p;
}


static cJSON *
folder_json(const cJSON *f) {
  cJSON *o = cJSON_CreateObject();
  jset_str(o, "id", jstr(f, "id"));
  jset_iso(o, "revisionDate", jnum(f, "rev", 0));
  jset_str(o, "name", jstr(f, "name"));
  jset_str(o, "object", "folder");
  return o;
}


static cJSON *
cipher_json(const cJSON *c) {
  int type = (int)jnum(c, "type", 1);
  cJSON *o = cJSON_CreateObject();
  jset_str(o, "object", "cipherDetails");
  jset_str(o, "id", jstr(c, "id"));
  jset_num(o, "type", type);
  jset_iso(o, "creationDate", jnum(c, "created", 0));
  jset_iso(o, "revisionDate", jnum(c, "rev", 0));
  jset_iso(o, "deletedDate", jnum(c, "deleted", 0));
  jset_num(o, "reprompt", jnum(c, "reprompt", 0) == 1 ? 1 : 0);
  jset(o, "organizationId", cJSON_CreateNull());
  jset_str(o, "key", jstr(c, "key"));
  jset(o, "attachments", cJSON_CreateNull());
  jset(o, "organizationUseTotp", cJSON_CreateTrue());
  jset(o, "collectionIds", cJSON_CreateArray());
  jset_str(o, "name", jstr(c, "name"));
  jset_str(o, "notes", jstr(c, "notes"));
  const cJSON *f = cJSON_GetObjectItem(c, "fields");
  jset(o, "fields", cJSON_IsArray(f) ? cJSON_Duplicate(f, 1) : cJSON_CreateArray());
  const cJSON *ph = cJSON_GetObjectItem(c, "passwordHistory");
  jset(o, "passwordHistory", cJSON_IsArray(ph) ? cJSON_Duplicate(ph, 1) : cJSON_CreateArray());
  for(int t=1; t<=NTYPES; t++) jset(o, TYPEKEYS[t], cJSON_CreateNull());
  if(type >= 1 && type <= NTYPES) {
    const cJSON *td = cJSON_GetObjectItem(c, TYPEKEYS[type]);
    cJSON *d = cJSON_IsObject(td) ? cJSON_Duplicate(td, 1) : cJSON_CreateObject();
    if(type == 1) {
      const cJSON *uris = cJSON_GetObjectItem(d, "uris");
      const cJSON *first = cJSON_IsArray(uris) ? cJSON_GetArrayItem(uris, 0) : NULL;
      const char *u = first ? jstr(first, "uri") : NULL;
      jset_str(d, "uri", u);
    } else if(type == 2 && !cJSON_IsNumber(cJSON_GetObjectItem(d, "type"))) {
      jset_num(d, "type", 0);
    }
    jset(o, TYPEKEYS[type], d);
  }
  const char *fid = jstr(c, "folderId");
  jset_str(o, "folderId", fid && fid[0] ? fid : NULL);
  jset(o, "favorite", cJSON_CreateBool(jbool(c, "favorite")));
  jset(o, "archivedDate", cJSON_CreateNull());
  jset(o, "edit", cJSON_CreateTrue());
  jset(o, "viewPassword", cJSON_CreateTrue());
  cJSON *perm = cJSON_CreateObject();
  jset(perm, "delete", cJSON_CreateTrue());
  jset(perm, "restore", cJSON_CreateTrue());
  jset(o, "permissions", perm);
  return o;
}


/* Quita las claves "response" que a veces mandan los clientes. */
static void
strip_response(cJSON *o) {
  if(!cJSON_IsObject(o)) return;
  cJSON_DeleteItemFromObject(o, "response");
  cJSON *uris = cJSON_GetObjectItem(o, "uris");
  cJSON *u;
  if(cJSON_IsArray(uris)) cJSON_ArrayForEach(u, uris) cJSON_DeleteItemFromObject(u, "response");
}


/* Copia los datos de un elemento recibido (DATA) en el guardado (C).
   Devuelve NULL o un mensaje de error. */
static const char *
cipher_from_data(cJSON *v, cJSON *c, const cJSON *data, int check_rev) {
  int type = (int)jnum(data, "type", 0);
  if(type < 1 || type > NTYPES) return "Tipo de elemento no válido";
  const char *name = jstr(data, "name");
  if(!name) return "Falta el nombre";
  const cJSON *td = cJSON_GetObjectItem(data, TYPEKEYS[type]);
  if(!cJSON_IsObject(td)) return "Faltan los datos del elemento";
  const char *notes = jstr(data, "notes");
  if(notes && strlen(notes) > 100000) return "Las notas son demasiado largas";
  if(cJSON_GetObjectItem(data, "organizationId") &&
     !cJSON_IsNull(cJSON_GetObjectItem(data, "organizationId"))) {
    return "Este servidor no tiene organizaciones";
  }

  const char *fid = jstr(data, "folderId");
  if(fid && !fid[0]) fid = NULL;
  if(fid && !vault_find_id(cJSON_GetObjectItem(v, "folders"), fid)) {
    return "La carpeta no existe";
  }

  if(check_rev) {
    const char *lk = jstr(data, "lastKnownRevisionDate");
    long long known = lk ? bw_parse_iso(lk) : -1;
    if(known > 0 && jnum(c, "rev", 0) - known > 1000000LL) {
      return "La copia de este elemento está desactualizada. Sincroniza e inténtalo otra vez.";
    }
  }

  jset_num(c, "type", type);
  jset_str(c, "name", name);
  jset_str(c, "notes", notes);
  jset_str(c, "key", jstr(data, "key"));
  jset_num(c, "reprompt", jnum(data, "reprompt", 0) == 1 ? 1 : 0);
  jset(c, "favorite", cJSON_CreateBool(jbool(data, "favorite")));
  jset_str(c, "folderId", fid);
  const cJSON *f = cJSON_GetObjectItem(data, "fields");
  jset(c, "fields", cJSON_IsArray(f) ? cJSON_Duplicate(f, 1) : cJSON_CreateNull());
  const cJSON *ph = cJSON_GetObjectItem(data, "passwordHistory");
  jset(c, "passwordHistory", cJSON_IsArray(ph) ? cJSON_Duplicate(ph, 1) : cJSON_CreateNull());
  for(int t=1; t<=NTYPES; t++) cJSON_DeleteItemFromObjectCaseSensitive(c, TYPEKEYS[t]);
  cJSON *d = cJSON_Duplicate(td, 1);
  strip_response(d);
  jset(c, TYPEKEYS[type], d);
  long long now = bw_now_us();
  if(jnum(c, "created", 0) <= 0) jset_num(c, "created", (double)now);
  jset_num(c, "rev", (double)now);
  return NULL;
}


static cJSON *
cipher_new(cJSON *v) {
  char id[37];
  cJSON *c = cJSON_CreateObject();
  bw_uuid(id);
  jset_str(c, "id", id);
  cJSON_AddItemToArray(cJSON_GetObjectItem(v, "ciphers"), c);
  return c;
}


static void
array_remove(cJSON *arr, cJSON *item) {
  int i = 0;
  cJSON *it;
  cJSON_ArrayForEach(it, arr) {
    if(it == item) {
      cJSON_DeleteItemFromArray(arr, i);
      return;
    }
    i++;
  }
}


/* ------------------------------------------------------------------ */
/* Identidad: prelogin y tokens                                        */
/* ------------------------------------------------------------------ */

/* Busca el usuario por su correo de Bitwarden.  Con vault_lock tomado.
   Devuelve la bóveda cargada (o NULL). */
static cJSON *
find_by_email(const char *email, user_t *u) {
  char local[CFG_NAME_MAX + 1], name[CFG_NAME_MAX + 1] = "";
  const char *at = strchr(email, '@');
  if(!at || (size_t)(at - email) > CFG_NAME_MAX) return NULL;
  memcpy(local, email, (size_t)(at - email));
  local[at - email] = 0;
  cfg_lock();
  for(int i=0; i<cfg_nusers(); i++) {
    if(!strcasecmp(cfg_user_at(i)->name, local)) {
      snprintf(name, sizeof(name), "%s", cfg_user_at(i)->name);
      break;
    }
  }
  cfg_unlock();
  if(!name[0] || cfg_get_user(name, u)) return NULL;
  cJSON *v = vault_load(name);
  const char *e = v ? jstr(v, "email") : NULL;
  if(!e || strcasecmp(e, email)) {
    cJSON_Delete(v);
    return NULL;
  }
  return v;
}


static int
vault_globally_enabled(void) {
  cfg_lock();
  int e = cfg_settings()->vault_enabled;
  cfg_unlock();
  return e;
}


static int
h_prelogin(req_t *r) {
  int iter = BW_KDF_ITER;
  if(read_body_max(r, HTTP_BODY_MAX)) return bw_fail(r, 400, "Petición no válida");
  cJSON *b = cJSON_Parse(r->body ? r->body : "");
  const char *email = b ? jstr(b, "email") : NULL;
  if(email) {
    user_t u;
    vault_lock();
    cJSON *v = find_by_email(email, &u);
    if(v) iter = (int)jnum(v, "iter", BW_KDF_ITER);
    cJSON_Delete(v);
    vault_unlock();
    memset(&u, 0, sizeof(u));
  }
  cJSON_Delete(b);
  cJSON *j = cJSON_CreateObject();
  jset_num(j, "kdf", 0);
  jset_num(j, "kdfIterations", iter);
  jset(j, "kdfMemory", cJSON_CreateNull());
  jset(j, "kdfParallelism", cJSON_CreateNull());
  cJSON *ks = cJSON_CreateObject();
  jset_num(ks, "iterations", iter);
  jset_num(ks, "kdfType", 0);
  jset(ks, "memory", cJSON_CreateNull());
  jset(ks, "parallelism", cJSON_CreateNull());
  jset(j, "kdfSettings", ks);
  jset(j, "salt", cJSON_CreateNull());
  return bw_send(r, 200, j);
}


static char *
make_access_token(const cJSON *v, const char *user, const char *device, const char *client) {
  long long now = time(NULL);
  cJSON *p = cJSON_CreateObject();
  jset_num(p, "nbf", (double)now);
  jset_num(p, "exp", (double)(now + ACCESS_TTL));
  jset_str(p, "iss", "ps5nas|login");
  jset_str(p, "sub", jstr(v, "id"));
  jset(p, "premium", cJSON_CreateTrue());
  jset_str(p, "name", user);
  jset_str(p, "email", jstr(v, "email"));
  jset(p, "email_verified", cJSON_CreateTrue());
  jset_str(p, "sstamp", jstr(v, "sstamp"));
  jset_str(p, "device", device);
  jset_str(p, "client_id", client && client[0] ? client : "undefined");
  cJSON *sc = cJSON_CreateArray();
  cJSON_AddItemToArray(sc, cJSON_CreateString("api"));
  cJSON_AddItemToArray(sc, cJSON_CreateString("offline_access"));
  jset(p, "scope", sc);
  cJSON *amr = cJSON_CreateArray();
  cJSON_AddItemToArray(amr, cJSON_CreateString("Application"));
  jset(p, "amr", amr);
  jset_str(p, "pu", user);
  char *s = cJSON_PrintUnformatted(p);
  cJSON_Delete(p);
  if(!s) return NULL;
  char *jwt = bw_jwt_sign(g_jwt_key, s);
  free(s);
  return jwt;
}


static int
h_token(req_t *r) {
  char grant[32], email[256], hash[128], device[128], dname[128], dtype[16], client[32];
  uint32_t ip = r->peer.sin_addr.s_addr;
  user_t u;

  if(read_body_max(r, HTTP_BODY_MAX)) return bw_grant_fail(r, "Petición no válida");
  get_param(r->body, "grant_type", grant, sizeof(grant));
  get_param(r->body, "client_id", client, sizeof(client));
  get_param(r->body, "deviceIdentifier", device, sizeof(device));
  get_param(r->body, "deviceName", dname, sizeof(dname));
  get_param(r->body, "deviceType", dtype, sizeof(dtype));

  if(!strcmp(grant, "refresh_token")) {
    char rt[256], uname[CFG_NAME_MAX + 1], th[65];
    uint8_t d[32];
    get_param(r->body, "refresh_token", rt, sizeof(rt));
    char *dot = strrchr(rt, '.');
    if(!dot || (size_t)(dot - rt) > CFG_NAME_MAX) return bw_grant_fail(r, "Sesión no válida");
    memcpy(uname, rt, (size_t)(dot - rt));
    uname[dot - rt] = 0;
    bw_sha256(rt, strlen(rt), d);
    to_hex(d, 32, th);
    if(cfg_get_user(uname, &u) || !u.enabled || !u.vault || u.must_chpass ||
       !vault_globally_enabled()) {
      return bw_grant_fail(r, "La cuenta no está disponible");
    }
    vault_lock();
    cJSON *v = vault_load(uname);
    cJSON *dev = NULL, *it;
    if(v) cJSON_ArrayForEach(it, cJSON_GetObjectItem(v, "devices")) {
      const char *h = jstr(it, "rt");
      if(h && strlen(h) == 64 && bw_consttime_eq(h, th, 64)) dev = it;
    }
    if(!dev) {
      cJSON_Delete(v);
      vault_unlock();
      return bw_grant_fail(r, "La sesión ha caducado. Vuelve a iniciar sesión.");
    }
    jset_num(dev, "used", (double)bw_now_us());
    vault_save(uname, v);
    char *at = make_access_token(v, uname, jstr(dev, "id"), client);
    cJSON_Delete(v);
    vault_unlock();
    if(!at) return bw_fail(r, 500, "Sin memoria");
    cJSON *j = cJSON_CreateObject();
    jset_str(j, "refresh_token", rt);
    jset_str(j, "access_token", at);
    jset_num(j, "expires_in", ACCESS_TTL);
    jset_str(j, "token_type", "Bearer");
    jset_str(j, "scope", "api offline_access");
    free(at);
    return bw_send(r, 200, j);
  }

  if(strcmp(grant, "password")) return bw_grant_fail(r, "Tipo de inicio de sesión no admitido");
  if(rl_blocked(ip)) return bw_fail(r, 429, "Demasiados intentos. Espera unos minutos.");
  get_param(r->body, "username", email, sizeof(email));
  get_param(r->body, "password", hash, sizeof(hash));
  if(!vault_globally_enabled()) {
    return bw_grant_fail(r, "El gestor de contraseñas está desactivado en PS5NAS");
  }

  vault_lock();
  cJSON *v = find_by_email(email, &u);
  if(!v || check_master_hash(v, hash)) {
    cJSON_Delete(v);
    vault_unlock();
    rl_fail(ip);
    sleep(1);
    return bw_grant_fail(r, "Usuario o contraseña incorrectos");
  }
  const char *why = NULL;
  if(!u.enabled) why = "Tu cuenta de PS5NAS está desactivada";
  else if(!u.vault) why = "El administrador no te ha activado el gestor de contraseñas";
  else if(u.must_chpass) why = "Antes tienes que cambiar tu contraseña temporal en la web de PS5NAS";
  if(why) {
    cJSON_Delete(v);
    vault_unlock();
    return bw_grant_fail(r, why);
  }
  rl_clear(ip);

  /* Dispositivo y token de refresco. */
  char devid[128], rt[CFG_NAME_MAX + 72], rhex[65], th[65];
  uint8_t rnd[32], d[32];
  if(device[0]) snprintf(devid, sizeof(devid), "%s", device);
  else bw_uuid(devid);
  bw_random(rnd, sizeof(rnd));
  to_hex(rnd, sizeof(rnd), rhex);
  snprintf(rt, sizeof(rt), "%s.%s", u.name, rhex);
  bw_sha256(rt, strlen(rt), d);
  to_hex(d, 32, th);

  cJSON *devs = cJSON_GetObjectItem(v, "devices");
  if(!cJSON_IsArray(devs)) {
    devs = cJSON_CreateArray();
    jset(v, "devices", devs);
  }
  cJSON *dev = vault_find_id(devs, devid);
  if(!dev) {
    while(cJSON_GetArraySize(devs) >= MAX_DEVICES) {
      /* Se olvida el que lleva más tiempo sin usarse. */
      cJSON *it, *old = NULL;
      cJSON_ArrayForEach(it, devs) {
        if(!old || jnum(it, "used", 0) < jnum(old, "used", 0)) old = it;
      }
      array_remove(devs, old);
    }
    dev = cJSON_CreateObject();
    jset_str(dev, "id", devid);
    jset_num(dev, "created", (double)bw_now_us());
    cJSON_AddItemToArray(devs, dev);
  }
  jset_str(dev, "name", dname[0] ? dname : "?");
  jset_num(dev, "type", atoi(dtype));
  jset_str(dev, "rt", th);
  jset_num(dev, "used", (double)bw_now_us());
  if(vault_save(u.name, v)) {
    cJSON_Delete(v);
    vault_unlock();
    return bw_fail(r, 500, "No se pudo guardar la sesión");
  }
  char *at = make_access_token(v, u.name, devid, client);

  cJSON *j = cJSON_CreateObject();
  jset_str(j, "access_token", at);
  jset_num(j, "expires_in", ACCESS_TTL);
  jset_str(j, "token_type", "Bearer");
  jset_str(j, "refresh_token", rt);
  jset_str(j, "Key", jstr(v, "key"));
  jset_str(j, "PrivateKey", jstr(v, "priv"));
  jset_num(j, "Kdf", 0);
  jset_num(j, "KdfIterations", (double)jnum(v, "iter", BW_KDF_ITER));
  jset(j, "KdfMemory", cJSON_CreateNull());
  jset(j, "KdfParallelism", cJSON_CreateNull());
  jset(j, "ForcePasswordReset", cJSON_CreateFalse());
  jset(j, "ResetMasterPassword", cJSON_CreateFalse());
  cJSON *mpp = cJSON_CreateObject();
  jset_str(mpp, "Object", "masterPasswordPolicy");
  jset(j, "MasterPasswordPolicy", mpp);
  jset_str(j, "scope", "api offline_access");
  jset(j, "unofficialServer", cJSON_CreateTrue());
  cJSON *ak = cJSON_CreateObject();
  cJSON *kp = cJSON_CreateObject();
  jset_str(kp, "wrappedPrivateKey", jstr(v, "priv"));
  jset_str(kp, "publicKey", jstr(v, "pub"));
  jset_str(kp, "Object", "publicKeyEncryptionKeyPair");
  jset(ak, "publicKeyEncryptionKeyPair", kp);
  jset_str(ak, "Object", "privateKeys");
  jset(j, "AccountKeys", ak);
  cJSON *udo = cJSON_CreateObject();
  jset(udo, "HasMasterPassword", cJSON_CreateTrue());
  cJSON *mpu = cJSON_CreateObject();
  cJSON *kdf = cJSON_CreateObject();
  jset_num(kdf, "KdfType", 0);
  jset_num(kdf, "Iterations", (double)jnum(v, "iter", BW_KDF_ITER));
  jset(kdf, "Memory", cJSON_CreateNull());
  jset(kdf, "Parallelism", cJSON_CreateNull());
  jset(mpu, "Kdf", kdf);
  jset_str(mpu, "MasterKeyEncryptedUserKey", jstr(v, "key"));
  jset_str(mpu, "MasterKeyWrappedUserKey", jstr(v, "key"));
  jset_str(mpu, "Salt", jstr(v, "email"));
  jset(udo, "MasterPasswordUnlock", mpu);
  jset_str(udo, "Object", "userDecryptionOptions");
  jset(j, "UserDecryptionOptions", udo);
  free(at);
  cJSON_Delete(v);
  vault_unlock();
  LOG_PRINTF("ps5share: '%s' inició sesión en el gestor desde '%s'\n", u.name, dname);
  memset(&u, 0, sizeof(u));
  return bw_send(r, 200, j);
}


/* ------------------------------------------------------------------ */
/* API autenticada                                                     */
/* ------------------------------------------------------------------ */

typedef struct bwctx {
  user_t u;
  cJSON *v;
  int    dirty;
  char   device[128];
} bwctx_t;


/* Comprueba el token.  Si vale, deja vault_lock tomado y la bóveda cargada. */
static int
bw_auth(req_t *r, bwctx_t *c) {
  const char *tok = NULL;
  if(!strncasecmp(r->auth, "Bearer ", 7)) tok = r->auth + 7;
  if(!tok || !tok[0]) return -1;
  char *payload = bw_jwt_verify(g_jwt_key, tok);
  if(!payload) return -1;
  cJSON *p = cJSON_Parse(payload);
  free(payload);
  if(!p) return -1;
  long long exp = jnum(p, "exp", 0);
  const char *pu = jstr(p, "pu"), *ss = jstr(p, "sstamp"), *dev = jstr(p, "device");
  int ok = exp > (long long)time(NULL) && pu && ss && !cfg_get_user(pu, &c->u) &&
           c->u.enabled && c->u.vault && !c->u.must_chpass && vault_globally_enabled();
  if(ok) {
    snprintf(c->device, sizeof(c->device), "%s", dev ? dev : "");
    vault_lock();
    c->v = vault_load(c->u.name);
    const char *vs = c->v ? jstr(c->v, "sstamp") : NULL;
    if(!vs || strcmp(vs, ss)) {
      cJSON_Delete(c->v);
      c->v = NULL;
      vault_unlock();
      ok = 0;
    }
  }
  cJSON_Delete(p);
  return ok ? 0 : -1;
}


static cJSON *
parse_body(req_t *r) {
  if(read_body_max(r, HTTP_BODY_MAX_BIG)) return NULL;
  return cJSON_Parse(r->body ? r->body : "");
}


static int
h_sync(req_t *r, bwctx_t *c) {
  char ex[16] = "";
  get_param(r->query, "excludeDomains", ex, sizeof(ex));
  cJSON *j = cJSON_CreateObject();
  jset(j, "profile", profile_json(c->v));
  cJSON *fa = cJSON_CreateArray(), *it;
  cJSON_ArrayForEach(it, cJSON_GetObjectItem(c->v, "folders")) {
    cJSON_AddItemToArray(fa, folder_json(it));
  }
  jset(j, "folders", fa);
  jset(j, "collections", cJSON_CreateArray());
  jset(j, "policies", cJSON_CreateArray());
  jset(j, "policiesNew", cJSON_CreateArray());
  cJSON *ca = cJSON_CreateArray();
  cJSON_ArrayForEach(it, cJSON_GetObjectItem(c->v, "ciphers")) {
    cJSON_AddItemToArray(ca, cipher_json(it));
  }
  jset(j, "ciphers", ca);
  if(!strcasecmp(ex, "true")) {
    jset(j, "domains", cJSON_CreateNull());
  } else {
    cJSON *d = cJSON_CreateObject();
    jset(d, "equivalentDomains", cJSON_CreateArray());
    jset(d, "globalEquivalentDomains", cJSON_CreateArray());
    jset_str(d, "object", "domains");
    jset(j, "domains", d);
  }
  jset(j, "sends", cJSON_CreateArray());
  cJSON *ud = cJSON_CreateObject();
  cJSON *mpu = cJSON_CreateObject();
  cJSON *kdf = cJSON_CreateObject();
  jset_num(kdf, "kdfType", 0);
  jset_num(kdf, "iterations", (double)jnum(c->v, "iter", BW_KDF_ITER));
  jset(kdf, "memory", cJSON_CreateNull());
  jset(kdf, "parallelism", cJSON_CreateNull());
  jset(mpu, "kdf", kdf);
  jset_str(mpu, "masterKeyEncryptedUserKey", jstr(c->v, "key"));
  jset_str(mpu, "masterKeyWrappedUserKey", jstr(c->v, "key"));
  jset_str(mpu, "salt", jstr(c->v, "email"));
  jset(ud, "masterPasswordUnlock", mpu);
  jset_str(ud, "userKeyId", jstr(c->v, "keyId"));
  jset(j, "userDecryption", ud);
  jset_str(j, "object", "sync");
  return bw_send(r, 200, j);
}


static int
h_folders(req_t *r, bwctx_t *c, int nseg, char **seg) {
  cJSON *folders = cJSON_GetObjectItem(c->v, "folders");
  if(!cJSON_IsArray(folders)) {
    folders = cJSON_CreateArray();
    jset(c->v, "folders", folders);
  }
  if(nseg == 1) {
    if(!strcmp(r->method, "GET")) {
      cJSON *a = cJSON_CreateArray(), *it;
      cJSON_ArrayForEach(it, folders) cJSON_AddItemToArray(a, folder_json(it));
      return bw_list(r, a);
    }
    if(!strcmp(r->method, "POST")) {
      cJSON *b = parse_body(r);
      const char *name = b ? jstr(b, "name") : NULL;
      if(!name) {
        cJSON_Delete(b);
        return bw_fail(r, 400, "Falta el nombre de la carpeta");
      }
      char id[37];
      cJSON *f = cJSON_CreateObject();
      const char *want = jstr(b, "id");
      if(want && strlen(want) == 36 && !vault_find_id(folders, want)) snprintf(id, sizeof(id), "%s", want);
      else bw_uuid(id);
      jset_str(f, "id", id);
      jset_str(f, "name", name);
      jset_num(f, "rev", (double)bw_now_us());
      cJSON_AddItemToArray(folders, f);
      cJSON_Delete(b);
      c->dirty = 1;
      return bw_send(r, 200, folder_json(f));
    }
    return bw_fail(r, 405, "Método no permitido");
  }
  cJSON *f = vault_find_id(folders, seg[1]);
  if(!f) return bw_fail(r, 404, "La carpeta no existe");
  int del = !strcmp(r->method, "DELETE") ||
            (nseg == 3 && !strcmp(seg[2], "delete") && !strcmp(r->method, "POST"));
  if(nseg == 2 && !strcmp(r->method, "GET")) return bw_send(r, 200, folder_json(f));
  if(del) {
    cJSON *it;
    cJSON_ArrayForEach(it, cJSON_GetObjectItem(c->v, "ciphers")) {
      const char *fid = jstr(it, "folderId");
      if(fid && !strcasecmp(fid, seg[1])) {
        jset(it, "folderId", cJSON_CreateNull());
        jset_num(it, "rev", (double)bw_now_us());
      }
    }
    array_remove(folders, f);
    c->dirty = 1;
    return bw_empty(r);
  }
  if(nseg == 2 && (!strcmp(r->method, "PUT") || !strcmp(r->method, "POST"))) {
    cJSON *b = parse_body(r);
    const char *name = b ? jstr(b, "name") : NULL;
    if(!name) {
      cJSON_Delete(b);
      return bw_fail(r, 400, "Falta el nombre de la carpeta");
    }
    jset_str(f, "name", name);
    jset_num(f, "rev", (double)bw_now_us());
    cJSON_Delete(b);
    c->dirty = 1;
    return bw_send(r, 200, folder_json(f));
  }
  return bw_fail(r, 404, "No encontrado");
}


/* Lista de ids del cuerpo {"ids":[...]} */
static cJSON *
body_ids(cJSON *b) {
  cJSON *ids = cJSON_GetObjectItem(b, "ids");
  return cJSON_IsArray(ids) ? ids : NULL;
}


static int
h_import(req_t *r, bwctx_t *c) {
  cJSON *b = parse_body(r);
  if(!b) return bw_fail(r, 400, "Datos de importación no válidos");
  cJSON *folders = cJSON_GetObjectItem(c->v, "folders");
  cJSON *ciphers = cJSON_GetObjectItem(b, "ciphers");
  cJSON *nf = cJSON_GetObjectItem(b, "folders");
  cJSON *rel = cJSON_GetObjectItem(b, "folderRelationships");
  int nfold = cJSON_GetArraySize(nf);
  char (*fids)[37] = calloc((size_t)(nfold > 0 ? nfold : 1), 37);
  if(!fids) {
    cJSON_Delete(b);
    return bw_fail(r, 500, "Sin memoria");
  }
  int i = 0;
  cJSON *it;
  cJSON_ArrayForEach(it, nf) {
    const char *id = jstr(it, "id");
    if(id && vault_find_id(folders, id)) {
      snprintf(fids[i], 37, "%s", id);
    } else {
      cJSON *f = cJSON_CreateObject();
      bw_uuid(fids[i]);
      jset_str(f, "id", fids[i]);
      jset_str(f, "name", jstr(it, "name") ? jstr(it, "name") : "");
      jset_num(f, "rev", (double)bw_now_us());
      cJSON_AddItemToArray(folders, f);
    }
    i++;
  }
  int n = 0;
  const char *err = NULL;
  cJSON_ArrayForEach(it, ciphers) {
    /* Carpeta según folderRelationships (key = índice del elemento). */
    cJSON *rr;
    const char *fid = NULL;
    cJSON_ArrayForEach(rr, rel) {
      if(jnum(rr, "key", -1) == n) {
        long long fi = jnum(rr, "value", -1);
        if(fi >= 0 && fi < nfold) fid = fids[fi];
      }
    }
    cJSON *data = cJSON_Duplicate(it, 1);
    jset_str(data, "folderId", fid);
    cJSON_DeleteItemFromObject(data, "organizationId");
    cJSON *cc = cipher_new(c->v);
    err = cipher_from_data(c->v, cc, data, 0);
    cJSON_Delete(data);
    if(err) {
      array_remove(cJSON_GetObjectItem(c->v, "ciphers"), cc);
      break;
    }
    n++;
  }
  free(fids);
  cJSON_Delete(b);
  if(err) {
    /* No se guarda nada: la bóveda en memoria se descarta. */
    return bw_fail(r, 400, err);
  }
  c->dirty = 1;
  LOG_PRINTF("ps5share: '%s' importó %d elemento(s) en el gestor\n", c->u.name, n);
  return bw_empty(r);
}


static int
h_ciphers(req_t *r, bwctx_t *c, int nseg, char **seg) {
  cJSON *ciphers = cJSON_GetObjectItem(c->v, "ciphers");
  if(!cJSON_IsArray(ciphers)) {
    ciphers = cJSON_CreateArray();
    jset(c->v, "ciphers", ciphers);
  }
  const char *m = r->method;
  long long now = bw_now_us();

  if(nseg == 1) {
    if(!strcmp(m, "GET")) {
      cJSON *a = cJSON_CreateArray(), *it;
      cJSON_ArrayForEach(it, ciphers) cJSON_AddItemToArray(a, cipher_json(it));
      return bw_list(r, a);
    }
    if(!strcmp(m, "POST")) {
      cJSON *b = parse_body(r);
      if(!b) return bw_fail(r, 400, "Datos no válidos");
      cJSON *cc = cipher_new(c->v);
      const char *err = cipher_from_data(c->v, cc, b, 0);
      cJSON_Delete(b);
      if(err) return bw_fail(r, 400, err);
      c->dirty = 1;
      return bw_send(r, 200, cipher_json(cc));
    }
    if(!strcmp(m, "DELETE")) goto bulk_delete_hard;
    return bw_fail(r, 405, "Método no permitido");
  }

  const char *a1 = seg[1];
  if(nseg == 2 && !strcmp(a1, "create") && !strcmp(m, "POST")) {
    cJSON *b = parse_body(r);
    cJSON *data = b ? cJSON_GetObjectItem(b, "cipher") : NULL;
    if(!data) {
      cJSON_Delete(b);
      return bw_fail(r, 400, "Datos no válidos");
    }
    cJSON *cc = cipher_new(c->v);
    const char *err = cipher_from_data(c->v, cc, data, 0);
    cJSON_Delete(b);
    if(err) return bw_fail(r, 400, err);
    c->dirty = 1;
    return bw_send(r, 200, cipher_json(cc));
  }
  if(nseg == 2 && !strcmp(a1, "import") && !strcmp(m, "POST")) return h_import(r, c);
  if(nseg == 2 && !strcmp(a1, "purge") && !strcmp(m, "POST")) {
    cJSON *b = parse_body(r);
    int ok = b && !check_master_hash(c->v, jstr(b, "masterPasswordHash"));
    cJSON_Delete(b);
    if(!ok) return bw_fail(r, 400, "Contraseña incorrecta");
    jset(c->v, "ciphers", cJSON_CreateArray());
    jset(c->v, "folders", cJSON_CreateArray());
    c->dirty = 1;
    return bw_empty(r);
  }
  if(nseg == 2 && (!strcmp(a1, "delete") || !strcmp(a1, "restore") || !strcmp(a1, "move") ||
                   !strcmp(a1, "delete-admin"))) {
    if(!strcmp(a1, "delete") && !strcmp(m, "POST")) goto bulk_delete_hard;
    cJSON *b = parse_body(r);
    cJSON *ids = b ? body_ids(b) : NULL, *id;
    if(!ids) {
      cJSON_Delete(b);
      return bw_fail(r, 400, "Faltan los elementos");
    }
    cJSON *out = cJSON_CreateArray();
    const char *fid = jstr(b, "folderId");
    if(fid && !fid[0]) fid = NULL;
    if(!strcmp(a1, "move") && fid && !vault_find_id(cJSON_GetObjectItem(c->v, "folders"), fid)) {
      cJSON_Delete(b);
      cJSON_Delete(out);
      return bw_fail(r, 400, "La carpeta no existe");
    }
    cJSON_ArrayForEach(id, ids) {
      cJSON *cc = cJSON_IsString(id) ? vault_find_id(ciphers, id->valuestring) : NULL;
      if(!cc) continue;
      if(!strcmp(a1, "move")) {
        jset_str(cc, "folderId", fid);
      } else if(!strcmp(a1, "restore")) {
        cJSON_DeleteItemFromObject(cc, "deleted");
        cJSON_AddItemToArray(out, cipher_json(cc));
      } else {
        jset_num(cc, "deleted", (double)now);
      }
      jset_num(cc, "rev", (double)now);
    }
    cJSON_Delete(b);
    c->dirty = 1;
    if(!strcmp(a1, "restore")) return bw_list(r, out);
    cJSON_Delete(out);
    return bw_empty(r);
  }

  cJSON *cc = vault_find_id(ciphers, a1);
  if(!cc) return bw_fail(r, 404, "El elemento no existe");
  const char *a2 = nseg >= 3 ? seg[2] : "";

  if(nseg == 2 && !strcmp(m, "GET")) return bw_send(r, 200, cipher_json(cc));
  if(nseg == 3 && !strcmp(m, "GET") && (!strcmp(a2, "details") || !strcmp(a2, "admin"))) {
    return bw_send(r, 200, cipher_json(cc));
  }
  if((nseg == 2 && (!strcmp(m, "PUT") || !strcmp(m, "POST"))) ||
     (nseg == 3 && !strcmp(a2, "admin") && (!strcmp(m, "PUT") || !strcmp(m, "POST")))) {
    cJSON *b = parse_body(r);
    if(!b) return bw_fail(r, 400, "Datos no válidos");
    cJSON *backup = cJSON_Duplicate(cc, 1);
    const char *err = cipher_from_data(c->v, cc, b, 1);
    cJSON_Delete(b);
    if(err) {
      cJSON_ReplaceItemViaPointer(ciphers, cc, backup);
      return bw_fail(r, 400, err);
    }
    cJSON_Delete(backup);
    c->dirty = 1;
    return bw_send(r, 200, cipher_json(cc));
  }
  if(nseg == 3 && !strcmp(a2, "partial") && (!strcmp(m, "PUT") || !strcmp(m, "POST"))) {
    cJSON *b = parse_body(r);
    if(!b) return bw_fail(r, 400, "Datos no válidos");
    const char *fid = jstr(b, "folderId");
    if(fid && !fid[0]) fid = NULL;
    if(fid && !vault_find_id(cJSON_GetObjectItem(c->v, "folders"), fid)) {
      cJSON_Delete(b);
      return bw_fail(r, 400, "La carpeta no existe");
    }
    jset_str(cc, "folderId", fid);
    jset(cc, "favorite", cJSON_CreateBool(jbool(b, "favorite")));
    jset_num(cc, "rev", (double)now);
    cJSON_Delete(b);
    c->dirty = 1;
    return bw_send(r, 200, cipher_json(cc));
  }
  if((nseg == 3 && (!strcmp(a2, "delete") || !strcmp(a2, "delete-admin")) && !strcmp(m, "PUT"))) {
    jset_num(cc, "deleted", (double)now);
    jset_num(cc, "rev", (double)now);
    c->dirty = 1;
    return bw_empty(r);
  }
  if((nseg == 2 && !strcmp(m, "DELETE")) ||
     (nseg == 3 && !strcmp(a2, "admin") && !strcmp(m, "DELETE")) ||
     (nseg == 3 && (!strcmp(a2, "delete") || !strcmp(a2, "delete-admin")) && !strcmp(m, "POST"))) {
    array_remove(ciphers, cc);
    c->dirty = 1;
    return bw_empty(r);
  }
  if(nseg == 3 && (!strcmp(a2, "restore") || !strcmp(a2, "restore-admin")) && !strcmp(m, "PUT")) {
    cJSON_DeleteItemFromObject(cc, "deleted");
    jset_num(cc, "rev", (double)now);
    c->dirty = 1;
    return bw_send(r, 200, cipher_json(cc));
  }
  if(nseg >= 3 && !strncmp(a2, "attachment", 10)) {
    return bw_fail(r, 400, "PS5NAS no admite adjuntos en el gestor de contraseñas");
  }
  if(nseg >= 3 && (!strcmp(a2, "share") || !strncmp(a2, "collections", 11))) {
    return bw_fail(r, 400, "PS5NAS no tiene organizaciones");
  }
  return bw_fail(r, 404, "No encontrado");

 bulk_delete_hard: {
    cJSON *b = parse_body(r);
    cJSON *ids = b ? body_ids(b) : NULL, *id;
    if(!ids) {
      cJSON_Delete(b);
      return bw_fail(r, 400, "Faltan los elementos");
    }
    cJSON_ArrayForEach(id, ids) {
      cJSON *x = cJSON_IsString(id) ? vault_find_id(ciphers, id->valuestring) : NULL;
      if(x) array_remove(ciphers, x);
    }
    cJSON_Delete(b);
    c->dirty = 1;
    return bw_empty(r);
  }
}


static cJSON *
device_json(const cJSON *d) {
  cJSON *o = cJSON_CreateObject();
  jset_str(o, "id", jstr(d, "id"));
  jset_str(o, "name", jstr(d, "name"));
  jset_num(o, "type", (double)jnum(d, "type", 0));
  jset_str(o, "identifier", jstr(d, "id"));
  jset_iso(o, "creationDate", jnum(d, "created", 0));
  jset(o, "isTrusted", cJSON_CreateFalse());
  jset_str(o, "object", "device");
  return o;
}


static int
h_accounts(req_t *r, bwctx_t *c, int nseg, char **seg) {
  const char *a = nseg >= 2 ? seg[1] : "";
  const char *m = r->method;
  if(!strcmp(a, "profile")) return bw_send(r, 200, profile_json(c->v));
  if(!strcmp(a, "revision-date") && !strcmp(m, "GET")) {
    char num[32];
    snprintf(num, sizeof(num), "%lld", jnum(c->v, "rev", bw_now_us()) / 1000);
    return send_body(r, 200, "application/json; charset=utf-8", num, strlen(num), NULL);
  }
  if(!strcmp(a, "keys")) {
    cJSON *j = cJSON_CreateObject();
    jset_str(j, "key", jstr(c->v, "key"));
    jset_str(j, "publicKey", jstr(c->v, "pub"));
    jset_str(j, "privateKey", jstr(c->v, "priv"));
    jset_str(j, "object", "keys");
    return bw_send(r, 200, j);
  }
  if(!strcmp(a, "verify-password") && !strcmp(m, "POST")) {
    cJSON *b = parse_body(r);
    int ok = b && !check_master_hash(c->v, jstr(b, "masterPasswordHash"));
    cJSON_Delete(b);
    if(!ok) return bw_fail(r, 400, "Contraseña incorrecta");
    cJSON *j = cJSON_CreateObject();
    jset_str(j, "Object", "masterPasswordPolicy");
    return bw_send(r, 200, j);
  }
  if(!strcmp(a, "avatar")) return bw_send(r, 200, profile_json(c->v));
  if(!strcmp(a, "security-stamp") && !strcmp(m, "POST")) {
    cJSON *b = parse_body(r);
    int ok = b && !check_master_hash(c->v, jstr(b, "masterPasswordHash"));
    cJSON_Delete(b);
    if(!ok) return bw_fail(r, 400, "Contraseña incorrecta");
    char ss[37];
    bw_uuid(ss);
    jset_str(c->v, "sstamp", ss);
    jset(c->v, "devices", cJSON_CreateArray());
    c->dirty = 1;
    return bw_empty(r);
  }
  if(!strcmp(a, "key-management") && nseg == 3 && !strcmp(seg[2], "user-key-id") &&
     !strcmp(m, "POST")) {
    /* Identificador de la clave de usuario (clientes de 2025.8 en adelante). */
    if(jstr(c->v, "keyId")) return bw_fail(r, 422, "Unexpected data");
    cJSON *b = parse_body(r);
    const char *kid = b ? jstr(b, "userKeyId") : NULL;
    if(!kid || strlen(kid) > 200) {
      cJSON_Delete(b);
      return bw_fail(r, 400, "Datos no válidos");
    }
    jset_str(c->v, "keyId", kid);
    cJSON_Delete(b);
    c->dirty = 1;
    return bw_empty(r);
  }
  if(!strcmp(a, "password") || !strcmp(a, "kdf") || !strcmp(a, "email") ||
     !strcmp(a, "email-token") || !strcmp(a, "set-password") || !strcmp(a, "key-management")) {
    return bw_fail(r, 400, "La contraseña se cambia desde la web de PS5NAS (Mi cuenta). "
                           "Es la misma para los archivos y para el gestor.");
  }
  if(!strcmp(a, "delete") || (!strcmp(m, "DELETE") && nseg == 1)) {
    return bw_fail(r, 400, "Las cuentas se gestionan desde el panel de PS5NAS");
  }
  if(!strcmp(a, "api-key") || !strcmp(a, "rotate-api-key")) {
    return bw_fail(r, 400, "PS5NAS no admite claves de API");
  }
  return bw_fail(r, 404, "No encontrado");
}


static int
h_devices(req_t *r, bwctx_t *c, int nseg, char **seg) {
  cJSON *devs = cJSON_GetObjectItem(c->v, "devices");
  if(nseg == 1 && !strcmp(r->method, "GET")) {
    cJSON *a = cJSON_CreateArray(), *it;
    cJSON_ArrayForEach(it, devs) cJSON_AddItemToArray(a, device_json(it));
    return bw_list(r, a);
  }
  if(nseg >= 3 && !strcmp(seg[1], "identifier")) {
    cJSON *d = vault_find_id(devs, seg[2]);
    if(nseg == 3 && !strcmp(r->method, "GET")) {
      if(!d) return bw_fail(r, 404, "No existe el dispositivo");
      return bw_send(r, 200, device_json(d));
    }
    return bw_empty(r);      /* token / clear-token / keys: notificaciones push no disponibles */
  }
  if(strcmp(r->method, "GET")) return bw_empty(r);
  return bw_list(r, NULL);
}


/* Listas vacías de lo que no existe aquí (organizaciones, Send...). */
static int
is_empty_list(const char *p) {
  static const char *pre[] = {"sends", "collections", "emergency-access", "auth-requests",
                              "tasks", "two-factor", "webauthn", "organizations", "policies",
                              "security-tasks", "providers", "notifications", NULL};
  for(int i=0; pre[i]; i++) if(!strcmp(p, pre[i])) return 1;
  return 0;
}


static int
h_config(req_t *r) {
  char base[400];
  const char *host = r->host[0] ? r->host : "localhost";
  snprintf(base, sizeof(base), "%s://%s", req_https(r) ? "https" : "http", host);
  cJSON *j = cJSON_CreateObject();
  jset_str(j, "version", BW_SERVER_VERSION);
  jset_str(j, "gitHash", VERSION_TAG);
  cJSON *srv = cJSON_CreateObject();
  jset_str(srv, "name", "PS5NAS");
  jset_str(srv, "url", "https://github.com/");
  jset(j, "server", srv);
  cJSON *st = cJSON_CreateObject();
  jset(st, "disableUserRegistration", cJSON_CreateTrue());
  jset(st, "suppressOnboardingInterstitials", cJSON_CreateTrue());
  jset(j, "settings", st);
  cJSON *env = cJSON_CreateObject();
  char u[480];
  jset_str(env, "vault", base);
  snprintf(u, sizeof(u), "%s/api", base);
  jset_str(env, "api", u);
  snprintf(u, sizeof(u), "%s/identity", base);
  jset_str(env, "identity", u);
  snprintf(u, sizeof(u), "%s/notifications", base);
  jset_str(env, "notifications", u);
  jset_str(env, "sso", "");
  jset(env, "cloudRegion", cJSON_CreateNull());
  jset(env, "fillAssistRules", cJSON_CreateNull());
  jset(j, "environment", env);
  cJSON *push = cJSON_CreateObject();
  jset_num(push, "pushTechnology", 0);
  jset(push, "vapidPublicKey", cJSON_CreateNull());
  jset(j, "push", push);
  jset(j, "featureStates", cJSON_CreateObject());
  jset(j, "communication", cJSON_CreateNull());
  jset_str(j, "object", "config");
  return bw_send(r, 200, j);
}


static int
h_known_device(req_t *r) {
  char email[256];
  uint8_t eb[256];
  int ok = 0;
  int n = bw_b64_dec(r->req_email, strlen(r->req_email), eb, sizeof(eb) - 1);
  if(n > 0) {
    memcpy(email, eb, (size_t)n);
    email[n] = 0;
    user_t u;
    vault_lock();
    cJSON *v = find_by_email(email, &u);
    if(v && r->device_id[0]) ok = vault_find_id(cJSON_GetObjectItem(v, "devices"), r->device_id) != NULL;
    cJSON_Delete(v);
    vault_unlock();
    memset(&u, 0, sizeof(u));
  }
  return send_body(r, 200, "application/json; charset=utf-8", ok ? "true" : "false",
                   ok ? 4 : 5, NULL);
}


/* ------------------------------------------------------------------ */
/* Enrutado                                                            */
/* ------------------------------------------------------------------ */

static int
split_path(char *p, char **seg, int max) {
  int n = 0;
  char *save = NULL;
  for(char *t = strtok_r(p, "/", &save); t && n < max; t = strtok_r(NULL, "/", &save)) {
    seg[n++] = t;
  }
  return n;
}


static int
is_bw_path(const char *p) {
  return !strncmp(p, "/api/", 5) || !strncmp(p, "/identity/", 10) ||
         !strncmp(p, "/notifications/", 15) || !strncmp(p, "/icons/", 7) ||
         !strncmp(p, "/events/", 8);
}


static int
dispatch(req_t *r) {
  const char *m = r->method;
  char path[2048];
  char *seg[16];

  if(!strcmp(r->path, "/identity/connect/token") && !strcmp(m, "POST")) return h_token(r);
  if((!strcmp(r->path, "/identity/accounts/prelogin") ||
      !strcmp(r->path, "/identity/accounts/prelogin/password") ||
      !strcmp(r->path, "/api/accounts/prelogin")) && !strcmp(m, "POST")) return h_prelogin(r);
  if(!strncmp(r->path, "/identity/", 10)) {
    return bw_fail(r, 400, "PS5NAS no permite crear cuentas desde la app: pídeselo al "
                           "administrador");
  }
  if(!strcmp(r->path, "/api/config")) return h_config(r);
  if(!strcmp(r->path, "/api/alive") || !strcmp(r->path, "/alive")) {
    char d[40];
    bw_iso(bw_now_us(), d);
    char q[48];
    snprintf(q, sizeof(q), "\"%s\"", d);
    return send_body(r, 200, "application/json", q, strlen(q), NULL);
  }
  if(!strcmp(r->path, "/api/version")) {
    return send_body(r, 200, "application/json", "\"" BW_SERVER_VERSION "\"",
                     strlen(BW_SERVER_VERSION) + 2, NULL);
  }
  if(!strcmp(r->path, "/api/devices/knowndevice")) return h_known_device(r);
  if(!strncmp(r->path, "/icons/", 7) || !strncmp(r->path, "/notifications/", 15)) {
    return send_body(r, 404, "text/plain", "", 0, NULL);
  }
  if(!strncmp(r->path, "/events/", 8)) return bw_empty(r);

  /* A partir de aquí, con token. */
  bwctx_t c;
  memset(&c, 0, sizeof(c));
  if(bw_auth(r, &c)) {
    memset(&c.u, 0, sizeof(c.u));
    return bw_fail(r, 401, "Sesión no válida o caducada");
  }
  snprintf(path, sizeof(path), "%s", r->path + 5);    /* sin "/api/" */
  int n = split_path(path, seg, 16);
  int ret;
  if(n == 0) ret = bw_fail(r, 404, "No encontrado");
  else if(!strcmp(seg[0], "sync") && !strcmp(m, "GET")) ret = h_sync(r, &c);
  else if(!strcmp(seg[0], "ciphers")) ret = h_ciphers(r, &c, n, seg);
  else if(!strcmp(seg[0], "folders")) ret = h_folders(r, &c, n, seg);
  else if(!strcmp(seg[0], "accounts")) ret = h_accounts(r, &c, n, seg);
  else if(!strcmp(seg[0], "devices")) ret = h_devices(r, &c, n, seg);
  else if(!strcmp(seg[0], "users") && n == 3 && !strcmp(seg[2], "public-key")) {
    const char *id = jstr(c.v, "id");
    if(id && !strcasecmp(seg[1], id)) {
      cJSON *j = cJSON_CreateObject();
      jset_str(j, "userId", id);
      jset_str(j, "publicKey", jstr(c.v, "pub"));
      jset_str(j, "object", "userKey");
      ret = bw_send(r, 200, j);
    } else {
      ret = bw_fail(r, 404, "No existe el usuario");
    }
  }
  else if(!strcmp(seg[0], "settings") && n >= 2 && !strcmp(seg[1], "domains")) {
    cJSON *d = cJSON_CreateObject();
    jset(d, "equivalentDomains", cJSON_CreateArray());
    jset(d, "globalEquivalentDomains", cJSON_CreateArray());
    jset_str(d, "object", "domains");
    ret = bw_send(r, 200, d);
  }
  else if(is_empty_list(seg[0]) && !strcmp(m, "GET")) ret = bw_list(r, NULL);
  else if(!strcmp(seg[0], "sends")) {
    ret = bw_fail(r, 400, "PS5NAS no admite Bitwarden Send");
  }
  else if(!strcmp(m, "GET")) ret = bw_list(r, NULL);
  else ret = bw_fail(r, 404, "No encontrado");

  if(c.dirty) {
    vault_touch(c.v);
    if(vault_save(c.u.name, c.v)) {
      LOG_PRINTF("ps5share: ¡no se guardaron los cambios del gestor de '%s'!\n", c.u.name);
    }
  }
  cJSON_Delete(c.v);
  vault_unlock();
  memset(&c.u, 0, sizeof(c.u));
  return ret;
}


int
vault_handle(req_t *r) {
  if(!is_bw_path(r->path) || !g_ready) return 0;

  /* CORS: la API usa tokens Bearer (no cookies), así que se permite
     cualquier origen, como hace Bitwarden con su extensión. */
  char cors[1024] = "";
  if(r->origin[0] && !strpbrk(r->origin, "\r\n")) {
    snprintf(cors, sizeof(cors),
             "Access-Control-Allow-Origin: %s\r\n"
             "Access-Control-Allow-Credentials: true\r\n"
             "Vary: Origin\r\n", r->origin);
    r->extra_hdr = cors;
  }
  if(!strcmp(r->method, "OPTIONS")) {
    char h[1200];
    snprintf(h, sizeof(h),
             "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
             "Access-Control-Allow-Headers: %s\r\n"
             "Access-Control-Max-Age: 86400\r\n",
             r->acr_headers[0] && !strpbrk(r->acr_headers, "\r\n") ? r->acr_headers :
             "Authorization, Content-Type, Bitwarden-Client-Name, Bitwarden-Client-Version, "
             "Device-Type, X-Request-Email, X-Device-Identifier");
    send_body(r, 204, "text/plain", "", 0, h);
    r->extra_hdr = NULL;
    return 1;
  }
  if(!vault_globally_enabled() && strcmp(r->path, "/api/config")) {
    bw_fail(r, 503, "El gestor de contraseñas está desactivado en PS5NAS");
  } else {
    dispatch(r);
  }
  r->extra_hdr = NULL;
  return 1;
}
