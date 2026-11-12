/* ps5share - pestaña «Contraseñas» de la web de PS5NAS
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   La web de PS5NAS funciona también por HTTP normal (sin HTTPS) y en el
   navegador de la PS5, donde no hay WebCrypto.  Por eso aquí el cifrado lo
   hace la consola: con la sesión iniciada, se abre la clave de la bóveda
   del usuario y se descifran o cifran los elementos en el servidor, con el
   mismo formato que usan las apps de Bitwarden.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <cJSON.h>

#include "bwcrypto.h"
#include "config.h"
#include "log.h"
#include "tls.h"
#include "vault.h"
#include "vaultweb.h"

#define PW_HISTORY_MAX 5


static const char *
jstr(const cJSON *o, const char *k) {
  const cJSON *i = cJSON_GetObjectItem(o, k);
  return cJSON_IsString(i) ? i->valuestring : NULL;
}


static long long
jnum(const cJSON *o, const char *k, long long def) {
  const cJSON *i = cJSON_GetObjectItem(o, k);
  return cJSON_IsNumber(i) ? (long long)i->valuedouble : def;
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


/* Cifra S (NULL o "" -> null). */
static void
jset_enc(cJSON *o, const char *k, const uint8_t key[64], const char *s) {
  if(!s || !s[0]) {
    jset(o, k, cJSON_CreateNull());
    return;
  }
  char *e = bw_enc_str(key, s);
  jset_str(o, k, e);
  free(e);
}


static char *
dec(const uint8_t key[64], const char *enc) {
  uint8_t *out;
  size_t n;
  if(!enc) return NULL;
  if(bw_dec(key, enc, &out, &n)) return NULL;
  return (char*)out;
}


static void
add_dec(cJSON *o, const char *k, const uint8_t key[64], const char *enc) {
  char *s = dec(key, enc);
  jset_str(o, k, s ? s : (enc ? "" : NULL));
  if(s) {
    memset(s, 0, strlen(s));
    free(s);
  }
}


/* Clave con la que están cifrados los campos del elemento. */
static int
item_key(const cJSON *c, const uint8_t ukey[64], uint8_t out[64]) {
  const char *k = jstr(c, "key");
  if(!k) {
    memcpy(out, ukey, 64);
    return 0;
  }
  uint8_t *p;
  size_t n;
  if(bw_dec(ukey, k, &p, &n) || n != 64) {
    if(p) free(p);
    return -1;
  }
  memcpy(out, p, 64);
  memset(p, 0, n);
  free(p);
  return 0;
}


static int
send_cjson(req_t *r, cJSON *j) {
  char *s = cJSON_PrintUnformatted(j);
  cJSON_Delete(j);
  if(!s) return send_err(r, 500, "Sin memoria");
  int ret = send_body(r, 200, "application/json; charset=utf-8", s, strlen(s), NULL);
  memset(s, 0, strlen(s));
  free(s);
  return ret;
}


/* Abre la bóveda del usuario de la sesión.  Si devuelve 0 deja vault_lock
   tomado; si no, ya respondió con el error. */
static int
web_open(req_t *r, cJSON **v, uint8_t key[64]) {
  cfg_lock();
  int on = cfg_settings()->vault_enabled;
  cfg_unlock();
  if(!on) return send_err(r, 403, "El gestor de contraseñas está desactivado"), -1;
  if(!r->user.vault) return send_err(r, 403, "El administrador no te ha activado el gestor"), -1;
  if(!vault_has_account(r->user.name) && vault_ensure_stored(r->user.name)) {
    send_err(r, 409, "Tu gestor aún no está preparado: cierra sesión y vuelve a entrar");
    return -1;
  }
  vault_lock();
  *v = vault_load(r->user.name);
  if(!*v || vault_user_key(*v, r->user.name, key)) {
    cJSON_Delete(*v);
    *v = NULL;
    vault_unlock();
    send_err(r, 500, "No se pudo abrir tu gestor de contraseñas");
    return -1;
  }
  return 0;
}


static void
web_close(cJSON *v, uint8_t key[64]) {
  memset(key, 0, 64);
  cJSON_Delete(v);
  vault_unlock();
}


/* ------------------------------------------------------------------ */
/* Información                                                         */
/* ------------------------------------------------------------------ */

int
h_pw_info(req_t *r) {
  char email[160], fp[128], names[1024];
  cfg_lock();
  settings_t *st = cfg_settings();
  int enabled = st->vault_enabled, https = st->https_enabled;
  unsigned port = st->https_port;
  cfg_unlock();
  vault_login_email(r->user.name, email, sizeof(email));
  tls_ca_fingerprint(fp, sizeof(fp));
  tls_cert_names(names, sizeof(names));

  cJSON *j = cJSON_CreateObject();
  jset(j, "enabled", cJSON_CreateBool(enabled));
  jset(j, "allowed", cJSON_CreateBool(r->user.vault));
  jset(j, "ready", cJSON_CreateBool(vault_has_account(r->user.name)));
  jset_str(j, "email", email);
  jset(j, "https", cJSON_CreateBool(https));
  jset(j, "https_port", cJSON_CreateNumber(port));
  jset_str(j, "ca_fingerprint", fp);
  cJSON *urls = cJSON_CreateArray();
  char *save = NULL;
  for(char *t = strtok_r(names, " ", &save); t; t = strtok_r(NULL, " ", &save)) {
    if(!strcmp(t, "localhost") || !strcmp(t, "127.0.0.1")) continue;
    char u[300];
    if(port == 443) snprintf(u, sizeof(u), "https://%s", t);
    else snprintf(u, sizeof(u), "https://%s:%u", t, port);
    cJSON_AddItemToArray(urls, cJSON_CreateString(u));
  }
  jset(j, "server_urls", urls);
  jset(j, "secure", cJSON_CreateBool(r->tls));
  return send_cjson(r, j);
}


/* ------------------------------------------------------------------ */
/* Elementos                                                           */
/* ------------------------------------------------------------------ */

static cJSON *
item_out(const cJSON *c, const uint8_t ukey[64]) {
  uint8_t k[64];
  cJSON *o = cJSON_CreateObject();
  int type = (int)jnum(c, "type", 1);
  char d[40];
  jset_str(o, "id", jstr(c, "id"));
  jset(o, "type", cJSON_CreateNumber(type));
  jset(o, "favorite", cJSON_CreateBool(cJSON_IsTrue(cJSON_GetObjectItem(c, "favorite"))));
  jset_str(o, "folderId", jstr(c, "folderId"));
  jset(o, "deleted", cJSON_CreateBool(jnum(c, "deleted", 0) > 0));
  bw_iso(jnum(c, "rev", 0), d);
  jset_str(o, "revisionDate", d);
  if(item_key(c, ukey, k)) {
    jset_str(o, "name", "(no se pudo descifrar)");
    jset(o, "broken", cJSON_CreateTrue());
    return o;
  }
  add_dec(o, "name", k, jstr(c, "name"));
  add_dec(o, "notes", k, jstr(c, "notes"));

  if(type == 1) {
    const cJSON *l = cJSON_GetObjectItem(c, "login");
    cJSON *lo = cJSON_CreateObject();
    add_dec(lo, "username", k, jstr(l, "username"));
    add_dec(lo, "password", k, jstr(l, "password"));
    add_dec(lo, "totp", k, jstr(l, "totp"));
    cJSON *ua = cJSON_CreateArray(), *u;
    cJSON_ArrayForEach(u, cJSON_GetObjectItem(l, "uris")) {
      char *s = dec(k, jstr(u, "uri"));
      if(s) cJSON_AddItemToArray(ua, cJSON_CreateString(s));
      free(s);
    }
    jset(lo, "uris", ua);
    jset(o, "login", lo);
  } else if(type == 3) {
    const cJSON *cd = cJSON_GetObjectItem(c, "card");
    cJSON *co = cJSON_CreateObject();
    static const char *cf[] = {"cardholderName", "brand", "number", "expMonth", "expYear", "code"};
    for(size_t i=0; i<sizeof(cf)/sizeof(cf[0]); i++) add_dec(co, cf[i], k, jstr(cd, cf[i]));
    jset(o, "card", co);
  } else if(type == 4) {
    const cJSON *id = cJSON_GetObjectItem(c, "identity");
    cJSON *io = cJSON_CreateObject();
    static const char *idf[] = {"title", "firstName", "middleName", "lastName", "email", "phone",
                                "address1", "city", "postalCode", "country", "company"};
    for(size_t i=0; i<sizeof(idf)/sizeof(idf[0]); i++) add_dec(io, idf[i], k, jstr(id, idf[i]));
    jset(o, "identity", io);
  }
  cJSON *fa = cJSON_CreateArray(), *f;
  cJSON_ArrayForEach(f, cJSON_GetObjectItem(c, "fields")) {
    cJSON *fo = cJSON_CreateObject();
    add_dec(fo, "name", k, jstr(f, "name"));
    add_dec(fo, "value", k, jstr(f, "value"));
    jset(fo, "type", cJSON_CreateNumber((double)jnum(f, "type", 0)));
    cJSON_AddItemToArray(fa, fo);
  }
  jset(o, "fields", fa);
  memset(k, 0, sizeof(k));
  return o;
}


int
h_pw_items(req_t *r) {
  cJSON *v;
  uint8_t key[64];
  if(web_open(r, &v, key)) return 0;
  cJSON *j = cJSON_CreateObject();
  cJSON *fa = cJSON_CreateArray(), *it;
  cJSON_ArrayForEach(it, cJSON_GetObjectItem(v, "folders")) {
    cJSON *fo = cJSON_CreateObject();
    jset_str(fo, "id", jstr(it, "id"));
    add_dec(fo, "name", key, jstr(it, "name"));
    cJSON_AddItemToArray(fa, fo);
  }
  jset(j, "folders", fa);
  cJSON *ia = cJSON_CreateArray();
  cJSON_ArrayForEach(it, cJSON_GetObjectItem(v, "ciphers")) {
    cJSON_AddItemToArray(ia, item_out(it, key));
  }
  jset(j, "items", ia);
  web_close(v, key);
  return send_cjson(r, j);
}


/* Cifra y guarda una URI con su suma de comprobación. */
static cJSON *
enc_uri(const uint8_t k[64], const char *uri) {
  uint8_t h[32];
  char hb[48];
  cJSON *o = cJSON_CreateObject();
  jset_enc(o, "uri", k, uri);
  bw_sha256(uri, strlen(uri), h);
  bw_b64_enc(h, 32, hb, sizeof(hb));
  jset_enc(o, "uriChecksum", k, hb);
  jset(o, "match", cJSON_CreateNull());
  return o;
}


/* Campos de un formulario o de un objeto JSON importado. */
typedef struct item_in {
  int  type;
  int  favorite;
  char folder[64];
  char *name, *notes, *username, *password, *totp, *uris;
  char *card[6];
} item_in_t;

static const char *CARDF[] = {"cardholderName", "brand", "number", "expMonth", "expYear", "code"};


static void
item_in_free(item_in_t *in) {
  char **all[] = {&in->name, &in->notes, &in->username, &in->password, &in->totp, &in->uris};
  for(size_t i=0; i<sizeof(all)/sizeof(all[0]); i++) {
    if(*all[i]) {
      memset(*all[i], 0, strlen(*all[i]));
      free(*all[i]);
    }
  }
  for(int i=0; i<6; i++) {
    if(in->card[i]) {
      memset(in->card[i], 0, strlen(in->card[i]));
      free(in->card[i]);
    }
  }
}


/* Aplica IN sobre el elemento guardado C (nuevo o existente). */
static const char *
apply_item(cJSON *v, cJSON *c, const uint8_t ukey[64], item_in_t *in) {
  uint8_t k[64];
  if(!in->name || !in->name[0]) return "Falta el nombre";
  if(in->type != 1 && in->type != 2 && in->type != 3) return "Tipo no válido";
  if(in->folder[0] && !vault_find_id(cJSON_GetObjectItem(v, "folders"), in->folder)) {
    return "La carpeta no existe";
  }
  if(item_key(c, ukey, k)) return "No se pudo descifrar el elemento";
  long long now = bw_now_us();
  int old_type = (int)jnum(c, "type", in->type);
  if(old_type != in->type) {
    cJSON_DeleteItemFromObject(c, "login");
    cJSON_DeleteItemFromObject(c, "secureNote");
    cJSON_DeleteItemFromObject(c, "card");
  }
  jset(c, "type", cJSON_CreateNumber(in->type));
  jset_enc(c, "name", k, in->name);
  jset_enc(c, "notes", k, in->notes);
  jset(c, "favorite", cJSON_CreateBool(in->favorite));
  jset_str(c, "folderId", in->folder[0] ? in->folder : NULL);

  if(in->type == 1) {
    cJSON *l = cJSON_GetObjectItem(c, "login");
    if(!cJSON_IsObject(l)) {
      l = cJSON_CreateObject();
      jset(c, "login", l);
    }
    /* Contraseña anterior al historial (como hace Bitwarden). */
    char *oldp = dec(k, jstr(l, "password"));
    if(oldp && oldp[0] && (!in->password || strcmp(oldp, in->password))) {
      cJSON *ph = cJSON_GetObjectItem(c, "passwordHistory");
      if(!cJSON_IsArray(ph)) {
        ph = cJSON_CreateArray();
        jset(c, "passwordHistory", ph);
      }
      cJSON *e = cJSON_CreateObject();
      char d[40];
      bw_iso(now, d);
      jset_str(e, "lastUsedDate", d);
      jset_enc(e, "password", k, oldp);
      cJSON_InsertItemInArray(ph, 0, e);
      while(cJSON_GetArraySize(ph) > PW_HISTORY_MAX) cJSON_DeleteItemFromArray(ph, PW_HISTORY_MAX);
      jset_str(l, "passwordRevisionDate", d);
    }
    if(oldp) {
      memset(oldp, 0, strlen(oldp));
      free(oldp);
    }
    jset_enc(l, "username", k, in->username);
    jset_enc(l, "password", k, in->password);
    jset_enc(l, "totp", k, in->totp);
    cJSON *ua = cJSON_CreateArray();
    if(in->uris) {
      char *save = NULL;
      for(char *t = strtok_r(in->uris, "\n", &save); t; t = strtok_r(NULL, "\n", &save)) {
        size_t n = strlen(t);
        while(n && (t[n-1] == '\r' || t[n-1] == ' ')) t[--n] = 0;
        while(*t == ' ') t++;
        if(*t) cJSON_AddItemToArray(ua, enc_uri(k, t));
      }
    }
    jset(l, "uris", ua);
  } else if(in->type == 2) {
    cJSON *sn = cJSON_CreateObject();
    jset(sn, "type", cJSON_CreateNumber(0));
    jset(c, "secureNote", sn);
  } else {
    cJSON *cd = cJSON_GetObjectItem(c, "card");
    if(!cJSON_IsObject(cd)) {
      cd = cJSON_CreateObject();
      jset(c, "card", cd);
    }
    for(int i=0; i<6; i++) jset_enc(cd, CARDF[i], k, in->card[i]);
  }
  memset(k, 0, sizeof(k));
  if(jnum(c, "created", 0) <= 0) jset(c, "created", cJSON_CreateNumber((double)now));
  jset(c, "rev", cJSON_CreateNumber((double)now));
  return NULL;
}


static char *
param_dup(const char *body, const char *name, size_t max) {
  char *s = malloc(max + 1);
  if(!s) return NULL;
  if(get_param(body, name, s, max + 1)) s[0] = 0;
  return s;
}


int
h_pw_save(req_t *r) {
  char id[64], tmp[16];
  item_in_t in;
  cJSON *v;
  uint8_t key[64];

  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  memset(&in, 0, sizeof(in));
  get_param(r->body, "id", id, sizeof(id));
  get_param(r->body, "type", tmp, sizeof(tmp));
  in.type = atoi(tmp);
  get_param(r->body, "favorite", tmp, sizeof(tmp));
  in.favorite = !strcmp(tmp, "1");
  get_param(r->body, "folder", in.folder, sizeof(in.folder));
  in.name = param_dup(r->body, "name", 1000);
  in.notes = param_dup(r->body, "notes", 60000);
  in.username = param_dup(r->body, "username", 2000);
  in.password = param_dup(r->body, "password", 5000);
  in.totp = param_dup(r->body, "totp", 2000);
  in.uris = param_dup(r->body, "uris", 20000);
  for(int i=0; i<6; i++) in.card[i] = param_dup(r->body, CARDF[i], 200);

  if(web_open(r, &v, key)) {
    item_in_free(&in);
    return 0;
  }
  cJSON *ciphers = cJSON_GetObjectItem(v, "ciphers");
  cJSON *c;
  int is_new = 0;
  if(id[0]) {
    c = vault_find_id(ciphers, id);
    if(!c) {
      web_close(v, key);
      item_in_free(&in);
      return send_err(r, 404, "El elemento no existe");
    }
    int t = (int)jnum(c, "type", 1);
    if(t > 3) {
      web_close(v, key);
      item_in_free(&in);
      return send_err(r, 400, "Este tipo de elemento solo se puede editar en la app de Bitwarden");
    }
  } else {
    char nid[37];
    c = cJSON_CreateObject();
    bw_uuid(nid);
    jset_str(c, "id", nid);
    is_new = 1;
  }
  const char *err = apply_item(v, c, key, &in);
  item_in_free(&in);
  if(err) {
    if(is_new) cJSON_Delete(c);
    web_close(v, key);
    return send_err(r, 400, err);
  }
  if(is_new) cJSON_AddItemToArray(ciphers, c);
  vault_touch(v);
  int sr = vault_save(r->user.name, v);
  char nid[40];
  snprintf(nid, sizeof(nid), "%s", jstr(c, "id"));
  web_close(v, key);
  if(sr) return send_err(r, 500, "No se pudo guardar");
  sb_t b = {0};
  sb_puts(&b, "{\"ok\":true,\"id\":");
  sb_json_str(&b, nid);
  sb_puts(&b, "}");
  return send_json(r, 200, &b, NULL);
}


static int
change_item(req_t *r, int restore) {
  char id[64], perm[8];
  cJSON *v;
  uint8_t key[64];
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "id", id, sizeof(id));
  get_param(r->body, "permanent", perm, sizeof(perm));
  if(web_open(r, &v, key)) return 0;
  cJSON *ciphers = cJSON_GetObjectItem(v, "ciphers");
  cJSON *c = vault_find_id(ciphers, id);
  if(!c) {
    web_close(v, key);
    return send_err(r, 404, "El elemento no existe");
  }
  long long now = bw_now_us();
  if(restore) {
    cJSON_DeleteItemFromObject(c, "deleted");
    jset(c, "rev", cJSON_CreateNumber((double)now));
  } else if(!strcmp(perm, "1")) {
    int i = 0;
    cJSON *it;
    cJSON_ArrayForEach(it, ciphers) {
      if(it == c) break;
      i++;
    }
    cJSON_DeleteItemFromArray(ciphers, i);
  } else {
    jset(c, "deleted", cJSON_CreateNumber((double)now));
    jset(c, "rev", cJSON_CreateNumber((double)now));
  }
  vault_touch(v);
  int sr = vault_save(r->user.name, v);
  web_close(v, key);
  return sr ? send_err(r, 500, "No se pudo guardar") : send_ok(r);
}


int h_pw_delete(req_t *r)  { return change_item(r, 0); }
int h_pw_restore(req_t *r) { return change_item(r, 1); }


int
h_pw_folder(req_t *r) {
  char id[64], name[300];
  cJSON *v;
  uint8_t key[64];
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "id", id, sizeof(id));
  get_param(r->body, "name", name, sizeof(name));
  if(!name[0]) return send_err(r, 400, "Falta el nombre");
  if(web_open(r, &v, key)) return 0;
  cJSON *folders = cJSON_GetObjectItem(v, "folders");
  if(!cJSON_IsArray(folders)) {
    folders = cJSON_CreateArray();
    jset(v, "folders", folders);
  }
  cJSON *f;
  if(id[0]) {
    if(!(f = vault_find_id(folders, id))) {
      web_close(v, key);
      return send_err(r, 404, "La carpeta no existe");
    }
  } else {
    char nid[37];
    bw_uuid(nid);
    f = cJSON_CreateObject();
    jset_str(f, "id", nid);
    cJSON_AddItemToArray(folders, f);
  }
  jset_enc(f, "name", key, name);
  jset(f, "rev", cJSON_CreateNumber((double)bw_now_us()));
  vault_touch(v);
  int sr = vault_save(r->user.name, v);
  web_close(v, key);
  return sr ? send_err(r, 500, "No se pudo guardar") : send_ok(r);
}


int
h_pw_folder_delete(req_t *r) {
  char id[64];
  cJSON *v;
  uint8_t key[64];
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "id", id, sizeof(id));
  if(web_open(r, &v, key)) return 0;
  cJSON *folders = cJSON_GetObjectItem(v, "folders");
  cJSON *f = vault_find_id(folders, id), *it;
  if(!f) {
    web_close(v, key);
    return send_err(r, 404, "La carpeta no existe");
  }
  long long now = bw_now_us();
  cJSON_ArrayForEach(it, cJSON_GetObjectItem(v, "ciphers")) {
    const char *fid = jstr(it, "folderId");
    if(fid && !strcasecmp(fid, id)) {
      jset(it, "folderId", cJSON_CreateNull());
      jset(it, "rev", cJSON_CreateNumber((double)now));
    }
  }
  cJSON_DetachItemViaPointer(folders, f);
  cJSON_Delete(f);
  vault_touch(v);
  int sr = vault_save(r->user.name, v);
  web_close(v, key);
  return sr ? send_err(r, 500, "No se pudo guardar") : send_ok(r);
}


/* ------------------------------------------------------------------ */
/* Importar y exportar                                                 */
/* ------------------------------------------------------------------ */

static char *
dup_or_null(const char *s) {
  return s ? strdup(s) : NULL;
}


/* Busca una carpeta por nombre (descifrado) o la crea. */
static const char *
folder_by_name(cJSON *v, const uint8_t key[64], const char *name) {
  cJSON *folders = cJSON_GetObjectItem(v, "folders"), *it;
  if(!cJSON_IsArray(folders)) {
    folders = cJSON_CreateArray();
    jset(v, "folders", folders);
  }
  cJSON_ArrayForEach(it, folders) {
    char *n = dec(key, jstr(it, "name"));
    int same = n && !strcmp(n, name);
    free(n);
    if(same) return jstr(it, "id");
  }
  char nid[37];
  bw_uuid(nid);
  cJSON *f = cJSON_CreateObject();
  jset_str(f, "id", nid);
  jset_enc(f, "name", key, name);
  jset(f, "rev", cJSON_CreateNumber((double)bw_now_us()));
  cJSON_AddItemToArray(folders, f);
  return jstr(f, "id");
}


int
h_pw_import(req_t *r) {
  cJSON *v;
  uint8_t key[64];
  if(read_body_max(r, HTTP_BODY_MAX_BIG)) return send_err(r, 413, "El archivo es demasiado grande");
  char *items = malloc(r->body_len + 1);
  if(!items) return send_err(r, 500, "Sin memoria");
  get_param(r->body, "items", items, r->body_len + 1);
  cJSON *list = cJSON_Parse(items);
  free(items);
  if(!cJSON_IsArray(list)) {
    cJSON_Delete(list);
    return send_err(r, 400, "No se encontraron contraseñas en el archivo");
  }
  if(web_open(r, &v, key)) {
    cJSON_Delete(list);
    return 0;
  }
  cJSON *ciphers = cJSON_GetObjectItem(v, "ciphers");
  int n = 0, skipped = 0;
  cJSON *it;
  cJSON_ArrayForEach(it, list) {
    item_in_t in;
    memset(&in, 0, sizeof(in));
    const char *type = jstr(it, "type");
    in.type = type && !strcmp(type, "note") ? 2 : 1;
    in.favorite = cJSON_IsTrue(cJSON_GetObjectItem(it, "favorite"));
    in.name = dup_or_null(jstr(it, "name"));
    in.notes = dup_or_null(jstr(it, "notes"));
    in.username = dup_or_null(jstr(it, "username"));
    in.password = dup_or_null(jstr(it, "password"));
    in.totp = dup_or_null(jstr(it, "totp"));
    in.uris = dup_or_null(jstr(it, "url"));
    if((!in.name || !in.name[0]) && in.uris && in.uris[0]) {
      free(in.name);
      in.name = strdup(in.uris);
    }
    const char *folder = jstr(it, "folder");
    if(folder && folder[0]) {
      const char *fid = folder_by_name(v, key, folder);
      if(fid) snprintf(in.folder, sizeof(in.folder), "%s", fid);
    }
    char nid[37];
    cJSON *c = cJSON_CreateObject();
    bw_uuid(nid);
    jset_str(c, "id", nid);
    if(apply_item(v, c, key, &in)) {
      cJSON_Delete(c);
      skipped++;
    } else {
      cJSON_AddItemToArray(ciphers, c);
      n++;
    }
    item_in_free(&in);
  }
  cJSON_Delete(list);
  vault_touch(v);
  int sr = vault_save(r->user.name, v);
  web_close(v, key);
  if(sr) return send_err(r, 500, "No se pudo guardar");
  LOG_PRINTF("ps5share: '%s' importó %d contraseña(s) desde la web\n", r->user.name, n);
  sb_t b = {0};
  sb_printf(&b, "{\"ok\":true,\"imported\":%d,\"skipped\":%d}", n, skipped);
  return send_json(r, 200, &b, NULL);
}


static void
csv_field(sb_t *b, const char *s, int last) {
  if(!s) s = "";
  if(strpbrk(s, ",\"\r\n")) {
    sb_putn(b, "\"", 1);
    for(const char *p = s; *p; p++) {
      if(*p == '"') sb_putn(b, "\"\"", 2);
      else sb_putn(b, p, 1);
    }
    sb_putn(b, "\"", 1);
  } else {
    sb_puts(b, s);
  }
  sb_puts(b, last ? "\r\n" : ",");
}


int
h_pw_export(req_t *r) {
  char pass[256];
  cJSON *v;
  uint8_t key[64];
  uint32_t ip = r->peer.sin_addr.s_addr;
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  if(rl_blocked(ip)) return send_err(r, 429, "Demasiados intentos. Espera unos minutos.");
  get_param(r->body, "pass", pass, sizeof(pass));
  if(cfg_authenticate(r->user.name, pass, NULL)) {
    memset(pass, 0, sizeof(pass));
    rl_fail(ip);
    return send_err(r, 403, "La contraseña no es correcta");
  }
  memset(pass, 0, sizeof(pass));
  if(web_open(r, &v, key)) return 0;

  sb_t b = {0};
  sb_puts(&b, "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,"
              "login_password,login_totp\r\n");
  cJSON *it;
  int n = 0;
  cJSON_ArrayForEach(it, cJSON_GetObjectItem(v, "ciphers")) {
    if(jnum(it, "deleted", 0) > 0) continue;
    cJSON *o = item_out(it, key);
    int type = (int)jnum(o, "type", 1);
    const char *fid = jstr(o, "folderId");
    char *fname = NULL;
    if(fid) {
      cJSON *f = vault_find_id(cJSON_GetObjectItem(v, "folders"), fid);
      if(f) fname = dec(key, jstr(f, "name"));
    }
    /* Las tarjetas e identidades van como notas con sus datos. */
    sb_t notes = {0};
    sb_puts(&notes, jstr(o, "notes") ? jstr(o, "notes") : "");
    const char *sub = type == 3 ? "card" : (type == 4 ? "identity" : NULL);
    if(sub) {
      cJSON *d = cJSON_GetObjectItem(o, sub), *f;
      cJSON_ArrayForEach(f, d) {
        if(cJSON_IsString(f) && f->valuestring[0]) {
          if(notes.len) sb_puts(&notes, "\n");
          sb_puts(&notes, f->string);
          sb_puts(&notes, ": ");
          sb_puts(&notes, f->valuestring);
        }
      }
    }
    sb_t fields = {0};
    cJSON *f;
    cJSON_ArrayForEach(f, cJSON_GetObjectItem(o, "fields")) {
      if(fields.len) sb_puts(&fields, "\n");
      sb_puts(&fields, jstr(f, "name") ? jstr(f, "name") : "");
      sb_puts(&fields, ": ");
      sb_puts(&fields, jstr(f, "value") ? jstr(f, "value") : "");
    }
    const cJSON *l = cJSON_GetObjectItem(o, "login");
    sb_t uris = {0};
    cJSON *u;
    cJSON_ArrayForEach(u, cJSON_GetObjectItem(l, "uris")) {
      if(uris.len) sb_puts(&uris, ",");
      sb_puts(&uris, u->valuestring);
    }
    csv_field(&b, fname, 0);
    csv_field(&b, cJSON_IsTrue(cJSON_GetObjectItem(o, "favorite")) ? "1" : "", 0);
    csv_field(&b, type == 1 ? "login" : "note", 0);
    csv_field(&b, jstr(o, "name"), 0);
    csv_field(&b, notes.p, 0);
    csv_field(&b, fields.p, 0);
    csv_field(&b, "0", 0);
    csv_field(&b, uris.p, 0);
    csv_field(&b, l ? jstr(l, "username") : NULL, 0);
    csv_field(&b, l ? jstr(l, "password") : NULL, 0);
    csv_field(&b, l ? jstr(l, "totp") : NULL, 1);
    free(notes.p);
    free(fields.p);
    free(uris.p);
    free(fname);
    cJSON_Delete(o);
    n++;
  }
  web_close(v, key);
  LOG_PRINTF("ps5share: '%s' exportó %d contraseña(s)\n", r->user.name, n);
  char disp[160];
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  snprintf(disp, sizeof(disp),
           "Content-Disposition: attachment; filename=\"ps5nas-contrasenas-%04d%02d%02d.csv\"\r\n",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
  int ret = send_body(r, 200, "text/csv; charset=utf-8", b.p ? b.p : "", b.len, disp);
  if(b.p) {
    memset(b.p, 0, b.len);
    free(b.p);
  }
  return ret;
}


/* ------------------------------------------------------------------ */
/* Certificado                                                         */
/* ------------------------------------------------------------------ */

int
h_pw_ca(req_t *r) {
  char pem[4096];
  long n = tls_ca_pem(pem, sizeof(pem));
  if(n <= 0) return send_err(r, 404, "No hay certificado");
  return send_body(r, 200, "application/x-x509-ca-cert", pem, (size_t)n,
                   "Content-Disposition: attachment; filename=\"PS5NAS-CA.crt\"\r\n");
}


int
h_admin_tls_regen(req_t *r) {
  char what[16];
  if(read_body(r)) return send_err(r, 400, "Petición no válida");
  get_param(r->body, "what", what, sizeof(what));
  if(!strcmp(what, "ca")) {
    if(tls_regenerate_ca()) return send_err(r, 500, "No se pudo crear el certificado");
    LOG_PRINTF("ps5share: '%s' regeneró la autoridad de certificación\n", r->user.name);
  } else {
    tls_refresh(1);
  }
  return send_ok(r);
}
