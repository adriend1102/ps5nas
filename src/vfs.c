/* ps5share - sistema de archivos virtual por usuario
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "vfs.h"


void
vfs_normalize(const char *cwd, const char *path, char *out, size_t outlen) {
  char buf[PATH_MAX * 2];
  char *parts[512];
  int n = 0;

  if(!path) path = "";
  if(path[0] == '/') {
    snprintf(buf, sizeof(buf), "%s", path);
  } else {
    snprintf(buf, sizeof(buf), "%s/%s", cwd && cwd[0] ? cwd : "/", path);
  }

  /* Acepta también '\' como separador (clientes Windows). */
  for(char *p = buf; *p; p++) if(*p == '\\') *p = '/';

  char *save = NULL;
  for(char *tok = strtok_r(buf, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
    if(!strcmp(tok, ".")) continue;
    if(!strcmp(tok, "..")) {
      if(n > 0) n--;
      continue;
    }
    if(n < (int)(sizeof(parts)/sizeof(parts[0]))) parts[n++] = tok;
  }

  size_t len = 0;
  out[0] = 0;
  if(n == 0) {
    snprintf(out, outlen, "/");
    return;
  }
  for(int i=0; i<n; i++) {
    int w = snprintf(out + len, outlen - len, "/%s", parts[i]);
    if(w < 0 || (size_t)w >= outlen - len) break;
    len += w;
  }
}


int
vfs_resolve(const user_t *u, const char *vabs, vfs_res_t *r) {
  char first[PATH_MAX];
  const char *rest;
  const char *p = vabs;

  memset(r, 0, sizeof(*r));
  r->mount = -1;
  snprintf(r->vpath, sizeof(r->vpath), "%s", vabs);

  while(*p == '/') p++;
  if(!*p) return 0;   /* raíz virtual */

  rest = strchr(p, '/');
  size_t flen = rest ? (size_t)(rest - p) : strlen(p);
  if(flen >= sizeof(first)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(first, p, flen);
  first[flen] = 0;

  for(int i=0; i<u->nmounts; i++) {
    if(strcmp(u->mounts[i].name, first)) continue;

    r->mount = i;
    r->rw = u->mounts[i].rw;

    const char *base = u->mounts[i].path;
    size_t blen = strlen(base);
    while(blen > 1 && base[blen-1] == '/') blen--;

    if(!rest || !rest[1]) {
      r->is_mount_root = 1;
      snprintf(r->real, sizeof(r->real), "%.*s", (int)blen, base);
      return 0;
    }

    int w = snprintf(r->real, sizeof(r->real), "%.*s%s",
                     (int)(blen == 1 ? 0 : blen), base, rest);
    if(w < 0 || (size_t)w >= sizeof(r->real)) {
      errno = ENAMETOOLONG;
      return -1;
    }

    /* No permitir cruzar enlaces simbólicos dentro del montaje. */
    char acc[PATH_MAX];
    size_t pos = (blen == 1 ? 0 : blen);
    while(pos < strlen(r->real)) {
      const char *slash = strchr(r->real + pos + 1, '/');
      size_t end = slash ? (size_t)(slash - r->real) : strlen(r->real);
      memcpy(acc, r->real, end);
      acc[end] = 0;

      struct stat st;
      if(lstat(acc, &st)) {
        break;            /* no existe (p. ej. archivo a crear): fin */
      }
      if(S_ISLNK(st.st_mode)) {
        errno = EACCES;
        return -1;
      }
      pos = end;
    }
    return 0;
  }

  errno = ENOENT;
  return -1;
}


int
vfs_lookup(const user_t *u, const char *cwd, const char *path, vfs_res_t *r) {
  char v[PATH_MAX];
  vfs_normalize(cwd, path, v, sizeof(v));
  return vfs_resolve(u, v, r);
}
