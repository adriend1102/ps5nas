/* ps5share - sistema de archivos virtual por usuario
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
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


/* Cifra cada componente de REST ("/a/b") y lo añade a OUT. */
static int
enc_rest(const ukey_t *key, const char *rest, char *out, size_t outlen) {
  char comp[PATH_MAX], encname[512];
  size_t len = strlen(out);
  const char *p = rest;

  while(*p) {
    while(*p == '/') p++;
    if(!*p) break;
    const char *e = strchr(p, '/');
    size_t n = e ? (size_t)(e - p) : strlen(p);
    if(n >= sizeof(comp)) { errno = ENAMETOOLONG; return -1; }
    memcpy(comp, p, n);
    comp[n] = 0;
    if(crypt_name_enc(key, comp, encname, sizeof(encname))) return -1;
    int w = snprintf(out + len, outlen - len, "/%s", encname);
    if(w < 0 || (size_t)w >= outlen - len) { errno = ENAMETOOLONG; return -1; }
    len += (size_t)w;
    p += n;
  }
  return 0;
}


int
vfs_mount_usable(const user_t *u, const ukey_t *key, int i) {
  if(i < 0 || i >= u->nmounts) return 0;
  return !u->mounts[i].enc || (key && key->ok);
}


int
vfs_resolve(const user_t *u, const ukey_t *key, const char *vabs, vfs_res_t *r) {
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
    r->enc = u->mounts[i].enc;
    if(r->enc) {
      if(!key || !key->ok) {
        errno = EACCES;
        return -1;
      }
      r->key = key;
    }

    const char *base = u->mounts[i].path;
    size_t blen = strlen(base);
    while(blen > 1 && base[blen-1] == '/') blen--;

    if(!rest || !rest[1]) {
      r->is_mount_root = 1;
      snprintf(r->real, sizeof(r->real), "%.*s", (int)blen, base);
      return 0;
    }

    if(r->enc) {
      snprintf(r->real, sizeof(r->real), "%.*s", (int)(blen == 1 ? 0 : blen), base);
      if(enc_rest(key, rest, r->real, sizeof(r->real))) return -1;
    } else {
      int w = snprintf(r->real, sizeof(r->real), "%.*s%s",
                       (int)(blen == 1 ? 0 : blen), base, rest);
      if(w < 0 || (size_t)w >= sizeof(r->real)) {
        errno = ENAMETOOLONG;
        return -1;
      }
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
vfs_lookup(const user_t *u, const ukey_t *key, const char *cwd, const char *path,
           vfs_res_t *r) {
  char v[PATH_MAX];
  vfs_normalize(cwd, path, v, sizeof(v));
  return vfs_resolve(u, key, v, r);
}


int
vfs_entry_name(const vfs_res_t *dir, const char *disk_name, char *out, size_t outlen) {
  if(!strcmp(disk_name, ".") || !strcmp(disk_name, "..")) return -1;
  if(!dir->enc) {
    snprintf(out, outlen, "%s", disk_name);
    return 0;
  }
  return crypt_name_dec(dir->key, disk_name, out, outlen);
}


void
vfs_fix_size(const vfs_res_t *dir, struct stat *st) {
  if(dir->enc && S_ISREG(st->st_mode)) st->st_size = crypt_plain_size(st->st_size);
}


int
vfs_stat(const vfs_res_t *r, struct stat *st) {
  if(stat(r->real, st)) return -1;
  vfs_fix_size(r, st);
  return 0;
}


/* ------------------------------------------------------------------ */
/* Archivos                                                            */
/* ------------------------------------------------------------------ */

int
vf_open(vfile_t *f, const vfs_res_t *r, int flags) {
  memset(f, 0, sizeof(*f));
  f->fd = -1;
  if(r->mount < 0) {
    errno = EISDIR;
    return -1;
  }

  if(!r->enc) {
    if((f->fd = open(r->real, flags, 0666)) < 0) return -1;
    return 0;
  }

  int acc = flags & O_ACCMODE;
  int writable = acc != O_RDONLY;
  int oflags = (writable ? O_RDWR : O_RDONLY) |
               (flags & (O_CREAT | O_EXCL));
  struct stat st;
  int existed = !stat(r->real, &st);
  int fd = open(r->real, oflags, 0666);
  if(fd < 0) return -1;
  int fresh = writable && (!existed || (flags & O_TRUNC));
  if(cfile_open(&f->cf, fd, writable, fresh, r->key)) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  f->fd = fd;
  f->enc = 1;
  f->append = (flags & O_APPEND) != 0;
  return 0;
}


ssize_t
vf_pread(vfile_t *f, void *buf, size_t len, off_t off) {
  if(f->enc) return cfile_pread(&f->cf, buf, len, off);
  for(;;) {
    ssize_t n = pread(f->fd, buf, len, off);
    if(n < 0 && errno == EINTR) continue;
    return n;
  }
}


ssize_t
vf_pwrite(vfile_t *f, const void *buf, size_t len, off_t off) {
  if(f->enc) {
    if(f->append) off = cfile_size(&f->cf);
    return cfile_pwrite(&f->cf, buf, len, off);
  }
  size_t done = 0;
  while(done < len) {
    ssize_t n = pwrite(f->fd, (const char*)buf + done, len - done, off + (off_t)done);
    if(n < 0 && errno == EINTR) continue;
    if(n <= 0) return done ? (ssize_t)done : -1;
    done += (size_t)n;
  }
  return (ssize_t)done;
}


off_t
vf_size(vfile_t *f) {
  if(f->enc) return cfile_size(&f->cf);
  struct stat st;
  if(fstat(f->fd, &st)) return -1;
  return st.st_size;
}


int
vf_close(vfile_t *f) {
  int r = 0;
  if(f->enc) {
    r = cfile_close(&f->cf);
  } else if(f->fd >= 0) {
    r = close(f->fd);
  }
  f->fd = -1;
  f->enc = 0;
  return r;
}
