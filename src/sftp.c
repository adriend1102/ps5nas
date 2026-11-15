/* ps5share - servidor SFTP (SSH) multiusuario
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   El transporte SSH (cifrado, intercambio de claves, autenticación) lo hace
   wolfSSH.  El protocolo SFTP (versión 3, el que usan OpenSSH, FileZilla,
   WinSCP y los exploradores de Android) está implementado aquí, encima del
   mismo VFS que el FTP y la web: cada usuario solo ve sus carpetas y solo
   puede escribir en las de lectura/escritura.

   Solo se acepta el subsistema "sftp": no hay shell, ni ejecución de
   comandos, ni reenvío de puertos.  */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <wolfssh/ssh.h>
#include <wolfssh/keygen.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "config.h"
#include "io.h"
#include "log.h"
#include "sftp.h"
#include "vfs.h"

#define SFTP_MAX_CLIENTS   32
#define SFTP_MAX_HANDLES   64
#define SFTP_MAX_PACKET    (256 * 1024 + 1024)
#define SFTP_MAX_READ      (128 * 1024)
#define SFTP_IDLE_MS       (30 * 60 * 1000)
#define SFTP_MAX_AUTH      5

/* Tipos de mensaje SFTP v3 (draft-ietf-secsh-filexfer-02) */
enum {
  FXP_INIT = 1, FXP_VERSION = 2, FXP_OPEN = 3, FXP_CLOSE = 4, FXP_READ = 5,
  FXP_WRITE = 6, FXP_LSTAT = 7, FXP_FSTAT = 8, FXP_SETSTAT = 9,
  FXP_FSETSTAT = 10, FXP_OPENDIR = 11, FXP_READDIR = 12, FXP_REMOVE = 13,
  FXP_MKDIR = 14, FXP_RMDIR = 15, FXP_REALPATH = 16, FXP_STAT = 17,
  FXP_RENAME = 18, FXP_READLINK = 19, FXP_SYMLINK = 20,
  FXP_STATUS = 101, FXP_HANDLE = 102, FXP_DATA = 103, FXP_NAME = 104,
  FXP_ATTRS = 105, FXP_EXTENDED = 200, FXP_EXTENDED_REPLY = 201,
};

enum {
  FX_OK = 0, FX_EOF = 1, FX_NO_SUCH_FILE = 2, FX_PERMISSION_DENIED = 3,
  FX_FAILURE = 4, FX_BAD_MESSAGE = 5, FX_OP_UNSUPPORTED = 8,
};

#define FXF_READ   0x01
#define FXF_WRITE  0x02
#define FXF_APPEND 0x04
#define FXF_CREAT  0x08
#define FXF_TRUNC  0x10
#define FXF_EXCL   0x20

#define ATTR_SIZE        0x01
#define ATTR_UIDGID      0x02
#define ATTR_PERMISSIONS 0x04
#define ATTR_ACMODTIME   0x08
#define ATTR_EXTENDED    0x80000000u


static WOLFSSH_CTX *g_ctx = NULL;
static char g_fp_ecdsa[80];
static char g_fp_rsa[80];
static int  g_nclients = 0;
static pthread_mutex_t g_nclients_lock = PTHREAD_MUTEX_INITIALIZER;


/* ------------------------------------------------------------------ */
/* Sesión                                                              */
/* ------------------------------------------------------------------ */

typedef struct handle {
  int   used;
  int   is_dir;
  int   is_file;
  vfile_t vf;
  int   rw;
  int   enc;
  DIR  *dir;
  int   root_idx;           /* para listar la raíz virtual */
  int   done;
  char  vpath[PATH_MAX];
  char  real[PATH_MAX];
} handle_t;


typedef struct sess {
  WOLFSSH *ssh;
  int      fd;
  struct sockaddr_in peer;
  int      authed;
  int      auth_fails;
  int      sftp_ok;
  user_t   user;
  ukey_t   key;     /* clave de sus carpetas cifradas */

  uint8_t *in;      /* paquete entrante */
  size_t   in_len;
  uint8_t *out;     /* respuesta */
  size_t   out_len, out_cap;
  int      out_err;

  handle_t handles[SFTP_MAX_HANDLES];
} sess_t;


/* ------------------------------------------------------------------ */
/* Codificación                                                        */
/* ------------------------------------------------------------------ */

static void
out_reserve(sess_t *s, size_t n) {
  if(s->out_len + n <= s->out_cap) return;
  size_t nc = s->out_cap ? s->out_cap : 4096;
  while(nc < s->out_len + n) nc *= 2;
  uint8_t *p = realloc(s->out, nc);
  if(!p) {
    s->out_err = 1;
    return;
  }
  s->out = p;
  s->out_cap = nc;
}

static void
put_bytes(sess_t *s, const void *b, size_t n) {
  out_reserve(s, n);
  if(s->out_err) return;
  memcpy(s->out + s->out_len, b, n);
  s->out_len += n;
}

static void
put_u8(sess_t *s, uint8_t v) {
  put_bytes(s, &v, 1);
}

static void
put_u32(sess_t *s, uint32_t v) {
  uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
  put_bytes(s, b, 4);
}

static void
put_u64(sess_t *s, uint64_t v) {
  put_u32(s, (uint32_t)(v >> 32));
  put_u32(s, (uint32_t)v);
}

static void
put_str(sess_t *s, const void *p, size_t n) {
  put_u32(s, (uint32_t)n);
  put_bytes(s, p, n);
}

static void
put_cstr(sess_t *s, const char *p) {
  put_str(s, p, strlen(p));
}


/* Comienza una respuesta: deja hueco para la longitud. */
static void
begin(sess_t *s, uint8_t type, uint32_t id, int with_id) {
  s->out_len = 0;
  s->out_err = 0;
  put_u32(s, 0);
  put_u8(s, type);
  if(with_id) put_u32(s, id);
}


typedef struct reader {
  const uint8_t *p;
  size_t len, pos;
  int err;
} reader_t;

static uint32_t
get_u32(reader_t *r) {
  if(r->pos + 4 > r->len) { r->err = 1; return 0; }
  const uint8_t *b = r->p + r->pos;
  r->pos += 4;
  return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

static uint64_t
get_u64(reader_t *r) {
  uint64_t hi = get_u32(r);
  uint64_t lo = get_u32(r);
  return (hi << 32) | lo;
}

/* Devuelve un puntero al contenido del string (no terminado en 0). */
static const uint8_t *
get_str(reader_t *r, uint32_t *len) {
  uint32_t n = get_u32(r);
  if(r->err || r->pos + n > r->len) { r->err = 1; *len = 0; return NULL; }
  const uint8_t *p = r->p + r->pos;
  r->pos += n;
  *len = n;
  return p;
}

/* Lee un string como texto C (rechaza bytes nulos y textos largos). */
static int
get_cstr(reader_t *r, char *out, size_t outlen) {
  uint32_t n;
  const uint8_t *p = get_str(r, &n);
  if(!p || n >= outlen || memchr(p, 0, n)) { r->err = 1; return -1; }
  memcpy(out, p, n);
  out[n] = 0;
  return 0;
}

/* Salta un bloque ATTRS (en OPEN, MKDIR, SETSTAT...). */
static void
skip_attrs(reader_t *r) {
  uint32_t flags = get_u32(r);
  if(flags & ATTR_SIZE) get_u64(r);
  if(flags & ATTR_UIDGID) { get_u32(r); get_u32(r); }
  if(flags & ATTR_PERMISSIONS) get_u32(r);
  if(flags & ATTR_ACMODTIME) { get_u32(r); get_u32(r); }
  if(flags & ATTR_EXTENDED) {
    uint32_t n = get_u32(r), l;
    for(uint32_t i=0; i<n && !r->err; i++) { get_str(r, &l); get_str(r, &l); }
  }
}


static void
put_attrs(sess_t *s, const struct stat *st, int rw) {
  uint32_t perm = st->st_mode & S_IFMT;
  if(S_ISDIR(st->st_mode)) perm |= rw ? 0755 : 0555;
  else perm |= rw ? 0644 : 0444;
  put_u32(s, ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME);
  put_u64(s, (uint64_t)st->st_size);
  put_u32(s, 0);
  put_u32(s, 0);
  put_u32(s, perm);
  put_u32(s, (uint32_t)st->st_atime);
  put_u32(s, (uint32_t)st->st_mtime);
}


static void
longname(char *buf, size_t len, const char *name, const struct stat *st, int rw) {
  struct tm tm;
  char tbuf[32];
  int dir = S_ISDIR(st->st_mode);
  gmtime_r(&st->st_mtime, &tm);
  strftime(tbuf, sizeof(tbuf), "%b %d %H:%M", &tm);
  snprintf(buf, len, "%cr%c%cr-%cr-%c 1 ps5 ps5 %12llu %s %s",
           dir ? 'd' : '-', rw ? 'w' : '-', dir ? 'x' : '-', dir ? 'x' : '-',
           dir ? 'x' : '-', (unsigned long long)st->st_size, tbuf, name);
}


/* ------------------------------------------------------------------ */
/* Envío / recepción sobre el canal SSH                                */
/* ------------------------------------------------------------------ */

static int
chan_send(sess_t *s, const uint8_t *buf, size_t len) {
  size_t off = 0;
  int spins = 0;
  while(off < len) {
    int n = wolfSSH_stream_send(s->ssh, (byte*)buf + off, (word32)(len - off));
    if(n > 0) {
      off += (size_t)n;
      spins = 0;
      continue;
    }
    int err = wolfSSH_get_error(s->ssh);
    if(n == WS_WINDOW_FULL || err == WS_WINDOW_FULL || err == WS_WANT_WRITE ||
       err == WS_REKEYING || err == WS_WANT_READ || n == WS_REKEYING) {
      if(++spins > 100000) return -1;
      /* Procesa el ajuste de ventana / rekey del cliente. */
      int w = wolfSSH_worker(s->ssh, NULL);
      if(w == WS_FATAL_ERROR || w == WS_CHANNEL_CLOSED || w == WS_DISCONNECT) return -1;
      if(w == WS_WANT_READ && io_wait_readable(s->fd, SFTP_IDLE_MS) != 1) return -1;
      continue;
    }
    return -1;
  }
  return 0;
}


static int
finish(sess_t *s) {
  if(s->out_err) return -1;
  uint32_t n = (uint32_t)(s->out_len - 4);
  s->out[0] = (uint8_t)(n >> 24);
  s->out[1] = (uint8_t)(n >> 16);
  s->out[2] = (uint8_t)(n >> 8);
  s->out[3] = (uint8_t)n;
  return chan_send(s, s->out, s->out_len);
}


/* Lee exactamente N bytes del canal. */
static int
chan_read(sess_t *s, uint8_t *buf, size_t len) {
  size_t off = 0;
  int spins = 0;
  while(off < len) {
    int n = wolfSSH_stream_read(s->ssh, buf + off, (word32)(len - off));
    if(n > 0) {
      off += (size_t)n;
      spins = 0;
      continue;
    }
    int err = wolfSSH_get_error(s->ssh);
    if(n == WS_REKEYING || n == WS_WANT_READ || n == WS_WANT_WRITE || n == WS_CHAN_RXD ||
       n == WS_WINDOW_FULL || n == 0 ||
       (n == WS_FATAL_ERROR && (err == WS_WANT_READ || err == WS_WANT_WRITE ||
                                err == WS_REKEYING))) {
      if(++spins > 100000) return -1;
      if((n == WS_WANT_READ || err == WS_WANT_READ) &&
         io_wait_readable(s->fd, SFTP_IDLE_MS) != 1) {
        return -1;   /* inactividad */
      }
      continue;
    }
    return -1;   /* EOF, canal cerrado o error */
  }
  return 0;
}


/* ------------------------------------------------------------------ */
/* Respuestas                                                          */
/* ------------------------------------------------------------------ */

static int
status(sess_t *s, uint32_t id, uint32_t code, const char *msg) {
  begin(s, FXP_STATUS, id, 1);
  put_u32(s, code);
  put_cstr(s, msg);
  put_cstr(s, "es");
  return finish(s);
}

static int
status_errno(sess_t *s, uint32_t id) {
  switch(errno) {
  case ENOENT:
  case ENOTDIR: return status(s, id, FX_NO_SUCH_FILE, "No existe");
  case EACCES:
  case EPERM:   return status(s, id, FX_PERMISSION_DENIED, "Permiso denegado");
  case EEXIST:  return status(s, id, FX_FAILURE, "Ya existe");
  case ENOTEMPTY: return status(s, id, FX_FAILURE, "La carpeta no está vacía");
  case ENOSPC:  return status(s, id, FX_FAILURE, "Sin espacio en el disco");
  default:      return status(s, id, FX_FAILURE, strerror(errno));
  }
}

static int
deny(sess_t *s, uint32_t id) {
  return status(s, id, FX_PERMISSION_DENIED, "Permiso denegado");
}


static int
send_handle(sess_t *s, uint32_t id, int idx) {
  char h[16];
  int n = snprintf(h, sizeof(h), "h%d", idx);
  begin(s, FXP_HANDLE, id, 1);
  put_str(s, h, (size_t)n);
  return finish(s);
}


static handle_t *
get_handle(sess_t *s, reader_t *r) {
  uint32_t n;
  const uint8_t *p = get_str(r, &n);
  char buf[16];
  if(!p || n < 2 || n >= sizeof(buf) || p[0] != 'h') return NULL;
  memcpy(buf, p + 1, n - 1);
  buf[n - 1] = 0;
  char *end;
  long idx = strtol(buf, &end, 10);
  if(*end || idx < 0 || idx >= SFTP_MAX_HANDLES || !s->handles[idx].used) return NULL;
  return &s->handles[idx];
}


static int
alloc_handle(sess_t *s) {
  for(int i=0; i<SFTP_MAX_HANDLES; i++) {
    if(!s->handles[i].used) {
      memset(&s->handles[i], 0, sizeof(s->handles[i]));
      s->handles[i].used = 1;
      return i;
    }
  }
  return -1;
}


static void
close_handle(handle_t *h) {
  if(h->is_file) vf_close(&h->vf);
  if(h->dir) closedir(h->dir);
  memset(h, 0, sizeof(*h));
}


/* ------------------------------------------------------------------ */
/* Operaciones                                                         */
/* ------------------------------------------------------------------ */

static int
lookup(sess_t *s, reader_t *r, vfs_res_t *res, int *bad) {
  char path[PATH_MAX];
  *bad = 0;
  if(get_cstr(r, path, sizeof(path))) {
    *bad = 1;
    return -1;
  }
  return vfs_lookup(&s->user, &s->key, "/", path, res);
}


static int
op_realpath(sess_t *s, uint32_t id, reader_t *r) {
  char path[PATH_MAX], norm[PATH_MAX];
  if(get_cstr(r, path, sizeof(path))) return status(s, id, FX_BAD_MESSAGE, "Mensaje no válido");
  vfs_normalize("/", path, norm, sizeof(norm));
  begin(s, FXP_NAME, id, 1);
  put_u32(s, 1);
  put_cstr(s, norm);
  put_cstr(s, norm);
  put_u32(s, 0);
  return finish(s);
}


static int
op_stat(sess_t *s, uint32_t id, reader_t *r) {
  vfs_res_t res;
  struct stat st;
  int bad;
  if(lookup(s, r, &res, &bad)) {
    return bad ? status(s, id, FX_BAD_MESSAGE, "Mensaje no válido") : status_errno(s, id);
  }
  if(res.mount < 0) {
    memset(&st, 0, sizeof(st));
    st.st_mode = S_IFDIR | 0555;
    st.st_mtime = st.st_atime = time(NULL);
  } else if(vfs_stat(&res, &st)) {
    return status_errno(s, id);
  }
  begin(s, FXP_ATTRS, id, 1);
  put_attrs(s, &st, res.mount >= 0 && res.rw);
  return finish(s);
}


static int
op_fstat(sess_t *s, uint32_t id, reader_t *r) {
  handle_t *h = get_handle(s, r);
  struct stat st;
  if(!h) return status(s, id, FX_FAILURE, "Handle no válido");
  if(h->is_file) {
    if(fstat(h->vf.fd, &st)) return status_errno(s, id);
    off_t sz = vf_size(&h->vf);
    if(sz >= 0) st.st_size = sz;
  } else if(h->real[0]) {
    if(stat(h->real, &st)) return status_errno(s, id);
  } else {
    memset(&st, 0, sizeof(st));
    st.st_mode = S_IFDIR | 0555;
  }
  begin(s, FXP_ATTRS, id, 1);
  put_attrs(s, &st, h->rw);
  return finish(s);
}


static int
op_open(sess_t *s, uint32_t id, reader_t *r) {
  vfs_res_t res;
  int bad;
  if(lookup(s, r, &res, &bad)) {
    return bad ? status(s, id, FX_BAD_MESSAGE, "Mensaje no válido") : status_errno(s, id);
  }
  uint32_t pflags = get_u32(r);
  skip_attrs(r);
  if(r->err) return status(s, id, FX_BAD_MESSAGE, "Mensaje no válido");
  if(res.mount < 0 || res.is_mount_root) return status(s, id, FX_FAILURE, "Es una carpeta");

  int writing = pflags & (FXF_WRITE | FXF_APPEND | FXF_CREAT | FXF_TRUNC);
  if(writing && !res.rw) return deny(s, id);

  int flags;
  if((pflags & FXF_READ) && (pflags & FXF_WRITE)) flags = O_RDWR;
  else if(pflags & FXF_WRITE) flags = O_WRONLY;
  else flags = O_RDONLY;
  if(pflags & FXF_APPEND) flags |= O_APPEND;
  if(pflags & FXF_CREAT) flags |= O_CREAT;
  if(pflags & FXF_TRUNC) flags |= O_TRUNC;
  if(pflags & FXF_EXCL) flags |= O_EXCL;

  struct stat st;
  if(!stat(res.real, &st) && S_ISDIR(st.st_mode)) return status(s, id, FX_FAILURE, "Es una carpeta");

  int idx = alloc_handle(s);
  if(idx < 0) return status(s, id, FX_FAILURE, "Demasiados archivos abiertos");
  handle_t *h = &s->handles[idx];
  if(vf_open(&h->vf, &res, flags)) {
    int e = errno;
    h->used = 0;
    errno = e;
    return status_errno(s, id);
  }
  h->is_file = 1;
  h->rw = res.rw;
  snprintf(h->vpath, sizeof(h->vpath), "%s", res.vpath);
  snprintf(h->real, sizeof(h->real), "%s", res.real);
  return send_handle(s, id, idx);
}


static int
op_close(sess_t *s, uint32_t id, reader_t *r) {
  handle_t *h = get_handle(s, r);
  if(!h) return status(s, id, FX_FAILURE, "Handle no válido");
  int err = 0;
  if(h->is_file && vf_close(&h->vf)) err = errno;
  h->is_file = 0;
  close_handle(h);
  if(err) {
    errno = err;
    return status_errno(s, id);
  }
  return status(s, id, FX_OK, "OK");
}


static int
op_read(sess_t *s, uint32_t id, reader_t *r) {
  handle_t *h = get_handle(s, r);
  uint64_t off = get_u64(r);
  uint32_t len = get_u32(r);
  if(r->err) return status(s, id, FX_BAD_MESSAGE, "Mensaje no válido");
  if(!h || !h->is_file) return status(s, id, FX_FAILURE, "Handle no válido");
  if(len > SFTP_MAX_READ) len = SFTP_MAX_READ;

  begin(s, FXP_DATA, id, 1);
  size_t lenpos = s->out_len;
  put_u32(s, 0);
  out_reserve(s, len);
  if(s->out_err) return -1;
  ssize_t n = vf_pread(&h->vf, s->out + s->out_len, len, (off_t)off);
  if(n < 0) return status_errno(s, id);
  if(n == 0) return status(s, id, FX_EOF, "Fin de archivo");
  s->out_len += (size_t)n;
  s->out[lenpos]   = (uint8_t)(n >> 24);
  s->out[lenpos+1] = (uint8_t)(n >> 16);
  s->out[lenpos+2] = (uint8_t)(n >> 8);
  s->out[lenpos+3] = (uint8_t)n;
  return finish(s);
}


static int
op_write(sess_t *s, uint32_t id, reader_t *r) {
  handle_t *h = get_handle(s, r);
  uint64_t off = get_u64(r);
  uint32_t len;
  const uint8_t *data = get_str(r, &len);
  if(r->err || !data) return status(s, id, FX_BAD_MESSAGE, "Mensaje no válido");
  if(!h || !h->is_file) return status(s, id, FX_FAILURE, "Handle no válido");
  if(!h->rw) return deny(s, id);

  ssize_t n = vf_pwrite(&h->vf, data, len, (off_t)off);
  if(n < 0 || (uint32_t)n != len) return status_errno(s, id);
  return status(s, id, FX_OK, "OK");
}


static int
op_opendir(sess_t *s, uint32_t id, reader_t *r) {
  vfs_res_t res;
  int bad;
  if(lookup(s, r, &res, &bad)) {
    return bad ? status(s, id, FX_BAD_MESSAGE, "Mensaje no válido") : status_errno(s, id);
  }
  int idx = alloc_handle(s);
  if(idx < 0) return status(s, id, FX_FAILURE, "Demasiados handles abiertos");
  handle_t *h = &s->handles[idx];
  h->is_dir = 1;
  snprintf(h->vpath, sizeof(h->vpath), "%s", res.vpath);
  if(res.mount >= 0) {
    if(!(h->dir = opendir(res.real))) {
      int e = errno;
      h->used = 0;
      errno = e;
      return status_errno(s, id);
    }
    h->rw = res.rw;
    h->enc = res.enc;
    snprintf(h->real, sizeof(h->real), "%s", res.real);
  }
  return send_handle(s, id, idx);
}


static int
op_readdir(sess_t *s, uint32_t id, reader_t *r) {
  handle_t *h = get_handle(s, r);
  char lname[PATH_MAX + 128];
  struct stat st;
  int count = 0;

  if(!h || !h->is_dir) return status(s, id, FX_FAILURE, "Handle no válido");
  if(h->done) return status(s, id, FX_EOF, "Fin");

  begin(s, FXP_NAME, id, 1);
  size_t cntpos = s->out_len;
  put_u32(s, 0);

  if(!h->dir) {
    /* Raíz virtual: las carpetas asignadas al usuario. */
    for(; h->root_idx < s->user.nmounts && count < 100; h->root_idx++) {
      const mount_t *m = &s->user.mounts[h->root_idx];
      if(!vfs_mount_usable(&s->user, &s->key, h->root_idx)) continue;
      if(stat(m->path, &st) || !S_ISDIR(st.st_mode)) continue;
      longname(lname, sizeof(lname), m->name, &st, m->rw);
      put_cstr(s, m->name);
      put_cstr(s, lname);
      put_attrs(s, &st, m->rw);
      count++;
    }
    if(h->root_idx >= s->user.nmounts) h->done = 1;
  } else {
    struct dirent *e;
    char full[PATH_MAX * 2], name[NAME_MAX + 1];
    vfs_res_t dres;
    memset(&dres, 0, sizeof(dres));
    dres.enc = h->enc;
    dres.key = &s->key;
    while(count < 100 && (e = readdir(h->dir))) {
      if(vfs_entry_name(&dres, e->d_name, name, sizeof(name))) continue;
      snprintf(full, sizeof(full), "%s/%s", h->real, e->d_name);
      if(lstat(full, &st) || S_ISLNK(st.st_mode)) continue;
      vfs_fix_size(&dres, &st);
      longname(lname, sizeof(lname), name, &st, h->rw);
      put_cstr(s, name);
      put_cstr(s, lname);
      put_attrs(s, &st, h->rw);
      count++;
    }
    if(count < 100) h->done = 1;
  }

  if(!count) return status(s, id, FX_EOF, "Fin");
  if(s->out_err) return -1;
  s->out[cntpos]   = (uint8_t)(count >> 24);
  s->out[cntpos+1] = (uint8_t)(count >> 16);
  s->out[cntpos+2] = (uint8_t)(count >> 8);
  s->out[cntpos+3] = (uint8_t)count;
  return finish(s);
}


static int
op_remove(sess_t *s, uint32_t id, reader_t *r) {
  vfs_res_t res;
  struct stat st;
  int bad;
  if(lookup(s, r, &res, &bad)) {
    return bad ? status(s, id, FX_BAD_MESSAGE, "Mensaje no válido") : status_errno(s, id);
  }
  if(res.mount < 0 || res.is_mount_root || !res.rw) return deny(s, id);
  if(lstat(res.real, &st)) return status_errno(s, id);
  if(S_ISDIR(st.st_mode)) return status(s, id, FX_FAILURE, "Es una carpeta");
  if(unlink(res.real)) return status_errno(s, id);
  return status(s, id, FX_OK, "OK");
}


static int
op_mkdir(sess_t *s, uint32_t id, reader_t *r) {
  vfs_res_t res;
  int bad;
  if(lookup(s, r, &res, &bad)) {
    return bad ? status(s, id, FX_BAD_MESSAGE, "Mensaje no válido") : status_errno(s, id);
  }
  skip_attrs(r);
  if(res.mount < 0 || res.is_mount_root || !res.rw) return deny(s, id);
  if(mkdir(res.real, 0777)) return status_errno(s, id);
  return status(s, id, FX_OK, "OK");
}


static int
op_rmdir(sess_t *s, uint32_t id, reader_t *r) {
  vfs_res_t res;
  int bad;
  if(lookup(s, r, &res, &bad)) {
    return bad ? status(s, id, FX_BAD_MESSAGE, "Mensaje no válido") : status_errno(s, id);
  }
  if(res.mount < 0 || res.is_mount_root || !res.rw) return deny(s, id);
  if(rmdir(res.real)) return status_errno(s, id);
  return status(s, id, FX_OK, "OK");
}


static int
op_rename(sess_t *s, uint32_t id, reader_t *r, int posix) {
  vfs_res_t from, to;
  struct stat st;
  int bad;
  if(lookup(s, r, &from, &bad)) {
    return bad ? status(s, id, FX_BAD_MESSAGE, "Mensaje no válido") : status_errno(s, id);
  }
  if(lookup(s, r, &to, &bad)) {
    return bad ? status(s, id, FX_BAD_MESSAGE, "Mensaje no válido") : status_errno(s, id);
  }
  if(from.mount < 0 || from.is_mount_root || !from.rw ||
     to.mount < 0 || to.is_mount_root || !to.rw || from.mount != to.mount) {
    return deny(s, id);
  }
  /* SFTP v3 estándar: no sobrescribir; posix-rename sí. */
  if(!posix && !lstat(to.real, &st)) return status(s, id, FX_FAILURE, "Ya existe");
  if(rename(from.real, to.real)) return status_errno(s, id);
  return status(s, id, FX_OK, "OK");
}


static int
op_setstat(sess_t *s, uint32_t id, reader_t *r, int by_handle) {
  /* Se acepta y se ignora (los clientes intentan poner permisos o fechas
     tras subir).  Solo se comprueba que el destino exista. */
  if(by_handle) {
    if(!get_handle(s, r)) return status(s, id, FX_FAILURE, "Handle no válido");
  } else {
    vfs_res_t res;
    int bad;
    if(lookup(s, r, &res, &bad)) {
      return bad ? status(s, id, FX_BAD_MESSAGE, "Mensaje no válido") : status_errno(s, id);
    }
  }
  return status(s, id, FX_OK, "OK");
}


static int
op_extended(sess_t *s, uint32_t id, reader_t *r) {
  char name[128];
  if(get_cstr(r, name, sizeof(name))) return status(s, id, FX_BAD_MESSAGE, "Mensaje no válido");
  if(!strcmp(name, "posix-rename@openssh.com")) return op_rename(s, id, r, 1);
  return status(s, id, FX_OP_UNSUPPORTED, "No soportado");
}


/* ------------------------------------------------------------------ */
/* Bucle SFTP                                                          */
/* ------------------------------------------------------------------ */

static int
handle_packet(sess_t *s) {
  reader_t r = {s->in, s->in_len, 0, 0};
  uint8_t type = s->in[0];
  r.pos = 1;

  if(type == FXP_INIT) {
    begin(s, FXP_VERSION, 0, 0);
    put_u32(s, 3);
    put_cstr(s, "posix-rename@openssh.com");
    put_cstr(s, "1");
    return finish(s);
  }

  uint32_t id = get_u32(&r);
  if(r.err) return -1;

  /* Recarga el usuario: los cambios de la web se aplican al momento. */
  user_t fresh;
  if(cfg_get_user(s->user.name, &fresh) || !fresh.enabled || fresh.must_chpass) {
    status(s, id, FX_PERMISSION_DENIED, "Tu cuenta ha sido desactivada");
    return -1;
  }
  memcpy(&s->user, &fresh, sizeof(fresh));

  switch(type) {
  case FXP_OPEN:     return op_open(s, id, &r);
  case FXP_CLOSE:    return op_close(s, id, &r);
  case FXP_READ:     return op_read(s, id, &r);
  case FXP_WRITE:    return op_write(s, id, &r);
  case FXP_LSTAT:
  case FXP_STAT:     return op_stat(s, id, &r);
  case FXP_FSTAT:    return op_fstat(s, id, &r);
  case FXP_SETSTAT:  return op_setstat(s, id, &r, 0);
  case FXP_FSETSTAT: return op_setstat(s, id, &r, 1);
  case FXP_OPENDIR:  return op_opendir(s, id, &r);
  case FXP_READDIR:  return op_readdir(s, id, &r);
  case FXP_REMOVE:   return op_remove(s, id, &r);
  case FXP_MKDIR:    return op_mkdir(s, id, &r);
  case FXP_RMDIR:    return op_rmdir(s, id, &r);
  case FXP_REALPATH: return op_realpath(s, id, &r);
  case FXP_RENAME:   return op_rename(s, id, &r, 0);
  case FXP_EXTENDED: return op_extended(s, id, &r);
  default:           return status(s, id, FX_OP_UNSUPPORTED, "No soportado");
  }
}


static void
sftp_loop(sess_t *s) {
  uint8_t hdr[4];
  s->in = malloc(SFTP_MAX_PACKET);
  if(!s->in) return;

  for(;;) {
    if(chan_read(s, hdr, 4)) break;
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | hdr[3];
    if(len < 1 || len > SFTP_MAX_PACKET) break;
    if(chan_read(s, s->in, len)) break;
    s->in_len = len;
    if(handle_packet(s)) break;
  }

  for(int i=0; i<SFTP_MAX_HANDLES; i++) {
    if(s->handles[i].used) close_handle(&s->handles[i]);
  }
}


/* ------------------------------------------------------------------ */
/* Callbacks de wolfSSH                                                */
/* ------------------------------------------------------------------ */

static int
cb_auth_types(WOLFSSH *ssh, void *ctx) {
  return WOLFSSH_USERAUTH_PASSWORD;
}


static int
cb_auth(byte type, WS_UserAuthData *d, void *ctx) {
  sess_t *s = ctx;
  char user[CFG_NAME_MAX + 1];
  char pass[256];
  char ip[INET_ADDRSTRLEN];

  if(!s || type != WOLFSSH_USERAUTH_PASSWORD || !d) return WOLFSSH_USERAUTH_FAILURE;
  if(d->usernameSz >= sizeof(user) || d->sf.password.passwordSz >= sizeof(pass)) {
    return WOLFSSH_USERAUTH_FAILURE;
  }
  memcpy(user, d->username, d->usernameSz);
  user[d->usernameSz] = 0;
  memcpy(pass, d->sf.password.password, d->sf.password.passwordSz);
  pass[d->sf.password.passwordSz] = 0;

  inet_ntop(AF_INET, &s->peer.sin_addr, ip, sizeof(ip));
  int via_app = 0;
  int ok = !memchr(d->username, 0, d->usernameSz) &&
           !cfg_authenticate_service(user, pass, &s->user, &via_app);
  if(ok && !s->user.must_chpass) {
    /* Con una contraseña de aplicación la clave se abre con la guardada. */
    if(via_app) cfg_unlock_key_stored(s->user.name, &s->key);
    else cfg_unlock_key(s->user.name, pass, &s->key);
  }
  memset(pass, 0, sizeof(pass));

  if(!ok) {
    LOG_PRINTF("sftp: login fallido de '%s' desde %s\n", user, ip);
    sleep(2);
    if(++s->auth_fails >= SFTP_MAX_AUTH) return WOLFSSH_USERAUTH_REJECTED;
    return WOLFSSH_USERAUTH_INVALID_PASSWORD;
  }
  if(s->user.must_chpass) {
    /* SFTP no tiene forma estándar de pedir el cambio; se hace en la web. */
    LOG_PRINTF("sftp: '%s' debe cambiar su contraseña en la web\n", s->user.name);
    return WOLFSSH_USERAUTH_REJECTED;
  }
  s->authed = 1;
  LOG_PRINTF("sftp: '%s' conectado desde %s\n", s->user.name, ip);
  return WOLFSSH_USERAUTH_SUCCESS;
}


static int
cb_reject(WOLFSSH_CHANNEL *ch, void *ctx) {
  return 1;   /* shell / exec: denegado */
}


static int
cb_subsys(WOLFSSH_CHANNEL *ch, void *ctx) {
  sess_t *s = ctx;
  const char *cmd = wolfSSH_ChannelGetSessionCommand(ch);
  if(!s || !s->authed || s->sftp_ok || !cmd) return 1;
  if(wolfSSH_ChannelGetSessionType(ch) != WOLFSSH_SESSION_SUBSYSTEM) return 1;
  if(wolfSSH_ChannelGetSessionCommandSz(ch) != 4 || strcmp(cmd, "sftp")) return 1;
  s->sftp_ok = 1;
  return WS_SUCCESS;
}


static int
cb_chan_open(WOLFSSH_CHANNEL *ch, void *ctx) {
  const char *t = wolfSSH_ChannelGetType(ch);
  return (t && !strcmp(t, "session")) ? WS_SUCCESS : 1;
}


/* ------------------------------------------------------------------ */
/* Claves del servidor                                                 */
/* ------------------------------------------------------------------ */

static void
b64(const uint8_t *in, size_t n, char *out) {
  static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t o = 0;
  for(size_t i=0; i<n; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    if(i + 1 < n) v |= (uint32_t)in[i+1] << 8;
    if(i + 2 < n) v |= in[i+2];
    out[o++] = t[(v >> 18) & 63];
    out[o++] = t[(v >> 12) & 63];
    if(i + 1 < n) out[o++] = t[(v >> 6) & 63];
    if(i + 2 < n) out[o++] = t[v & 63];
  }
  out[o] = 0;   /* sin '=' como en "SHA256:..." de OpenSSH */
}


static void
blob_str(uint8_t *blob, size_t *pos, const void *p, size_t n) {
  blob[(*pos)++] = (uint8_t)(n >> 24);
  blob[(*pos)++] = (uint8_t)(n >> 16);
  blob[(*pos)++] = (uint8_t)(n >> 8);
  blob[(*pos)++] = (uint8_t)n;
  memcpy(blob + *pos, p, n);
  *pos += n;
}


static void
blob_mpint(uint8_t *blob, size_t *pos, const uint8_t *p, size_t n) {
  while(n > 0 && p[0] == 0) { p++; n--; }
  if(n > 0 && (p[0] & 0x80)) {
    uint8_t tmp[1024];
    if(n + 1 > sizeof(tmp)) return;
    tmp[0] = 0;
    memcpy(tmp + 1, p, n);
    blob_str(blob, pos, tmp, n + 1);
  } else {
    blob_str(blob, pos, p, n);
  }
}


static void
fingerprint(const uint8_t *blob, size_t n, char *out, size_t outlen) {
  uint8_t h[32];
  char enc[48];
  wc_Sha256Hash(blob, (word32)n, h);
  b64(h, 32, enc);
  snprintf(out, outlen, "SHA256:%s", enc);
}


static void
fp_ecdsa(const uint8_t *der, word32 sz) {
  ecc_key key;
  word32 idx = 0;
  uint8_t q[133], blob[512];
  word32 qlen = sizeof(q);
  size_t pos = 0;
  if(wc_ecc_init(&key)) return;
  if(!wc_EccPrivateKeyDecode(der, &idx, &key, sz) && !wc_ecc_export_x963(&key, q, &qlen)) {
    blob_str(blob, &pos, "ecdsa-sha2-nistp256", 19);
    blob_str(blob, &pos, "nistp256", 8);
    blob_str(blob, &pos, q, qlen);
    fingerprint(blob, pos, g_fp_ecdsa, sizeof(g_fp_ecdsa));
  }
  wc_ecc_free(&key);
}


static void
fp_rsa(const uint8_t *der, word32 sz) {
  RsaKey key;
  word32 idx = 0;
  uint8_t e[16], n[600], blob[1200];
  word32 elen = sizeof(e), nlen = sizeof(n);
  size_t pos = 0;
  if(wc_InitRsaKey(&key, NULL)) return;
  if(!wc_RsaPrivateKeyDecode(der, &idx, &key, sz) &&
     !wc_RsaFlattenPublicKey(&key, e, &elen, n, &nlen)) {
    blob_str(blob, &pos, "ssh-rsa", 7);
    blob_mpint(blob, &pos, e, elen);
    blob_mpint(blob, &pos, n, nlen);
    fingerprint(blob, pos, g_fp_rsa, sizeof(g_fp_rsa));
  }
  wc_FreeRsaKey(&key);
}


/* Carga una clave del disco o la genera y la guarda (0600). */
static int
load_or_make_key(const char *dir, const char *file, int rsa, uint8_t *buf, size_t cap) {
  char path[PATH_MAX];
  int sz = -1;
  snprintf(path, sizeof(path), "%s/%s", dir, file);

  int fd = open(path, O_RDONLY);
  if(fd >= 0) {
    ssize_t n = read(fd, buf, cap);
    close(fd);
    if(n > 0) sz = (int)n;
  }
  if(sz <= 0) {
    LOG_PRINTF("sftp: generando clave del servidor %s...\n", file);
    sz = rsa ? wolfSSH_MakeRsaKey(buf, (word32)cap, 3072, 65537)
             : wolfSSH_MakeEcdsaKey(buf, (word32)cap, 256);
    if(sz <= 0) {
      LOG_PRINTF("sftp: no se pudo generar %s (%d)\n", file, sz);
      return -1;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(fd >= 0) {
      if(io_writeall(fd, buf, (size_t)sz)) LOG_PERROR("write hostkey");
      close(fd);
    }
  }
  return sz;
}


int
sftp_init(const char *confdir) {
  uint8_t buf[4096];
  int sz;
  int keys = 0;

  if(wolfSSH_Init() != WS_SUCCESS) {
    LOG_PUTS("sftp: wolfSSH_Init falló");
    return -1;
  }
  if(!(g_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL))) {
    LOG_PUTS("sftp: no se pudo crear el contexto SSH");
    return -1;
  }

  if((sz = load_or_make_key(confdir, "ssh_host_ecdsa.der", 0, buf, sizeof(buf))) > 0) {
    if(wolfSSH_CTX_UsePrivateKey_buffer(g_ctx, buf, (word32)sz, WOLFSSH_FORMAT_ASN1) == WS_SUCCESS) {
      fp_ecdsa(buf, (word32)sz);
      keys++;
    }
  }
  if((sz = load_or_make_key(confdir, "ssh_host_rsa.der", 1, buf, sizeof(buf))) > 0) {
    if(wolfSSH_CTX_UsePrivateKey_buffer(g_ctx, buf, (word32)sz, WOLFSSH_FORMAT_ASN1) == WS_SUCCESS) {
      fp_rsa(buf, (word32)sz);
      keys++;
    }
  }
  memset(buf, 0, sizeof(buf));
  if(!keys) {
    LOG_PUTS("sftp: sin claves de servidor, SFTP desactivado");
    wolfSSH_CTX_free(g_ctx);
    g_ctx = NULL;
    return -1;
  }

  wolfSSH_SetUserAuth(g_ctx, cb_auth);
  wolfSSH_SetUserAuthTypes(g_ctx, cb_auth_types);
  wolfSSH_CTX_SetChannelOpenCb(g_ctx, cb_chan_open);
  wolfSSH_CTX_SetChannelReqShellCb(g_ctx, cb_reject);
  wolfSSH_CTX_SetChannelReqExecCb(g_ctx, cb_reject);
  wolfSSH_CTX_SetChannelReqSubsysCb(g_ctx, cb_subsys);
  wolfSSH_CTX_SetBanner(g_ctx, "ps5share SFTP\r\n");
  wolfSSH_CTX_SetWindowPacketSize(g_ctx, 2 * 1024 * 1024, 32 * 1024);

  LOG_PRINTF("sftp: claves listas (ECDSA %s, RSA %s)\n",
             g_fp_ecdsa[0] ? g_fp_ecdsa : "-", g_fp_rsa[0] ? g_fp_rsa : "-");
  return 0;
}


const char *sftp_fingerprint_ecdsa(void) { return g_fp_ecdsa; }
const char *sftp_fingerprint_rsa(void)   { return g_fp_rsa; }


/* ------------------------------------------------------------------ */
/* Servidor                                                            */
/* ------------------------------------------------------------------ */

static void*
client_thread(void *p) {
  sess_t *s = p;
  int opt = 1;

  setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
  setsockopt(s->fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
  io_sock_timeouts(s->fd, 120);   /* el login debe completarse a tiempo */

  if((s->ssh = wolfSSH_new(g_ctx))) {
    wolfSSH_SetUserAuthCtx(s->ssh, s);
    wolfSSH_SetChannelReqCtx(s->ssh, s);
    wolfSSH_set_fd(s->ssh, s->fd);

    int ret = wolfSSH_accept(s->ssh);
    if(ret == WS_SUCCESS && s->authed && s->sftp_ok) {
      io_sock_timeouts(s->fd, 1800);   /* 30 min de inactividad */
      sftp_loop(s);
    }
    wolfSSH_shutdown(s->ssh);
    wolfSSH_free(s->ssh);
  }

  close(s->fd);
  crypt_key_wipe(&s->key);
  free(s->in);
  free(s->out);
  free(s);

  pthread_mutex_lock(&g_nclients_lock);
  g_nclients--;
  pthread_mutex_unlock(&g_nclients_lock);
  return NULL;
}


int
sftp_serve(uint16_t port) {
  struct sockaddr_in sa;
  int srv;

  if(!g_ctx) return -1;
  if((srv = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_PERROR("socket");
    return -1;
  }
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port = htons(port);

  if(bind(srv, (struct sockaddr*)&sa, sizeof(sa)) || listen(srv, 16)) {
    LOG_PERROR("sftp bind/listen");
    close(srv);
    return -1;
  }
  LOG_PRINTF("ps5share: SFTP escuchando en el puerto %u\n", port);

  for(;;) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int fd = accept(srv, (struct sockaddr*)&peer, &plen);
    if(fd < 0) {
      if(errno == EINTR || errno == ECONNABORTED) continue;
      LOG_PERROR("sftp accept");
      break;
    }

    pthread_mutex_lock(&g_nclients_lock);
    int full = g_nclients >= SFTP_MAX_CLIENTS;
    if(!full) g_nclients++;
    pthread_mutex_unlock(&g_nclients_lock);
    if(full) {
      close(fd);
      continue;
    }

    sess_t *s = calloc(1, sizeof(*s));
    if(!s) {
      close(fd);
      pthread_mutex_lock(&g_nclients_lock);
      g_nclients--;
      pthread_mutex_unlock(&g_nclients_lock);
      continue;
    }
    s->fd = fd;
    s->peer = peer;

    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 1024 * 1024);
    if(pthread_create(&t, &attr, client_thread, s)) {
      close(fd);
      free(s);
      pthread_mutex_lock(&g_nclients_lock);
      g_nclients--;
      pthread_mutex_unlock(&g_nclients_lock);
    }
    pthread_attr_destroy(&attr);
  }

  close(srv);
  return -1;
}
