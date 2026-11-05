/* ps5share - servidor FTP multiusuario
   Copyright (C) 2026  ps5share contributors.
   Basado en ftpsrv (C) 2023-2025 John Törnblom.  GPLv3, ver LICENSE.

   Diferencias principales con ftpsrv:
   - Autenticación USER/PASS contra users.conf (PBKDF2-SHA256).
   - Cada usuario solo ve sus carpetas asignadas (vfs.c), con permisos ro/rw.
   - EPSV (RFC 2428) y rango de puertos pasivos configurable, para que
     funcione a través de Tailscale en la PS5 (las conexiones llegan por
     127.0.0.1 y la IP del PASV se sustituye por la IP de Tailscale).
   - Se eliminan los comandos peligrosos para un servidor compartido
     (KILL, MTRW, CHMOD, SELF).  */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
#include "ftp.h"
#include "io.h"
#include "log.h"
#include "vfs.h"

#define FTP_MAX_CLIENTS   48
#define FTP_LINE_MAX      4096
#define FTP_IDLE_TIMEOUT  900
#define FTP_DATA_TIMEOUT  120
#define FTP_MAX_FAILS     5


typedef struct ftp_env {
  int ctrl_fd;
  int data_fd;
  int pasv_fd;
  int use_port;
  struct sockaddr_in port_addr;
  struct sockaddr_in peer;
  struct sockaddr_in local;

  int  logged_in;
  int  fails;
  char pending_user[CFG_NAME_MAX+1];
  user_t user;

  char  cwd[PATH_MAX];
  char  type;
  off_t rest;
  int   has_rnfr;
  char  rnfr[PATH_MAX];

  void  *buf;
  char   line[FTP_LINE_MAX];
} ftp_env_t;


typedef int (ftp_fn_t)(ftp_env_t *env, const char *arg);

static int g_nclients = 0;
static pthread_mutex_t g_nclients_lock = PTHREAD_MUTEX_INITIALIZER;


/* ------------------------------------------------------------------ */
/* Utilidades                                                          */
/* ------------------------------------------------------------------ */

static int
reply(ftp_env_t *env, const char *fmt, ...) {
  char buf[0x1000];
  va_list ap;
  va_start(ap, fmt);
  int len = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if(len < 0) return -1;
  if((size_t)len >= sizeof(buf)) len = sizeof(buf) - 1;
  return io_writeall(env->ctrl_fd, buf, (size_t)len);
}


static int
reply_errno(ftp_env_t *env) {
  int e = errno;
  switch(e) {
  case ENOENT:  return reply(env, "550 No existe el archivo o carpeta\r\n");
  case EACCES:
  case EPERM:   return reply(env, "550 Permiso denegado\r\n");
  case EEXIST:  return reply(env, "550 Ya existe\r\n");
  case ENOTDIR: return reply(env, "550 No es una carpeta\r\n");
  case EISDIR:  return reply(env, "550 Es una carpeta\r\n");
  case ENOTEMPTY: return reply(env, "550 La carpeta no está vacía\r\n");
  case ENOSPC:  return reply(env, "452 Sin espacio en el disco\r\n");
  case EXDEV:   return reply(env, "550 No se puede mover entre carpetas distintas\r\n");
  default:      return reply(env, "550 %s\r\n", strerror(e));
  }
}


static int
deny(ftp_env_t *env) {
  return reply(env, "550 Permiso denegado\r\n");
}


static int
resolve(ftp_env_t *env, const char *arg, vfs_res_t *r) {
  return vfs_lookup(&env->user, env->cwd, arg, r);
}


static int
readline(ftp_env_t *env) {
  size_t pos = 0;
  char c;

  for(;;) {
    ssize_t n = read(env->ctrl_fd, &c, 1);
    if(n < 0 && errno == EINTR) continue;
    if(n <= 0) return -1;
    if(c == '\r') continue;
    if(c == '\n') break;
    if(pos < sizeof(env->line) - 1) env->line[pos++] = c;
  }
  env->line[pos] = 0;
  return 0;
}


static void
mode_string(mode_t mode, int rw, char *buf) {
  buf[0] = S_ISDIR(mode) ? 'd' : (S_ISLNK(mode) ? 'l' : '-');
  buf[1] = 'r'; buf[2] = rw ? 'w' : '-'; buf[3] = S_ISDIR(mode) ? 'x' : '-';
  buf[4] = 'r'; buf[5] = '-'; buf[6] = S_ISDIR(mode) ? 'x' : '-';
  buf[7] = 'r'; buf[8] = '-'; buf[9] = S_ISDIR(mode) ? 'x' : '-';
  buf[10] = 0;
}


/* ------------------------------------------------------------------ */
/* Conexión de datos                                                   */
/* ------------------------------------------------------------------ */

static void
close_data(ftp_env_t *env) {
  if(env->data_fd >= 0) close(env->data_fd);
  env->data_fd = -1;
}


static void
close_pasv(ftp_env_t *env) {
  if(env->pasv_fd >= 0) close(env->pasv_fd);
  env->pasv_fd = -1;
}


static int
open_data(ftp_env_t *env) {
  int fd = -1;
  int opt;

  close_data(env);

  if(env->use_port) {
    if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;
    io_sock_timeouts(fd, FTP_DATA_TIMEOUT);
    if(connect(fd, (struct sockaddr*)&env->port_addr, sizeof(env->port_addr))) {
      close(fd);
      return -1;
    }
    env->use_port = 0;
  } else if(env->pasv_fd >= 0) {
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    if(io_wait_readable(env->pasv_fd, 30000) != 1) {
      close_pasv(env);
      errno = ETIMEDOUT;
      return -1;
    }
    fd = accept(env->pasv_fd, (struct sockaddr*)&a, &alen);
    close_pasv(env);
    if(fd < 0) return -1;
    /* Solo aceptamos la conexión de datos desde la misma IP del control. */
    if(a.sin_addr.s_addr != env->peer.sin_addr.s_addr) {
      LOG_PUTS("ftp: conexión de datos rechazada (IP distinta)");
      close(fd);
      errno = EACCES;
      return -1;
    }
    io_sock_timeouts(fd, FTP_DATA_TIMEOUT);
  } else {
    errno = ENOTCONN;
    return -1;
  }

  opt = IO_BUFSIZE;
  setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
  env->data_fd = fd;
  return 0;
}


static int
data_printf(ftp_env_t *env, const char *fmt, ...) {
  char buf[PATH_MAX + 256];
  va_list ap;
  va_start(ap, fmt);
  int len = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if(len < 0) return -1;
  if((size_t)len >= sizeof(buf)) len = sizeof(buf) - 1;
  return io_writeall(env->data_fd, buf, (size_t)len);
}


static int
start_data(ftp_env_t *env) {
  if(env->pasv_fd < 0 && !env->use_port) {
    reply(env, "425 Usa PASV/EPSV o PORT primero\r\n");
    return -1;
  }
  if(reply(env, "150 Abriendo conexión de datos\r\n")) return -1;
  if(open_data(env)) {
    reply(env, "425 No se pudo abrir la conexión de datos: %s\r\n", strerror(errno));
    return -1;
  }
  return 0;
}


static int
open_pasv_listener(ftp_env_t *env, uint16_t *port_out) {
  settings_t s;
  struct sockaddr_in a;
  socklen_t alen = sizeof(a);
  int fd;

  cfg_lock();
  memcpy(&s, cfg_settings(), sizeof(s));
  cfg_unlock();

  close_pasv(env);
  env->use_port = 0;

  if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_ANY);

  int bound = 0;
  if(s.pasv_min && s.pasv_max >= s.pasv_min) {
    uint32_t range = (uint32_t)s.pasv_max - s.pasv_min + 1;
    uint32_t start = arc4random() % range;
    for(uint32_t i=0; i<range && !bound; i++) {
      a.sin_port = htons((uint16_t)(s.pasv_min + (start + i) % range));
      if(!bind(fd, (struct sockaddr*)&a, sizeof(a))) bound = 1;
    }
  } else {
    a.sin_port = 0;
    bound = !bind(fd, (struct sockaddr*)&a, sizeof(a));
  }

  if(!bound || listen(fd, 1) || getsockname(fd, (struct sockaddr*)&a, &alen)) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }

  env->pasv_fd = fd;
  *port_out = ntohs(a.sin_port);
  return 0;
}


/* ------------------------------------------------------------------ */
/* Comandos sin autenticación                                          */
/* ------------------------------------------------------------------ */

static int
cmd_USER(ftp_env_t *env, const char *arg) {
  env->logged_in = 0;
  snprintf(env->pending_user, sizeof(env->pending_user), "%s", arg);
  return reply(env, "331 Contraseña requerida\r\n");
}


static int
cmd_PASS(ftp_env_t *env, const char *arg) {
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &env->peer.sin_addr, ip, sizeof(ip));

  if(!env->pending_user[0]) {
    return reply(env, "503 Envía USER primero\r\n");
  }
  if(cfg_authenticate(env->pending_user, arg, &env->user)) {
    env->fails++;
    LOG_PRINTF("ftp: login fallido de '%s' desde %s\n", env->pending_user, ip);
    sleep(2);
    if(env->fails >= FTP_MAX_FAILS) {
      reply(env, "421 Demasiados intentos\r\n");
      return -1;
    }
    return reply(env, "530 Usuario o contraseña incorrectos\r\n");
  }
  if(env->user.must_chpass) {
    LOG_PRINTF("ftp: '%s' debe cambiar su contraseña en la web\n", env->user.name);
    return reply(env, "530 Debes cambiar tu contraseña en la web antes de usar FTP\r\n");
  }
  env->logged_in = 1;
  env->fails = 0;
  strcpy(env->cwd, "/");
  LOG_PRINTF("ftp: '%s' conectado desde %s\n", env->user.name, ip);
  return reply(env, "230 Bienvenido, %s\r\n", env->user.name);
}


static int
cmd_QUIT(ftp_env_t *env, const char *arg) {
  reply(env, "221 Adiós\r\n");
  return -1;
}


static int
cmd_NOOP(ftp_env_t *env, const char *arg) {
  return reply(env, "200 OK\r\n");
}


static int
cmd_SYST(ftp_env_t *env, const char *arg) {
  return reply(env, "215 UNIX Type: L8\r\n");
}


static int
cmd_FEAT(ftp_env_t *env, const char *arg) {
  return reply(env,
               "211-Extensiones:\r\n"
               " EPSV\r\n"
               " MDTM\r\n"
               " MLSD\r\n"
               " REST STREAM\r\n"
               " SIZE\r\n"
               " UTF8\r\n"
               "211 Fin\r\n");
}


static int
cmd_OPTS(ftp_env_t *env, const char *arg) {
  if(!strncasecmp(arg, "UTF8", 4)) return reply(env, "200 UTF8 activado\r\n");
  return reply(env, "501 Opción no soportada\r\n");
}


static int
cmd_unimpl(ftp_env_t *env, const char *arg) {
  return reply(env, "502 Comando no implementado\r\n");
}


/* ------------------------------------------------------------------ */
/* Navegación                                                          */
/* ------------------------------------------------------------------ */

static int
cmd_PWD(ftp_env_t *env, const char *arg) {
  return reply(env, "257 \"%s\" es la carpeta actual\r\n", env->cwd);
}


static int
cmd_CWD(ftp_env_t *env, const char *arg) {
  vfs_res_t r;
  struct stat st;

  if(resolve(env, arg, &r)) return reply_errno(env);
  if(r.mount >= 0) {
    if(stat(r.real, &st)) return reply_errno(env);
    if(!S_ISDIR(st.st_mode)) return reply(env, "550 No es una carpeta\r\n");
  }
  snprintf(env->cwd, sizeof(env->cwd), "%s", r.vpath);
  return reply(env, "250 Carpeta cambiada a \"%s\"\r\n", env->cwd);
}


static int
cmd_CDUP(ftp_env_t *env, const char *arg) {
  return cmd_CWD(env, "..");
}


static int
cmd_TYPE(ftp_env_t *env, const char *arg) {
  char t = arg[0] & ~0x20;
  if(t != 'A' && t != 'I' && t != 'L') return reply(env, "504 Tipo no soportado\r\n");
  env->type = (t == 'A') ? 'A' : 'I';
  return reply(env, "200 Tipo %c\r\n", env->type);
}


static int
cmd_MODE(ftp_env_t *env, const char *arg) {
  return (arg[0] & ~0x20) == 'S' ? reply(env, "200 OK\r\n") : reply(env, "504 Solo modo S\r\n");
}


static int
cmd_STRU(ftp_env_t *env, const char *arg) {
  return (arg[0] & ~0x20) == 'F' ? reply(env, "200 OK\r\n") : reply(env, "504 Solo estructura F\r\n");
}


static int
cmd_ALLO(ftp_env_t *env, const char *arg) {
  return reply(env, "202 No es necesario\r\n");
}


static int
cmd_ABOR(ftp_env_t *env, const char *arg) {
  close_data(env);
  close_pasv(env);
  return reply(env, "226 Abortado\r\n");
}


/* ------------------------------------------------------------------ */
/* Modo pasivo / activo                                                */
/* ------------------------------------------------------------------ */

static int
cmd_PASV(ftp_env_t *env, const char *arg) {
  uint16_t port;
  uint32_t addr = env->local.sin_addr.s_addr;

  if(open_pasv_listener(env, &port)) return reply_errno(env);

  /* Si el control llega por loopback (proxy de Tailscale en la PS5),
     anunciamos la IP configurada (la de Tailscale) en lugar de 127.0.0.1. */
  if((ntohl(addr) >> 24) == 127) {
    struct in_addr ia;
    cfg_lock();
    int ok = cfg_settings()->pasv_address[0] &&
             inet_pton(AF_INET, cfg_settings()->pasv_address, &ia) == 1;
    cfg_unlock();
    if(ok) addr = ia.s_addr;
  }

  uint8_t *a = (uint8_t*)&addr;
  return reply(env, "227 Modo pasivo (%u,%u,%u,%u,%u,%u)\r\n",
               a[0], a[1], a[2], a[3], port >> 8, port & 0xff);
}


static int
cmd_EPSV(ftp_env_t *env, const char *arg) {
  uint16_t port;

  if(!strcasecmp(arg, "ALL")) return reply(env, "200 EPSV ALL aceptado\r\n");
  if(arg[0] && strcmp(arg, "1")) return reply(env, "522 Solo IPv4 (1)\r\n");
  if(open_pasv_listener(env, &port)) return reply_errno(env);
  return reply(env, "229 Modo pasivo extendido (|||%u|)\r\n", port);
}


static int
cmd_PORT(ftp_env_t *env, const char *arg) {
  unsigned a[6];
  uint8_t b[4];

  if(sscanf(arg, "%u,%u,%u,%u,%u,%u", a, a+1, a+2, a+3, a+4, a+5) != 6) {
    return reply(env, "501 Uso: PORT h1,h2,h3,h4,p1,p2\r\n");
  }
  for(int i=0; i<6; i++) if(a[i] > 255) return reply(env, "501 Valor no válido\r\n");
  for(int i=0; i<4; i++) b[i] = (uint8_t)a[i];

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  memcpy(&sa.sin_addr.s_addr, b, 4);
  sa.sin_port = htons((uint16_t)((a[4] << 8) | a[5]));

  /* Evita "FTP bounce": solo a la IP del propio cliente y puertos altos. */
  if(sa.sin_addr.s_addr != env->peer.sin_addr.s_addr || ntohs(sa.sin_port) < 1024) {
    return reply(env, "504 PORT solo hacia tu propia IP\r\n");
  }

  close_pasv(env);
  env->port_addr = sa;
  env->use_port = 1;
  return reply(env, "200 PORT aceptado\r\n");
}


/* ------------------------------------------------------------------ */
/* Listados                                                            */
/* ------------------------------------------------------------------ */

enum { LS_LIST, LS_NLST, LS_MLSD };

static void
emit_entry(ftp_env_t *env, int kind, const char *name, const struct stat *st, int rw) {
  struct tm tm;
  char tbuf[32];
  char mode[11];

  if(kind == LS_NLST) {
    data_printf(env, "%s\r\n", name);
    return;
  }

  gmtime_r(&st->st_mtime, &tm);
  if(kind == LS_MLSD) {
    strftime(tbuf, sizeof(tbuf), "%Y%m%d%H%M%S", &tm);
    int dir = S_ISDIR(st->st_mode);
    data_printf(env, "type=%s;size=%" PRIu64 ";modify=%s;perm=%s; %s\r\n",
                dir ? "dir" : "file", (uint64_t)st->st_size, tbuf,
                dir ? (rw ? "elcmpfd" : "el") : (rw ? "radfw" : "r"), name);
    return;
  }

  time_t now = time(NULL);
  if(now - st->st_mtime > 180L*24*3600 || st->st_mtime > now + 3600) {
    strftime(tbuf, sizeof(tbuf), "%b %d  %Y", &tm);
  } else {
    strftime(tbuf, sizeof(tbuf), "%b %d %H:%M", &tm);
  }
  mode_string(st->st_mode, rw, mode);
  data_printf(env, "%s 1 ps5 ps5 %13" PRIu64 " %s %s\r\n", mode,
              (uint64_t)st->st_size, tbuf, name);
}


static int
do_list(ftp_env_t *env, const char *arg, int kind) {
  vfs_res_t r;
  struct stat st;
  const char *path = "";

  /* Ignora opciones tipo "-la" que mandan algunos clientes. */
  while(*arg == '-') {
    while(*arg && *arg != ' ') arg++;
    while(*arg == ' ') arg++;
  }
  path = arg;

  if(resolve(env, path, &r)) return reply_errno(env);

  if(r.mount < 0) {
    if(start_data(env)) return 0;
    for(int i=0; i<env->user.nmounts; i++) {
      const mount_t *m = &env->user.mounts[i];
      if(stat(m->path, &st)) {
        memset(&st, 0, sizeof(st));
        st.st_mode = S_IFDIR | 0555;
      }
      if(!S_ISDIR(st.st_mode)) continue;
      emit_entry(env, kind, m->name, &st, m->rw);
    }
    close_data(env);
    return reply(env, "226 Listado completo\r\n");
  }

  if(stat(r.real, &st)) return reply_errno(env);

  if(!S_ISDIR(st.st_mode)) {
    /* LIST de un archivo concreto */
    if(start_data(env)) return 0;
    const char *base = strrchr(r.vpath, '/');
    emit_entry(env, kind, base ? base + 1 : r.vpath, &st, r.rw);
    close_data(env);
    return reply(env, "226 Listado completo\r\n");
  }

  DIR *d = opendir(r.real);
  if(!d) return reply_errno(env);
  if(start_data(env)) {
    closedir(d);
    return 0;
  }

  struct dirent *e;
  char full[PATH_MAX * 2];
  while((e = readdir(d))) {
    if(!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
    snprintf(full, sizeof(full), "%s/%s", r.real, e->d_name);
    if(lstat(full, &st)) continue;
    if(S_ISLNK(st.st_mode)) continue;   /* los symlinks no se exponen */
    emit_entry(env, kind, e->d_name, &st, r.rw);
  }
  closedir(d);
  close_data(env);
  return reply(env, "226 Listado completo\r\n");
}


static int cmd_LIST(ftp_env_t *env, const char *arg) { return do_list(env, arg, LS_LIST); }
static int cmd_NLST(ftp_env_t *env, const char *arg) { return do_list(env, arg, LS_NLST); }
static int cmd_MLSD(ftp_env_t *env, const char *arg) { return do_list(env, arg, LS_MLSD); }


static int
cmd_SIZE(ftp_env_t *env, const char *arg) {
  vfs_res_t r;
  struct stat st;
  if(resolve(env, arg, &r)) return reply_errno(env);
  if(r.mount < 0) return reply(env, "550 No es un archivo\r\n");
  if(stat(r.real, &st)) return reply_errno(env);
  if(!S_ISREG(st.st_mode)) return reply(env, "550 No es un archivo\r\n");
  return reply(env, "213 %" PRIu64 "\r\n", (uint64_t)st.st_size);
}


static int
cmd_MDTM(ftp_env_t *env, const char *arg) {
  vfs_res_t r;
  struct stat st;
  struct tm tm;
  char tbuf[32];
  if(resolve(env, arg, &r)) return reply_errno(env);
  if(r.mount < 0) return reply(env, "550 No es un archivo\r\n");
  if(stat(r.real, &st)) return reply_errno(env);
  gmtime_r(&st.st_mtime, &tm);
  strftime(tbuf, sizeof(tbuf), "%Y%m%d%H%M%S", &tm);
  return reply(env, "213 %s\r\n", tbuf);
}


/* ------------------------------------------------------------------ */
/* Transferencias                                                      */
/* ------------------------------------------------------------------ */

static int
cmd_REST(ftp_env_t *env, const char *arg) {
  long long v = atoll(arg);
  if(v < 0) return reply(env, "501 Offset no válido\r\n");
  env->rest = (off_t)v;
  return reply(env, "350 Reanudando desde %lld\r\n", v);
}


static int
cmd_RETR(ftp_env_t *env, const char *arg) {
  vfs_res_t r;
  struct stat st;
  off_t off = env->rest;
  int fd;

  env->rest = 0;
  if(resolve(env, arg, &r)) return reply_errno(env);
  if(r.mount < 0) return reply(env, "550 No es un archivo\r\n");
  if((fd = open(r.real, O_RDONLY)) < 0) return reply_errno(env);
  if(fstat(fd, &st) || !S_ISREG(st.st_mode)) {
    close(fd);
    return reply(env, "550 No es un archivo\r\n");
  }
  if(off > st.st_size) off = st.st_size;
  if(lseek(fd, off, SEEK_SET) < 0) {
    int e = reply_errno(env);
    close(fd);
    return e;
  }
  if(start_data(env)) {
    close(fd);
    return 0;
  }

  int err = io_copy(fd, env->data_fd, (size_t)(st.st_size - off), env->buf, IO_BUFSIZE);
  close(fd);
  close_data(env);
  if(err) return reply(env, "426 Transferencia interrumpida\r\n");
  return reply(env, "226 Transferencia completa\r\n");
}


static int
do_store(ftp_env_t *env, const char *arg, int append) {
  vfs_res_t r;
  off_t off = env->rest;
  int fd, flags = O_WRONLY | O_CREAT;

  env->rest = 0;
  if(!arg[0]) return reply(env, "501 Falta el nombre\r\n");
  if(resolve(env, arg, &r)) return reply_errno(env);
  if(r.mount < 0 || r.is_mount_root || !r.rw) return deny(env);

  if(append) flags |= O_APPEND;
  else if(!off) flags |= O_TRUNC;

  if((fd = open(r.real, flags, 0666)) < 0) return reply_errno(env);
  if(!append && off && lseek(fd, off, SEEK_SET) < 0) {
    int e = reply_errno(env);
    close(fd);
    return e;
  }
  if(start_data(env)) {
    close(fd);
    return 0;
  }

  int err = 0;
  for(;;) {
    ssize_t n = recv(env->data_fd, env->buf, IO_BUFSIZE, 0);
    if(n < 0 && errno == EINTR) continue;
    if(n < 0) { err = errno; break; }
    if(n == 0) break;
    if(io_writeall(fd, env->buf, (size_t)n)) { err = errno; break; }
  }
  if(!err && !append && off) {
    off_t end = lseek(fd, 0, SEEK_CUR);
    if(end >= 0 && ftruncate(fd, end)) err = errno;
  }
  close(fd);
  close_data(env);

  if(err == ENOSPC) return reply(env, "452 Sin espacio en el disco\r\n");
  if(err) return reply(env, "426 Transferencia interrumpida: %s\r\n", strerror(err));
  return reply(env, "226 Archivo recibido\r\n");
}


static int cmd_STOR(ftp_env_t *env, const char *arg) { return do_store(env, arg, 0); }
static int cmd_APPE(ftp_env_t *env, const char *arg) { return do_store(env, arg, 1); }


/* ------------------------------------------------------------------ */
/* Modificaciones                                                      */
/* ------------------------------------------------------------------ */

static int
cmd_DELE(ftp_env_t *env, const char *arg) {
  vfs_res_t r;
  struct stat st;
  if(resolve(env, arg, &r)) return reply_errno(env);
  if(r.mount < 0 || r.is_mount_root || !r.rw) return deny(env);
  if(lstat(r.real, &st)) return reply_errno(env);
  if(S_ISDIR(st.st_mode)) return reply(env, "550 Es una carpeta (usa RMD)\r\n");
  if(unlink(r.real)) return reply_errno(env);
  return reply(env, "250 Archivo borrado\r\n");
}


static int
cmd_MKD(ftp_env_t *env, const char *arg) {
  vfs_res_t r;
  if(!arg[0]) return reply(env, "501 Falta el nombre\r\n");
  if(resolve(env, arg, &r)) return reply_errno(env);
  if(r.mount < 0 || r.is_mount_root || !r.rw) return deny(env);
  if(mkdir(r.real, 0777)) return reply_errno(env);
  return reply(env, "257 \"%s\" creada\r\n", r.vpath);
}


static int
cmd_RMD(ftp_env_t *env, const char *arg) {
  vfs_res_t r;
  if(resolve(env, arg, &r)) return reply_errno(env);
  if(r.mount < 0 || r.is_mount_root || !r.rw) return deny(env);
  if(rmdir(r.real)) return reply_errno(env);
  return reply(env, "250 Carpeta borrada\r\n");
}


static int
cmd_RNFR(ftp_env_t *env, const char *arg) {
  vfs_res_t r;
  struct stat st;
  env->has_rnfr = 0;
  if(resolve(env, arg, &r)) return reply_errno(env);
  if(r.mount < 0 || r.is_mount_root || !r.rw) return deny(env);
  if(lstat(r.real, &st)) return reply_errno(env);
  snprintf(env->rnfr, sizeof(env->rnfr), "%s", r.vpath);
  env->has_rnfr = 1;
  return reply(env, "350 Esperando el nuevo nombre\r\n");
}


static int
cmd_RNTO(ftp_env_t *env, const char *arg) {
  vfs_res_t from, to;
  if(!env->has_rnfr) return reply(env, "503 Envía RNFR primero\r\n");
  env->has_rnfr = 0;
  if(vfs_resolve(&env->user, env->rnfr, &from)) return reply_errno(env);
  if(resolve(env, arg, &to)) return reply_errno(env);
  if(to.mount < 0 || to.is_mount_root || !to.rw || from.mount != to.mount || !from.rw) {
    return deny(env);
  }
  if(rename(from.real, to.real)) return reply_errno(env);
  return reply(env, "250 Renombrado\r\n");
}


/* ------------------------------------------------------------------ */
/* Despacho                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
  const char *name;
  ftp_fn_t   *fn;
  int         noauth;   /* permitido antes de iniciar sesión */
  int         needarg;
} ftp_cmd_t;


static const ftp_cmd_t commands[] = {
  {"USER", cmd_USER, 1, 1}, {"PASS", cmd_PASS, 1, 0},
  {"QUIT", cmd_QUIT, 1, 0}, {"NOOP", cmd_NOOP, 1, 0},
  {"SYST", cmd_SYST, 1, 0}, {"FEAT", cmd_FEAT, 1, 0},
  {"OPTS", cmd_OPTS, 1, 1}, {"AUTH", cmd_unimpl, 1, 0},
  {"PBSZ", cmd_unimpl, 1, 0}, {"PROT", cmd_unimpl, 1, 0},
  {"CLNT", cmd_NOOP, 1, 0},

  {"PWD",  cmd_PWD, 0, 0},  {"XPWD", cmd_PWD, 0, 0},
  {"CWD",  cmd_CWD, 0, 1},  {"XCWD", cmd_CWD, 0, 1},
  {"CDUP", cmd_CDUP, 0, 0}, {"XCUP", cmd_CDUP, 0, 0},
  {"TYPE", cmd_TYPE, 0, 1}, {"MODE", cmd_MODE, 0, 1},
  {"STRU", cmd_STRU, 0, 1}, {"ALLO", cmd_ALLO, 0, 0},
  {"ABOR", cmd_ABOR, 0, 0},
  {"PASV", cmd_PASV, 0, 0}, {"EPSV", cmd_EPSV, 0, 0},
  {"PORT", cmd_PORT, 0, 1}, {"EPRT", cmd_unimpl, 0, 0},
  {"LIST", cmd_LIST, 0, 0}, {"NLST", cmd_NLST, 0, 0},
  {"MLSD", cmd_MLSD, 0, 0},
  {"SIZE", cmd_SIZE, 0, 1}, {"MDTM", cmd_MDTM, 0, 1},
  {"REST", cmd_REST, 0, 1}, {"RETR", cmd_RETR, 0, 1},
  {"STOR", cmd_STOR, 0, 1}, {"APPE", cmd_APPE, 0, 1},
  {"DELE", cmd_DELE, 0, 1},
  {"MKD",  cmd_MKD, 0, 1},  {"XMKD", cmd_MKD, 0, 1},
  {"RMD",  cmd_RMD, 0, 1},  {"XRMD", cmd_RMD, 0, 1},
  {"RNFR", cmd_RNFR, 0, 1}, {"RNTO", cmd_RNTO, 0, 1},
};


static int
dispatch(ftp_env_t *env, char *line) {
  char *arg = strchr(line, ' ');
  if(arg) {
    *arg++ = 0;
  } else {
    arg = line + strlen(line);
  }

  for(size_t i=0; i<sizeof(commands)/sizeof(commands[0]); i++) {
    const ftp_cmd_t *c = &commands[i];
    if(strcasecmp(line, c->name)) continue;

    if(!c->noauth) {
      if(!env->logged_in) return reply(env, "530 Inicia sesión primero\r\n");
      /* Recarga el usuario: los cambios de la web se aplican al momento. */
      user_t fresh;
      if(cfg_get_user(env->user.name, &fresh) || !fresh.enabled) {
        reply(env, "421 Tu cuenta ha sido desactivada\r\n");
        return -1;
      }
      memcpy(&env->user, &fresh, sizeof(fresh));
    }
    if(c->needarg && !arg[0]) return reply(env, "501 Falta el argumento\r\n");
    return c->fn(env, arg);
  }

  return reply(env, "502 Comando desconocido\r\n");
}


static void*
client_thread(void *p) {
  ftp_env_t *env = p;

  io_sock_timeouts(env->ctrl_fd, FTP_IDLE_TIMEOUT);
  setsockopt(env->ctrl_fd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));

  if(!reply(env, "220 ps5share %s listo\r\n", VERSION_TAG)) {
    while(!readline(env)) {
      if(dispatch(env, env->line)) break;
    }
  }

  close_data(env);
  close_pasv(env);
  close(env->ctrl_fd);
  free(env->buf);
  free(env);

  pthread_mutex_lock(&g_nclients_lock);
  g_nclients--;
  pthread_mutex_unlock(&g_nclients_lock);
  return NULL;
}


int
ftp_serve(uint16_t port) {
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

  if(bind(srv, (struct sockaddr*)&sa, sizeof(sa)) || listen(srv, 16)) {
    LOG_PERROR("ftp bind/listen");
    close(srv);
    return -1;
  }
  LOG_PRINTF("ps5share: FTP escuchando en el puerto %u\n", port);

  for(;;) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int fd = accept(srv, (struct sockaddr*)&peer, &plen);
    if(fd < 0) {
      if(errno == EINTR || errno == ECONNABORTED) continue;
      LOG_PERROR("ftp accept");
      break;
    }

    pthread_mutex_lock(&g_nclients_lock);
    int full = g_nclients >= FTP_MAX_CLIENTS;
    if(!full) g_nclients++;
    pthread_mutex_unlock(&g_nclients_lock);
    if(full) {
      static const char msg[] = "421 Demasiadas conexiones\r\n";
      if(write(fd, msg, sizeof(msg) - 1) < 0) {}
      close(fd);
      continue;
    }

    ftp_env_t *env = calloc(1, sizeof(*env));
    void *buf = malloc(IO_BUFSIZE);
    if(!env || !buf) {
      free(env);
      free(buf);
      close(fd);
      pthread_mutex_lock(&g_nclients_lock);
      g_nclients--;
      pthread_mutex_unlock(&g_nclients_lock);
      continue;
    }
    env->ctrl_fd = fd;
    env->data_fd = -1;
    env->pasv_fd = -1;
    env->type = 'I';
    env->buf = buf;
    env->peer = peer;
    strcpy(env->cwd, "/");
    socklen_t llen = sizeof(env->local);
    getsockname(fd, (struct sockaddr*)&env->local, &llen);

    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 1024 * 1024);
    if(pthread_create(&t, &attr, client_thread, env)) {
      close(fd);
      free(buf);
      free(env);
      pthread_mutex_lock(&g_nclients_lock);
      g_nclients--;
      pthread_mutex_unlock(&g_nclients_lock);
    }
    pthread_attr_destroy(&attr);
  }

  close(srv);
  return -1;
}
