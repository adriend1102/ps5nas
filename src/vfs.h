/* ps5share - sistema de archivos virtual por usuario
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Cada usuario ve una raíz virtual "/" que contiene únicamente sus carpetas
   asignadas ("montajes").  "/Peliculas/a.mkv" se traduce a
   "<ruta real del montaje Peliculas>/a.mkv".  No se puede salir de un
   montaje con ".." ni a través de enlaces simbólicos.  */

#pragma once

#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "crypt.h"


typedef struct vfs_res {
  int  mount;               /* índice del montaje, -1 si es la raíz virtual */
  int  rw;                  /* el montaje permite escritura */
  int  is_mount_root;       /* la ruta es exactamente la raíz de un montaje */
  int  enc;                 /* dentro de una carpeta privada cifrada */
  const ukey_t *key;        /* clave del usuario (si enc) */
  char vpath[PATH_MAX];     /* ruta virtual normalizada, empieza por '/' */
  char real[PATH_MAX];      /* ruta real (vacía si mount == -1) */
} vfs_res_t;


/* Combina CWD (virtual) y PATH y normaliza "." y "..".  Nunca sube de "/". */
void vfs_normalize(const char *cwd, const char *path, char *out, size_t outlen);

/* Resuelve una ruta virtual normalizada.  KEY es la clave del usuario o
   NULL (sin ella las carpetas cifradas dan EACCES).  Devuelve 0 o -1 con
   errno (ENOENT si el montaje no existe, EACCES si se cruza un symlink o la
   carpeta está cifrada y no hay clave, ENAMETOOLONG si un nombre no cabe
   cifrado). */
int  vfs_resolve(const user_t *u, const ukey_t *key, const char *vabs, vfs_res_t *r);

/* Atajo: normaliza y resuelve. */
int  vfs_lookup(const user_t *u, const ukey_t *key, const char *cwd, const char *path,
                vfs_res_t *r);

/* ¿Puede usarse el montaje I con esta clave? */
int  vfs_mount_usable(const user_t *u, const ukey_t *key, int i);

/* Traduce el nombre en disco de una entrada de DIR (resuelto en R) al que
   ve el usuario.  Devuelve 0 si debe mostrarse. */
int  vfs_entry_name(const vfs_res_t *dir, const char *disk_name, char *out, size_t outlen);

/* stat/lstat de la ruta resuelta, con el tamaño en claro si está cifrada. */
int  vfs_stat(const vfs_res_t *r, struct stat *st);
/* Ajusta el tamaño de una entrada leída con lstat dentro de DIR. */
void vfs_fix_size(const vfs_res_t *dir, struct stat *st);


/* Archivo abierto (normal o cifrado). */
typedef struct vfile {
  int     fd;
  int     enc;
  int     append;
  cfile_t cf;
} vfile_t;

/* FLAGS como open(2) (O_RDONLY/O_WRONLY/O_RDWR, O_CREAT, O_TRUNC, O_EXCL,
   O_APPEND). */
int     vf_open(vfile_t *f, const vfs_res_t *r, int flags);
ssize_t vf_pread(vfile_t *f, void *buf, size_t len, off_t off);
ssize_t vf_pwrite(vfile_t *f, const void *buf, size_t len, off_t off);
off_t   vf_size(vfile_t *f);
int     vf_close(vfile_t *f);
