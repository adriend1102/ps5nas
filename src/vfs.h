/* ps5share - sistema de archivos virtual por usuario
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Cada usuario ve una raíz virtual "/" que contiene únicamente sus carpetas
   asignadas ("montajes").  "/Peliculas/a.mkv" se traduce a
   "<ruta real del montaje Peliculas>/a.mkv".  No se puede salir de un
   montaje con ".." ni a través de enlaces simbólicos.  */

#pragma once

#include <limits.h>
#include "config.h"


typedef struct vfs_res {
  int  mount;               /* índice del montaje, -1 si es la raíz virtual */
  int  rw;                  /* el montaje permite escritura */
  int  is_mount_root;       /* la ruta es exactamente la raíz de un montaje */
  char vpath[PATH_MAX];     /* ruta virtual normalizada, empieza por '/' */
  char real[PATH_MAX];      /* ruta real (vacía si mount == -1) */
} vfs_res_t;


/* Combina CWD (virtual) y PATH y normaliza "." y "..".  Nunca sube de "/". */
void vfs_normalize(const char *cwd, const char *path, char *out, size_t outlen);

/* Resuelve una ruta virtual normalizada.  Devuelve 0 o -1 con errno
   (ENOENT si el montaje no existe, EACCES si se cruza un symlink). */
int  vfs_resolve(const user_t *u, const char *vabs, vfs_res_t *r);

/* Atajo: normaliza y resuelve. */
int  vfs_lookup(const user_t *u, const char *cwd, const char *path, vfs_res_t *r);
