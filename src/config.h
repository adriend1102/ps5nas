/* ps5share - servidor de archivos multiusuario para PS5
   Copyright (C) 2026  ps5share contributors
   Basado en ftpsrv (C) 2023-2025 John Törnblom.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.  See LICENSE.  */

#pragma once

#include <limits.h>
#include <pthread.h>
#include <stdint.h>

#define CFG_MAX_USERS   64
#define CFG_MAX_MOUNTS  16
#define CFG_NAME_MAX    48
#define CFG_SALT_HEX    32   /* 16 bytes */
#define CFG_HASH_HEX    64   /* 32 bytes */
#define CFG_PBKDF2_ITER 20000


typedef struct mount {
  char name[CFG_NAME_MAX+1];  /* nombre de la carpeta virtual que ve el usuario */
  char path[PATH_MAX];        /* ruta real en la PS5 */
  int  rw;                    /* 0 = solo lectura, 1 = lectura/escritura */
} mount_t;


typedef struct user {
  char name[CFG_NAME_MAX+1];
  char salt[CFG_SALT_HEX+1];
  char hash[CFG_HASH_HEX+1];
  int  admin;
  int  enabled;
  int  nmounts;
  mount_t mounts[CFG_MAX_MOUNTS];
} user_t;


typedef struct settings {
  uint16_t ftp_port;
  uint16_t http_port;
  uint16_t pasv_min;
  uint16_t pasv_max;
  char     pasv_address[64];  /* IP a anunciar en PASV cuando el control llega por loopback (Tailscale) */
  uint16_t sftp_port;
  int      sftp_enabled;
  int      ftp_enabled;       /* FTP sin cifrar: desactivado por defecto */
} settings_t;


/* Inicializa la configuración leyendo DIR/users.conf (lo crea si no existe). */
int  cfg_init(const char *dir);

/* Guarda la configuración actual en disco (atómico). Llamar con el lock. */
int  cfg_save_locked(void);

void cfg_lock(void);
void cfg_unlock(void);

/* Acceso a datos globales (usar con el lock). */
settings_t *cfg_settings(void);
int         cfg_nusers(void);
user_t     *cfg_user_at(int idx);
user_t     *cfg_find_user_locked(const char *name);

/* Copia segura de un usuario (sin necesidad de lock por fuera). */
int  cfg_get_user(const char *name, user_t *out);

/* Comprueba usuario y contraseña. Devuelve 0 y rellena OUT si son válidos. */
int  cfg_authenticate(const char *name, const char *pass, user_t *out);

/* Rellena salt+hash de U con una contraseña nueva. */
void cfg_set_password(user_t *u, const char *pass);

/* Alta/edición/baja (con el lock tomado por dentro). Devuelven 0 o -1 con msg. */
int  cfg_upsert_user(const user_t *u, const char *newpass, char *err, size_t errlen);
int  cfg_delete_user(const char *name, char *err, size_t errlen);
int  cfg_update_settings(const settings_t *s, char *err, size_t errlen);

/* Validaciones de nombres. */
int  cfg_valid_username(const char *s);
int  cfg_valid_mountname(const char *s);

/* Utilidades de aleatoriedad / tiempo constante. */
void cfg_random_hex(char *out, size_t nbytes);
int  ps5share_rand_seed(unsigned char *out, unsigned int sz);   /* para wolfCrypt */
int  cfg_consttime_eq(const char *a, const char *b);
