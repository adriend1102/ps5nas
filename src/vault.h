/* ps5share - gestor de contraseñas compatible con Bitwarden
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Cada usuario de PS5NAS con el gestor activado tiene una «bóveda» en
   VAULT_DIR/<usuario>.json.  Su contenido lo cifran los propios clientes
   (apps, extensión y escritorio de Bitwarden) con la clave del usuario, así
   que en el disco solo hay datos cifrados.  La contraseña es la misma que la
   de PS5NAS: al crear o cambiar la contraseña, la consola vuelve a proteger
   la clave de la bóveda con la nueva.  Una copia de esa clave va sellada con
   la clave maestra de la consola para que la web de PS5NAS pueda mostrar y
   editar las contraseñas sin pedirla otra vez.  */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <cJSON.h>

#include "httpd.h"

void  vault_init(const char *confdir);

/* API de Bitwarden (/api/..., /identity/..., /notifications/..., /icons/...).
   Devuelve 1 si la ruta es suya (y ya respondió), 0 si no. */
int   vault_handle(req_t *r);

/* Gestión de cuentas (las llama el servidor web). */
int   vault_ensure(const char *user, const char *password);      /* crea si falta */
int   vault_ensure_stored(const char *user);                     /* con la guardada */
void  vault_password_changed(const char *user, const char *newpass);
void  vault_user_deleted(const char *user);
int   vault_has_account(const char *user);
/* Igual, con la carpeta ya resuelta (se puede llamar con cfg_lock tomado). */
int   vault_has_account_in(const char *dir, const char *user);
void  vault_login_email(const char *user, char *out, size_t outlen);
int   vault_count_items(const char *user);
/* Mueve las bóvedas a otra carpeta.  0 o -1 con mensaje. */
int   vault_move_dir(const char *from, const char *to, char *err, size_t errlen);

/* Acceso desde la web de PS5NAS (vaultweb.c).  Con vault_lock tomado. */
void   vault_lock(void);
void   vault_unlock(void);
cJSON *vault_load(const char *user);
int    vault_save(const char *user, cJSON *v);
int    vault_user_key(const cJSON *v, const char *user, uint8_t key[64]);
void   vault_touch(cJSON *v);           /* marca la bóveda como modificada */
cJSON *vault_find_id(cJSON *arr, const char *id);
