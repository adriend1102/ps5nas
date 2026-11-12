/* ps5share - pestaña «Contraseñas» de la web de PS5NAS
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#pragma once

#include "httpd.h"

int h_pw_info(req_t *r);
int h_pw_items(req_t *r);
int h_pw_save(req_t *r);
int h_pw_delete(req_t *r);
int h_pw_restore(req_t *r);
int h_pw_folder(req_t *r);
int h_pw_folder_delete(req_t *r);
int h_pw_import(req_t *r);
int h_pw_export(req_t *r);
int h_pw_ca(req_t *r);             /* GET /ps5nas-ca.crt (público) */
int h_admin_tls_regen(req_t *r);   /* POST /api/admin/tls (administrador) */
