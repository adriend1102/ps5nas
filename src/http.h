/* ps5share - servidor web
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#pragma once

#include <stdint.h>

/* Bucle principal del servidor web (no retorna salvo error). */
int http_serve(uint16_t port);
/* Servidor HTTPS (hilo propio; nunca retorna). */
int http_serve_tls(void);
/* Clave compartida con los módulos de la consola (CONFDIR/module.key). */
void http_module_key_init(const char *confdir);
