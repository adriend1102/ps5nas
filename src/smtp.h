/* ps5share - envío de correos.  GPLv3, ver LICENSE. */
#pragma once
#include <stddef.h>

/* Envía un correo de texto (UTF-8) con la cuenta configurada en Ajustes.
   Devuelve 0, o -1 con un mensaje en ERR.  Bloquea unos segundos. */
int smtp_send(const char *to, const char *subject, const char *body, char *err, size_t errlen);
