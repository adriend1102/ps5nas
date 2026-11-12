/* ps5share - HTTPS con certificado propio de la consola
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   La primera vez se crea una autoridad de certificación (CA) propia de esta
   PS5 (ECDSA P-256, 10 años) que el usuario instala una vez en cada móvil u
   ordenador.  Con ella se firma el certificado del servidor, que lleva todas
   las direcciones por las que se puede llegar a la consola (IP de casa, IP
   de Tailscale, 127.0.0.1 y los nombres que se configuren).  Si cambian las
   IPs se vuelve a emitir solo, sin tener que reinstalar nada.  */

#pragma once

#include <stddef.h>

/* Prepara la CA y el certificado del servidor (los crea si hace falta). */
int   tls_init(const char *confdir);

/* Revisa si cambiaron las direcciones (o caduca pronto) y reemite el
   certificado del servidor.  Devuelve 1 si lo reemitió. */
int   tls_refresh(int force);

/* Vuelve a crear la CA (hay que reinstalarla en los dispositivos). */
int   tls_regenerate_ca(void);

/* Conexión TLS de servidor sobre FD (ya aceptado).  NULL si falla. */
void *tls_accept(int fd);
long  tls_recv(void *ssl, void *buf, size_t n);
int   tls_writeall(void *ssl, const void *buf, size_t n);
void  tls_close(void *ssl);

/* Certificado de la CA en PEM (copia en OUT).  Devuelve la longitud o -1. */
long  tls_ca_pem(char *out, size_t outlen);
/* Huella SHA-256 de la CA, "AB:CD:...". */
void  tls_ca_fingerprint(char *out, size_t outlen);
/* Nombres y direcciones del certificado actual, separados por espacios. */
void  tls_cert_names(char *out, size_t outlen);
/* Caducidad del certificado del servidor (epoch) o 0. */
long long tls_cert_expires(void);
