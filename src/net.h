/* ps5share - conexiones salientes (DNS, TLS y cliente HTTPS)
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Lo usan el correo (smtp.c) y la integración con Spotify (spotify.c).
   Todo el tráfico va cifrado con wolfSSL y se verifica el certificado del
   servidor contra las CA raíz de cacerts.h (más CONFDIR/ca-extra.pem, si
   existe, por si un servicio cambia de CA antes de actualizar PS5NAS). */

#pragma once

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

/* Resuelve HOST (getaddrinfo y, si falla en la consola, DNS propio). */
int net_resolve(const char *host, struct in_addr *out);

/* Conecta por TCP a HOST:PORT con TIMEOUT segundos de espera.
   Devuelve el socket o -1 con un mensaje en ERR. */
int net_connect(const char *host, uint16_t port, int timeout, char *err, size_t errlen);

/* Inicia TLS sobre *FDP (verificando que el certificado es de HOST).
   FDP debe seguir siendo válido mientras dure la conexión. */
int net_tls_start(int *fdp, const char *host, WOLFSSL_CTX **ctx, WOLFSSL **ssl,
                  char *err, size_t errlen);
void net_tls_close(WOLFSSL_CTX *ctx, WOLFSSL *ssl);


/* Respuesta HTTP completa en memoria. */
typedef struct https_resp {
  int    status;
  int    retry_after;      /* segundos (cabecera Retry-After), 0 si no hay */
  char  *body;             /* terminado en \0 */
  size_t len;
} https_resp_t;

#define HTTPS_BODY_MAX (8 * 1024 * 1024)

/* Petición HTTPS.  URL: https://host[:puerto]/ruta?consulta
   HEADERS: líneas extra terminadas en \r\n (o NULL).
   Devuelve 0 si hubo respuesta (cualquier código) o -1 con ERR. */
int  https_request(const char *method, const char *url, const char *headers,
                   const char *body, size_t body_len, https_resp_t *out,
                   char *err, size_t errlen);
void https_resp_free(https_resp_t *r);

/* Codifica S para usar en una URL o en un formulario. */
void net_urlencode(const char *s, char *out, size_t outlen);
