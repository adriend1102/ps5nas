/* ps5share - servidor SFTP
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#pragma once

#include <stdint.h>

/* Prepara wolfSSH y carga (o genera) las claves del servidor en CONFDIR. */
int sftp_init(const char *confdir);

/* Bucle principal del servidor SFTP (no retorna salvo error). */
int sftp_serve(uint16_t port);

/* Huellas "SHA256:..." de las claves del servidor ("" si no hay). */
const char *sftp_fingerprint_ecdsa(void);
const char *sftp_fingerprint_rsa(void);
