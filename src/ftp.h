/* ps5share - servidor FTP multiusuario
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#pragma once

#include <stdint.h>

/* Bucle principal del servidor FTP (no retorna salvo error). */
int ftp_serve(uint16_t port);
