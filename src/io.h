/* ps5share - utilidades de E/S
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#pragma once

#include <stddef.h>
#include <sys/types.h>

#define IO_BUFSIZE 0x100000

/* Escribe exactamente N bytes (reintenta escrituras parciales). */
int io_writeall(int fd, const void *buf, size_t n);

/* Copia hasta N bytes de FD_IN a FD_OUT usando BUF de tamaño BUFLEN.
   Si N es (size_t)-1 copia hasta EOF.  Devuelve 0 o -1. */
int io_copy(int fd_in, int fd_out, size_t n, void *buf, size_t buflen);

/* Espera a que FD sea legible durante TIMEOUT_MS.  1 listo, 0 timeout, -1 error. */
int io_wait_readable(int fd, int timeout_ms);

/* Pone timeouts de envío/recepción a un socket. */
void io_sock_timeouts(int fd, int seconds);
