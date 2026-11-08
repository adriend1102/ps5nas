/* ps5share - IP de Tailscale de la consola.  GPLv3, ver LICENSE. */
#pragma once
#include <stddef.h>

/* Escribe en OUT la IP 100.x.y.z de la consola, o "" si no se encuentra. */
void tsip_get(char *out, size_t outlen);
