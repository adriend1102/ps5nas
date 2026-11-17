/* ps5share - vigilancia de temperatura y control del ventilador
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   El ventilador se controla igual que Breeze (MiladRTX/Breeze, GPLv3):
   /dev/icc_fan, objeto «autoservo» del canal 0, cuyo objetivo de
   temperatura decide cuándo acelera la consola.  Bajar el objetivo hace
   que el ventilador gire antes y más rápido; nunca se escribe por encima
   del valor de fábrica (91 °C) ni por debajo de FAN_MIN_C.  */

#pragma once

#include <stddef.h>

#define FAN_MIN_C 50
#define FAN_MAX_C 91

enum {
  FAN_MODE_WATCH   = 0,   /* solo vigilar (no toca el ventilador) */
  FAN_MODE_PROTECT = 1,   /* actuar solo si se calienta */
  FAN_MODE_FIXED   = 2,   /* mantener un objetivo fijo */
};

/* Carga fan.conf de CONFDIR y arranca el hilo de vigilancia. */
void  fan_init(const char *confdir);

/* Estado e historial en JSON (malloc; el que llama lo libera). */
char *fan_status_json(void);

/* Cambia los ajustes (valores < 0: no cambiar).  0 bien, -1 con ERR. */
int   fan_configure(int mode, int trip_c, int cool_c, int fixed_c, int notify_on,
                    char *err, size_t errlen);
