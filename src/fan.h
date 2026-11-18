/* ps5share - vigilancia de temperatura y control del ventilador
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   El ventilador se controla igual que Breeze (MiladRTX/Breeze, GPLv3):
   /dev/icc_fan, objeto «autoservo» del canal 0, cuyo objetivo de
   temperatura decide cuándo acelera la consola.  Bajar el objetivo hace
   que el ventilador gire antes y más rápido; nunca se escribe por encima
   del valor de la consola ni por debajo de FAN_LOWEST_C.  Los modos son los
   de Machete IA (Silencioso, Equilibrado, Frío y Manual).  */

#pragma once

#include <stddef.h>

#define FAN_LOWEST_C 70   /* ningún modo baja de aquí */
#define FAN_TOP_C    95   /* tope del modo manual */
#define FAN_HOT_C    85   /* aviso en la consola a partir de aquí */

enum {
  FAN_MODE_QUIET    = 0,   /* el de la consola (no se toca) */
  FAN_MODE_BALANCED = 1,   /* 3 °C por debajo del de la consola */
  FAN_MODE_COOL     = 2,   /* 6 °C por debajo */
  FAN_MODE_MANUAL   = 3,   /* el que se elija (70-95, nunca por encima del de la consola) */
};

/* Carga fan.conf de CONFDIR y arranca el hilo de vigilancia. */
void  fan_init(const char *confdir);

/* Estado e historial en JSON (malloc; el que llama lo libera). */
char *fan_status_json(void);

/* "quiet", "balanced", "cool", "manual" -> modo; -1 si no. */
int   fan_mode_from(const char *s);

/* Cambia los ajustes (valores < 0: no cambiar).  0 bien, -1 con ERR. */
int   fan_configure(int mode, int manual_c, int notify_on, char *err, size_t errlen);
