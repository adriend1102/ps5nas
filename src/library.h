/* ps5share - biblioteca de música de las playlists de Spotify
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Organización en la carpeta de música (por defecto /mnt/usb0/Adrian/Spotify):

     Artista - Título.flac        todas las canciones, en la raíz
     Entrada/                     deja aquí archivos nuevos (por SFTP o la web):
                                  se leen sus etiquetas, se renombran y se
                                  mueven a la raíz
     Entrada/_duplicados/         los que ya estaban
     Listas/2026-11 Noviembre 2026.m3u8
                                  una lista por playlist mensual, con rutas
                                  relativas; las que faltan van comentadas
     Listas/Faltan.txt            canciones de las playlists sin archivo  */

#pragma once

#include <stddef.h>

typedef struct lib_track {
  int  ym;                 /* año*12 + (mes-1) */
  char added_at[24];       /* 2026-11-03T18:22:10Z */
  char uri[64];            /* spotify:track:... */
  char artist[160];        /* artistas separados por ", " */
  char title[200];
  char album[200];
  int  duration_ms;
} lib_track_t;

typedef struct lib_month {
  int  ym;
  int  total;
  int  have;
} lib_month_t;

/* Mueve lo que haya en DIR/Entrada a DIR.  Devuelve cuántos archivos movió. */
int  lib_ingest(const char *dir);

/* Escribe DIR/Listas/ (un .m3u8 por mes) y Faltan.txt para las canciones TRACKS (en
   orden de añadido) y rellena MONTHS (NMONTHS entradas, ya con ym) con
   cuántas hay y cuántas tienen archivo.  Devuelve 0 o -1 si DIR no existe. */
int  lib_build(const char *dir, const lib_track_t *tracks, int ntracks,
               lib_month_t *months, int nmonths);

/* Nombre del mes en español (1-12). */
const char *lib_month_name(int month);

/* Para pruebas: clave normalizada de búsqueda de "ARTISTA" + "TÍTULO". */
void lib_key(const char *artist, const char *title, int strip, char *out, size_t outlen);
