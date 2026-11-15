/* ps5share - playlists mensuales de Spotify
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Cada cierto tiempo (por defecto cada hora) lee las canciones de «Me gusta»
   y mantiene una playlist por mes («pl 11/2026») con las que se añadieron
   ese mes.  Adopta las playlists con ese nombre que ya existan (las del
   script antiguo) y solo añade lo que falta: nunca borra nada.

   Inicio de sesión: OAuth 2.0 con PKCE (sin secreto de cliente en la
   consola).  Como Spotify solo admite http://127.0.0.1 como dirección de
   vuelta, el usuario copia la dirección a la que le lleva el navegador y la
   pega en el panel.  El token de refresco se guarda cifrado con la clave
   maestra de la consola.

   Además, «top M/AAAA»: las canciones más escuchadas de cada mes, contadas
   con el historial de escuchas (se consulta cada 20 minutos) y completadas
   con el top de ~4 semanas de Spotify.  */

#pragma once

#include <stddef.h>

#define SPOTIFY_REDIRECT_URI "http://127.0.0.1:8888/callback"
#define SPOTIFY_DEFAULT_DIR  "/mnt/usb0/Adrian/Spotify"

/* Carga CONFDIR/spotify.conf y arranca el hilo de sincronización. */
int   spotify_init(const char *confdir);

/* Estado en JSON (malloc, liberar con free). */
char *spotify_status_json(void);

/* Cambia ajustes.  Los punteros NULL / valores < 0 no se tocan.
   START: "AAAA-MM".  Devuelve 0 o -1 con ERR. */
int   spotify_configure(const char *client_id, const char *start, const char *music_dir,
                        int interval_h, int enabled, int top_enabled, int top_size,
                        char *err, size_t errlen);

/* Prepara un inicio de sesión y escribe la URL de autorización en OUT. */
int   spotify_login_url(char *out, size_t outlen, char *err, size_t errlen);

/* Termina el inicio de sesión con la dirección pegada (o solo el código). */
int   spotify_finish_login(const char *pasted, char *err, size_t errlen);

void  spotify_request_sync(void);
void  spotify_disconnect(void);
