/* ps5share - arranque común a PS5 y Linux
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#pragma once

/* Carga la configuración y arranca FTP (hilo) y web (este hilo).
   NOTIFY_FN se llama con un texto de estado cuando hay red. */
int app_run(const char *confdir, void (*notify_fn)(const char *msg));
