# PS5NAS — app de la pantalla de inicio

Esta carpeta es la app nativa (título `PPSA27360`). Al abrirla arranca el
servidor ps5share si no está en marcha (envía `assets/ps5share.elf` al
cargador de payloads en `127.0.0.1:9021`) y abre el panel de administración en
el navegador de la consola.

Se compila desde la raíz del repositorio con `./tools/build-app.sh`, que deja
`dist/PPSA27360.zip` listo para copiar a `/data/homebrew/` (ShadowMountPlus lo
registra solo).

Basada en ps5-native-app-boilerplate (GPL-3.0-or-later, © 2026
BlackBearReloaded): sus herramientas de compilación están en `tools/`,
`tooling/` y `runtime/`. Ver `NOTICE-boilerplate.md`.
