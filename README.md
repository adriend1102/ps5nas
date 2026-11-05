# PS5 Share

Servidor de archivos **multiusuario** que corre directamente en una PS5 con
jailbreak. Cada usuario tiene su contraseña y solo ve las carpetas que le
asignes, en **solo lectura** o **lectura y escritura**. Se gestiona desde una
**web** (usuarios, carpetas y ajustes) y se accede por **FTP** o desde el propio
navegador (explorador de archivos con subida y descarga).

Está pensado para funcionar junto a **Tailscale para PS5**, de modo que la
consola sea a la vez el servidor y el punto de acceso VPN, sin necesitar ningún
PC encendido.

Es un fork de [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) de John
Törnblom (GPLv3).

```
 Móvil / portátil fuera de casa                 PS5 (siempre encendida)
 ┌───────────────────────────┐   Tailscale    ┌──────────────────────────────┐
 │ Navegador → http://ps5:8000│ ═════════════► │ tailscale.elf  (VPN, :8090)  │
 │ FileZilla → ftp://ps5:2121 │  (WireGuard)   │   └► reenvía a 127.0.0.1     │
 └───────────────────────────┘                 │ ps5share.elf                 │
                                               │   web :8000 · FTP :2121      │
 En casa: http://192.168.100.208:8000          │   usuarios → carpetas del SSD│
          ftp://192.168.100.208:2121           └──────────────────────────────┘
```

## Qué incluye

| | |
|---|---|
| `ps5share.elf` | El payload para la PS5 (web + FTP). |
| `windows/enviar-payload.ps1` | Envía cualquier `.elf` a la PS5 (puerto 9021). |
| `windows/instalar-tailscale-ps5.ps1` | Descarga la última versión de Tailscale para PS5 y la envía. |
| `windows/planB-windows-subnet-router.ps1` | Plan B si Tailscale no funciona en tu firmware: el Windows hace de puente. |

## Puesta en marcha

### 1. Cargar ps5share en la PS5

Con el jailbreak y el cargador de ELF (elfldr, puerto 9021) activos:

```powershell
cd windows
.\enviar-payload.ps1 -Archivo ..\ps5share.elf -PS5 192.168.100.208
```

En la PS5 aparecerá una notificación con las direcciones. Al arrancar,
ps5share **detiene el ftpsrv original** (no tiene contraseña y daría acceso a
todo el disco a cualquiera); se puede desactivar en Ajustes.

### 2. Crear el administrador y los usuarios

Abre `http://192.168.100.208:8000` en el PC o el móvil:

1. La primera vez te pide crear la cuenta de **administrador**.
2. En **Usuarios → Nuevo**: nombre, contraseña y las carpetas a las que tiene
   acceso. Para cada carpeta eliges el nombre que verá el usuario, la ruta real
   (botón **Elegir…** para navegar por el disco de la PS5) y el permiso.
3. Si tú también quieres ver archivos, añade carpetas a tu propio usuario.

Los cambios se aplican al momento: si desactivas o borras un usuario, sus
sesiones FTP y web se cortan.

Rutas habituales del almacenamiento en la PS5: `/mnt/ext0` (SSD M.2 o
almacenamiento ampliado), `/mnt/usb0`, `/mnt/usb1` (discos USB), `/data`.

### 3. Acceso remoto con Tailscale en la PS5

Se usa [holdmysocks/ps5-tailscale](https://github.com/holdmysocks/ps5-tailscale),
que ejecuta Tailscale dentro de la PS5 (modo userspace) y publica en tu red
Tailscale los puertos TCP que estén escuchando en la consola.

```powershell
.\instalar-tailscale-ps5.ps1 -PS5 192.168.100.208
```

En la página de estado de Tailscale (`http://192.168.100.208:8090`):

1. Inicia sesión en tu cuenta de Tailscale.
2. **Pon una contraseña** a esa página.
3. En *Settings → TCP ports never exposed* añade **8080, 9021, 2323, 3232**.
   Son websrv, el cargador de payloads, la shell y el log de otros payloads:
   ninguno pide contraseña y no deben quedar accesibles desde fuera.
4. Copia la IP de Tailscale de la PS5 (`100.x.y.z`) y pégala en
   **ps5share → Ajustes → IP de Tailscale**. Hace falta para el FTP en modo
   pasivo a través de Tailscale (FileZilla y WinSCP suelen funcionar igual sin
   ella porque usan EPSV, pero así va con cualquier cliente).

Desde cualquier dispositivo con Tailscale: `http://ps5:8000` (o
`http://100.x.y.z:8000`) y `ftp://ps5:2121`.

### 4. Dar acceso a otras personas

1. Crea su usuario en ps5share con sus carpetas.
2. Esa persona instala Tailscale con su propia cuenta.
3. Desde la consola de Tailscale (*Machines → ps5 → Share*) compártele **solo
   el dispositivo ps5**. No ve el resto de tus equipos.
4. En la PS5 deja `allowFrom` en su valor por defecto (si lo pones en `"own"`
   los dispositivos compartidos quedan fuera).

Con los puertos bloqueados del paso 3, lo único que puede alcanzar es la web y
el FTP de ps5share, donde solo ve sus carpetas.

### 5. Que arranque solo

Los payloads se pierden al reiniciar la consola o salir del modo reposo sin
jailbreak. Añade `tailscale.elf` y `ps5share.elf` a tu cargador automático
(el autoloader o gestor de payloads que uses) para que se carguen solos tras
cada jailbreak. La PS5 no atiende conexiones en modo reposo: tiene que estar
encendida.

## Clientes FTP

* Protocolo: FTP sin cifrar, puerto **2121**, modo **pasivo**.
* Usuario y contraseña: los que creaste en la web.
* Puertos pasivos: 50000–50099 (configurable). En casa no hay que abrir nada en
  el router; por Tailscale tampoco.

FileZilla, WinSCP, el explorador de Windows y las apps de móvil típicas sirven.

## Seguridad

* Contraseñas guardadas con PBKDF2-SHA256 (20 000 iteraciones, sal aleatoria)
  en `/data/ps5share/users.conf`.
* Los usuarios no pueden salir de sus carpetas (ni con `..` ni con enlaces
  simbólicos) y no pueden borrar ni renombrar la carpeta raíz asignada.
* Web: cookie `HttpOnly` + `SameSite=Strict`, protección CSRF por cabecera,
  bloqueo temporal tras 10 intentos fallidos, los archivos se sirven en un
  *sandbox* para que un HTML subido no pueda ejecutar nada.
* FTP: bloqueo tras 5 intentos por conexión, la conexión de datos solo se
  acepta desde la IP del cliente, sin `PORT` hacia terceros (anti *bounce*).
* **FTP y la web van sin cifrar.** A través de Tailscale el tráfico viaja
  cifrado por WireGuard; en tu red de casa no. No abras puertos en el router.
* Por Tailscale todas las conexiones llegan a ps5share desde `127.0.0.1`, así
  que el bloqueo por intentos fallidos de la web se aplica a todos los
  accesos remotos a la vez.

## Plan B: Windows como puente

Solo si Tailscale no funciona en tu firmware (ps5-tailscale está probado en
13.42). ps5share sigue en la PS5; el Windows anuncia la IP de la consola a tu
red Tailscale:

```powershell
# PowerShell como administrador, con Tailscale para Windows instalado
.\planB-windows-subnet-router.ps1 -PS5 192.168.100.208
```

Después aprueba la ruta en la consola de Tailscale. Desde fuera usarás
`http://192.168.100.208:8000` y `ftp://192.168.100.208:2121`. El Windows tiene
que estar encendido (y sin suspenderse).

## Compilar

Con el [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) en Linux o WSL:

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make -f Makefile.ps5            # genera ps5share.elf
make -f Makefile.ps5 test PS5_HOST=192.168.100.208   # compila y envía
```

Para probar en Linux sin consola:

```sh
./test/run_tests.sh             # compila la versión Linux y pasa ~60 pruebas
./ps5share-linux -d ./datos     # web en :8000, FTP en :2121
```

### Estructura

| Archivo | Qué hace |
|---|---|
| `src/config.c` | `users.conf`, usuarios, contraseñas (PBKDF2), ajustes |
| `src/vfs.c` | Carpetas virtuales por usuario y bloqueo de escapes |
| `src/ftp.c` | Servidor FTP (derivado de ftpsrv) con login y permisos |
| `src/http.c` | Servidor web y API JSON |
| `web/index.html` | Interfaz web (se incrusta en el ELF con `tools/embed.py`) |
| `src/main-prospero.c` | Arranque en PS5 |

### Formato de `users.conf`

Separado por tabuladores. Mejor editarlo desde la web. En las líneas `user`
los dos últimos campos son *administrador* y *activa* (1 = sí).

```
set	ftp_port	2121
set	http_port	8000
set	pasv_min	50000
set	pasv_max	50099
set	pasv_address	100.101.102.103
set	kill_ftpsrv	1
user	ana	<sal>	<hash>	1	1
mount	ana	rw	Fotos	/mnt/ext0/Fotos
mount	ana	ro	Películas	/mnt/usb0/Peliculas
```

Si olvidas la contraseña del administrador: carga el ftpsrv original, borra
`/data/ps5share/users.conf` (o solo las líneas de ese usuario) y vuelve a
cargar ps5share. Si no queda ningún usuario, la web vuelve a pedir que crees el
administrador.

## Licencia

GPLv3 (ver `LICENSE`). Basado en ftpsrv © John Törnblom.
