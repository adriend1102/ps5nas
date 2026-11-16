/*
 * PS5NAS - app de la pantalla de inicio.
 * Copyright (C) 2026 ps5share contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Basada en ps5-native-app-boilerplate (C) 2026 BlackBearReloaded
 * (salida de vídeo por CPU y fuente de mapa de bits).
 *
 * Al abrirla:
 *   1. comprueba si el servidor ps5share está en marcha (puerto web);
 *   2. si no, envía /app0/assets/ps5nas.elf al cargador de payloads
 *      (127.0.0.1:9021) y espera a que arranque;
 *   3. abre el panel (http://127.0.0.1:<puerto>/) en el navegador de la
 *      consola.
 * La pantalla muestra el estado y las direcciones para conectarse.
 * X abre el panel otra vez; TRIÁNGULO reinicia el servidor.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

extern "C"
{
    std::size_t sceKernelGetDirectMemorySize();
    int sceKernelAllocateDirectMemory(std::int64_t search_start, std::int64_t search_end,
                                      std::size_t length, std::size_t alignment, int memory_type,
                                      std::int64_t *physical_address);
    int sceKernelMapDirectMemory(void **address, std::size_t length, int protection, int flags,
                                 std::int64_t physical_address, std::size_t alignment);
    int sceKernelSendNotificationRequest(std::uint32_t device, void *request, std::size_t size,
                                         int blocking);
    int sceKernelUsleep(std::uint32_t microseconds);
    int sceKernelOpen(const char *path, int flags, int mode);
    long sceKernelRead(int fd, void *buffer, std::size_t size);
    int sceKernelClose(int fd);
    long sceKernelWrite(int fd, const void *buffer, std::size_t size);
    int sceSystemServiceHideSplashScreen();
    int sceSystemServiceLaunchWebBrowser(const char *uri, const void *param);
    int sceSystemServiceParamGetInt(int param_id, int *value);
    int sceVideoOutOpen(std::int32_t user_id, std::int32_t bus_type, std::int32_t index,
                        const void *param);
    int sceVideoOutSetFlipRate(std::int32_t handle, std::int32_t rate);
    int sceVideoOutSubmitFlip(std::int32_t handle, std::int32_t buffer_index,
                              std::uint32_t flip_mode, std::int64_t flip_argument);
    int sceVideoOutWaitVblank(std::int32_t handle);

    int sceUserServiceInitialize(const void *params);
    int sceUserServiceGetInitialUser(int *user);
    int scePadInit(void);
    int scePadOpen(int user, int type, int index, const void *parameters);
    int scePadReadState(int handle, void *data);

    int sceNetSocket(const char *name, int family, int type, int protocol);
    int sceNetConnect(int socket, const void *address, unsigned length);
    int sceNetSend(int socket, const void *data, std::size_t size, int flags);
    int sceNetRecv(int socket, void *data, std::size_t size, int flags);
    int sceNetSocketClose(int socket);
    int sceNetSetsockopt(int socket, int level, int name, const void *value, unsigned length);
    int sceNetCtlInit(void);
    int sceNetCtlGetInfo(int code, void *info);
}

namespace
{
/* ------------------------------------------------------------------ */
/* Vídeo                                                               */
/* ------------------------------------------------------------------ */

constexpr unsigned frame_width = 1920;
constexpr unsigned frame_height = 1080;
constexpr std::size_t frame_bytes = 0x1000000;
constexpr std::size_t memory_bytes = frame_bytes * 2;
constexpr std::size_t memory_alignment = 0x200000;
constexpr int memory_type_wc_garlic = 3;
constexpr int map_protection = 0x33;
constexpr std::uint64_t pixel_format_rgba8_srgb = UINT64_C(0x8000000022000000);

struct VideoBuffer
{
    void *data;
    void *metadata;
    void *reserved0;
    void *reserved1;
};

struct VideoAttribute
{
    std::uint8_t reserved[80];
};

struct NotificationRequest
{
    std::int32_t type;
    std::int32_t request_id;
    std::int32_t priority;
    std::int32_t message_id;
    std::int32_t target_id;
    std::int32_t user_id;
    std::int32_t unknown1;
    std::int32_t unknown2;
    std::int32_t app_id;
    std::int32_t error_num;
    std::int32_t unknown3;
    char use_icon_image_uri;
    char message[1024];
    char icon_uri[1024];
    char unknown[1024];
};

} // namespace

extern "C" void sceVideoOutSetBufferAttribute2(VideoAttribute *attribute,
                                               std::uint64_t pixel_format,
                                               std::uint32_t tiling_mode, std::uint32_t width,
                                               std::uint32_t height, std::uint64_t option,
                                               std::uint32_t dcc_control,
                                               std::uint64_t dcc_clear_color);
extern "C" int sceVideoOutRegisterBuffers2(std::int32_t handle, std::int32_t set_index,
                                           std::int32_t buffer_index_start, VideoBuffer *buffers,
                                           std::int32_t buffer_count, VideoAttribute *attribute,
                                           std::int32_t category, void *option);

namespace
{
enum Color : std::uint32_t
{
    bg = UINT32_C(0xff1a120c),
    panel = UINT32_C(0xff2c2018),
    line = UINT32_C(0xff4a3a2e),
    white = UINT32_C(0xffffffff),
    muted = UINT32_C(0xffb8aa9c),
    accent = UINT32_C(0xffff9a4e),  /* azul (formato ABGR) */
    ok = UINT32_C(0xff6cd47a),
    warn = UINT32_C(0xff4ec4ff),
    bad = UINT32_C(0xff5a5aff),
    lock = UINT32_C(0xff3db3f2),    /* amarillo del candado */
};

/* Fuente 5x7: mayúsculas, cifras y signos básicos. */
struct Glyph
{
    char c;
    std::uint8_t rows[7];
};

constexpr Glyph glyphs[] = {
    {' ', {0, 0, 0, 0, 0, 0, 0}},        {'0', {14, 17, 19, 21, 25, 17, 14}},
    {'1', {4, 12, 4, 4, 4, 4, 14}},      {'2', {14, 17, 1, 2, 4, 8, 31}},
    {'3', {30, 1, 1, 14, 1, 1, 30}},     {'4', {2, 6, 10, 18, 31, 2, 2}},
    {'5', {31, 16, 16, 30, 1, 1, 30}},   {'6', {14, 16, 16, 30, 17, 17, 14}},
    {'7', {31, 1, 2, 4, 8, 8, 8}},       {'8', {14, 17, 17, 14, 17, 17, 14}},
    {'9', {14, 17, 17, 15, 1, 1, 14}},   {'A', {14, 17, 17, 31, 17, 17, 17}},
    {'B', {30, 17, 17, 30, 17, 17, 30}}, {'C', {14, 17, 16, 16, 16, 17, 14}},
    {'D', {30, 17, 17, 17, 17, 17, 30}}, {'E', {31, 16, 16, 30, 16, 16, 31}},
    {'F', {31, 16, 16, 30, 16, 16, 16}}, {'G', {14, 17, 16, 23, 17, 17, 14}},
    {'H', {17, 17, 17, 31, 17, 17, 17}}, {'I', {31, 4, 4, 4, 4, 4, 31}},
    {'J', {7, 2, 2, 2, 18, 18, 12}},     {'K', {17, 18, 20, 24, 20, 18, 17}},
    {'L', {16, 16, 16, 16, 16, 16, 31}}, {'M', {17, 27, 21, 21, 17, 17, 17}},
    {'N', {17, 25, 21, 19, 17, 17, 17}}, {'O', {14, 17, 17, 17, 17, 17, 14}},
    {'P', {30, 17, 17, 30, 16, 16, 16}}, {'Q', {14, 17, 17, 17, 21, 18, 13}},
    {'R', {30, 17, 17, 30, 20, 18, 17}}, {'S', {15, 16, 16, 14, 1, 1, 30}},
    {'T', {31, 4, 4, 4, 4, 4, 4}},       {'U', {17, 17, 17, 17, 17, 17, 14}},
    {'V', {17, 17, 17, 17, 17, 10, 4}},  {'W', {17, 17, 17, 21, 21, 21, 10}},
    {'X', {17, 17, 10, 4, 10, 17, 17}},  {'Y', {17, 17, 10, 4, 4, 4, 4}},
    {'Z', {31, 1, 2, 4, 8, 16, 31}},     {':', {0, 4, 4, 0, 4, 4, 0}},
    {'.', {0, 0, 0, 0, 0, 12, 12}},      {',', {0, 0, 0, 0, 12, 4, 8}},
    {'/', {1, 1, 2, 4, 8, 16, 16}},      {'-', {0, 0, 0, 31, 0, 0, 0}},
    {'(', {2, 4, 8, 8, 8, 4, 2}},        {')', {8, 4, 2, 2, 2, 4, 8}},
    {'!', {4, 4, 4, 4, 4, 0, 4}},        {'?', {14, 17, 1, 2, 4, 0, 4}},
    {'_', {0, 0, 0, 0, 0, 0, 31}},       {'=', {0, 0, 31, 0, 31, 0, 0}},
    {'>', {8, 4, 2, 1, 2, 4, 8}},        {'<', {2, 4, 8, 16, 8, 4, 2}},
    {'+', {0, 4, 4, 31, 4, 4, 0}},       {'\'', {4, 4, 8, 0, 0, 0, 0}},
};

const std::uint8_t *glyph_rows(char c) noexcept
{
    if (c >= 'a' && c <= 'z')
        c = static_cast<char>(c - 'a' + 'A');
    for (const auto &g : glyphs)
        if (g.c == c)
            return g.rows;
    return glyphs[0].rows;
}

std::size_t tiled_offset(unsigned x, unsigned y) noexcept
{
    const std::uint32_t offset = ((y << 4) & 0x70U) ^ ((y << 5) & 0xf00U) ^ ((y << 9) & 0x1000U) ^
                                 ((y << 8) & 0x4000U) ^ ((x << 2) & 0xcU) ^ ((x << 5) & 0x380U) ^
                                 ((x << 4) & 0x400U) ^ ((x << 6) & 0x800U) ^ ((x << 9) & 0xa000U);
    const std::uint32_t blocks_per_row = (frame_width + 127U) >> 7;
    const std::uint32_t block_index = (y >> 7) * blocks_per_row + (x >> 7);
    return (static_cast<std::size_t>(block_index) << 16) + offset;
}

class Canvas
{
  public:
    explicit Canvas(std::uint8_t *pixels) noexcept : px_{pixels}
    {
    }

    void rect(unsigned x, unsigned y, unsigned w, unsigned h, std::uint32_t c) noexcept
    {
        if (x >= frame_width || y >= frame_height)
            return;
        const unsigned r = w > frame_width - x ? frame_width : x + w;
        const unsigned b = h > frame_height - y ? frame_height : y + h;
        for (unsigned row = y; row < b; ++row)
            for (unsigned col = x; col < r; ++col)
                *reinterpret_cast<std::uint32_t *>(px_ + tiled_offset(col, row)) = c;
    }

    unsigned text(unsigned x, unsigned y, std::string_view s, unsigned scale,
                  std::uint32_t c) noexcept
    {
        for (const char ch : s)
        {
            const std::uint8_t *rows = glyph_rows(ch);
            for (unsigned row = 0; row < 7; ++row)
                for (unsigned col = 0; col < 5; ++col)
                    if (rows[row] & (1U << (4 - col)))
                        rect(x + col * scale, y + row * scale, scale, scale, c);
            x += 6 * scale;
        }
        return x;
    }

    static unsigned width(std::string_view s, unsigned scale) noexcept
    {
        return static_cast<unsigned>(s.size()) * 6 * scale;
    }

  private:
    std::uint8_t *px_;
};

void flush_range(void *address, std::size_t length) noexcept
{
    auto *at = static_cast<std::uint8_t *>(address);
    const auto *end = at + length;
    for (; at < end; at += 64)
        __asm__ volatile("clflush (%0)" : : "r"(at) : "memory");
    __asm__ volatile("mfence" ::: "memory");
}

NotificationRequest notification{};

/* Registro de diagnóstico en /data/ps5share/app.log (si se puede escribir). */
void trace(const char *fmt, ...) noexcept
{
    char line[256];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    const int n = std::vsnprintf(line, sizeof(line) - 1, fmt, ap);
    __builtin_va_end(ap);
    if (n <= 0)
        return;
    std::size_t len = static_cast<std::size_t>(n) < sizeof(line) - 1 ? static_cast<std::size_t>(n)
                                                                    : sizeof(line) - 2;
    line[len++] = '\n';
    /* O_WRONLY | O_CREAT | O_APPEND */
    const int fd = sceKernelOpen("/data/ps5share/app.log", 0x0001 | 0x0200 | 0x0008, 0666);
    if (fd < 0)
        return;
    (void)sceKernelWrite(fd, line, len);
    (void)sceKernelClose(fd);
}

void notify(const char *message) noexcept
{
    std::memset(&notification, 0, sizeof(notification));
    std::snprintf(notification.message, sizeof(notification.message), "%s", message);
    (void)sceKernelSendNotificationRequest(0, &notification, sizeof(notification), 0);
}

/* ------------------------------------------------------------------ */
/* Red                                                                 */
/* ------------------------------------------------------------------ */

struct SockaddrIn
{
    std::uint8_t len;
    std::uint8_t family;
    std::uint16_t port;
    std::uint32_t addr;
    std::uint8_t zero[8];
};

int connect_local(std::uint16_t port) noexcept
{
    const int s = sceNetSocket("ps5share", 2, 1, 6);
    if (s < 0)
        return -1;
    const int timeout_us = 3'000'000;
    (void)sceNetSetsockopt(s, 0xffff, 0x1105, &timeout_us, sizeof(timeout_us));
    (void)sceNetSetsockopt(s, 0xffff, 0x1106, &timeout_us, sizeof(timeout_us));
    (void)sceNetSetsockopt(s, 0xffff, 0x1109, &timeout_us, sizeof(timeout_us));
    const SockaddrIn a{sizeof(SockaddrIn), 2,
                       static_cast<std::uint16_t>((port << 8) | (port >> 8)), 0x0100007f, {0}};
    if (sceNetConnect(s, &a, sizeof(a)) < 0)
    {
        (void)sceNetSocketClose(s);
        return -1;
    }
    return s;
}

bool port_open(std::uint16_t port) noexcept
{
    const int s = connect_local(port);
    if (s < 0)
        return false;
    (void)sceNetSocketClose(s);
    return true;
}

enum class Err
{
    none,
    no_elf,
    no_loader,
    send_failed,
    no_answer,
};

/* Envía el ELF incluido en la app al cargador de payloads. */
Err send_payload() noexcept
{
    const int fd = sceKernelOpen("/app0/assets/ps5nas.elf", 0, 0);
    trace("abrir /app0/assets/ps5nas.elf: %d", fd);
    if (fd < 0)
    {
        return Err::no_elf;
    }
    const int s = connect_local(9021);
    trace("conectar al cargador 9021: %d", s);
    if (s < 0)
    {
        (void)sceKernelClose(fd);
        return Err::no_loader;
    }
    static std::uint8_t buf[65536];
    bool ok = true;
    for (;;)
    {
        const long n = sceKernelRead(fd, buf, sizeof(buf));
        if (n == 0)
            break;
        if (n < 0)
        {
            ok = false;
            break;
        }
        long sent = 0;
        while (sent < n)
        {
            const int w = sceNetSend(s, buf + sent, static_cast<std::size_t>(n - sent), 0);
            if (w <= 0)
            {
                ok = false;
                break;
            }
            sent += w;
        }
        if (!ok)
            break;
    }
    (void)sceKernelClose(fd);
    (void)sceNetSocketClose(s);
    trace("envío del servidor: %s", ok ? "ok" : "fallo");
    return ok ? Err::none : Err::send_failed;
}

/* Lee los puertos de /data/ps5share/users.conf (si la app puede verlo). */
void read_ports(unsigned &http, unsigned &sftp) noexcept
{
    static char text[16384];
    const int fd = sceKernelOpen("/data/ps5share/users.conf", 0, 0);
    if (fd < 0)
        return;
    const long n = sceKernelRead(fd, text, sizeof(text) - 1);
    (void)sceKernelClose(fd);
    if (n <= 0)
        return;
    text[n] = 0;
    auto find = [&](const char *key, unsigned &out) {
        const char *p = std::strstr(text, key);
        if (!p)
            return;
        p += std::strlen(key);
        unsigned v = 0;
        while (*p >= '0' && *p <= '9')
            v = v * 10 + static_cast<unsigned>(*p++ - '0');
        if (v > 0 && v < 65536)
            out = v;
    };
    find("set\thttp_port\t", http);
    find("set\tsftp_port\t", sftp);
}

/* Puerto HTTPS del gestor de contraseñas (0 = desactivado). */
unsigned g_https = 0;

/* Pide /api/status al servidor: su IP de Tailscale y el puerto SFTP. */
bool fetch_status(unsigned http, char *ts_ip, std::size_t ts_len, unsigned &sftp,
                  char app_lang[3]) noexcept
{
    const int s = connect_local(static_cast<std::uint16_t>(http));
    if (s < 0)
        return false;
    static const char req[] = "GET /api/status HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    if (sceNetSend(s, req, sizeof(req) - 1, 0) != static_cast<int>(sizeof(req) - 1))
    {
        (void)sceNetSocketClose(s);
        return false;
    }
    static char buf[4096];
    std::size_t have = 0;
    for (;;)
    {
        const int n = sceNetRecv(s, buf + have, sizeof(buf) - 1 - have, 0);
        if (n <= 0)
            break;
        have += static_cast<std::size_t>(n);
        if (have >= sizeof(buf) - 1)
            break;
    }
    (void)sceNetSocketClose(s);
    buf[have] = 0;
    const char *p = std::strstr(buf, "\"tailscale_ip\":\"");
    if (!p)
        return false;
    p += 16;
    std::size_t n = 0;
    while (p[n] && p[n] != '"' && n + 1 < ts_len && n < 15)
    {
        ts_ip[n] = p[n];
        ++n;
    }
    ts_ip[n] = 0;
    const char *q = std::strstr(buf, "\"sftp_port\":");
    if (q)
    {
        q += 12;
        unsigned v = 0;
        while (*q >= '0' && *q <= '9')
            v = v * 10 + static_cast<unsigned>(*q++ - '0');
        if (v > 0 && v < 65536)
            sftp = v;
    }
    const char *h = std::strstr(buf, "\"https_port\":");
    unsigned hv = 0;
    if (h)
    {
        h += 13;
        while (*h >= '0' && *h <= '9')
            hv = hv * 10 + static_cast<unsigned>(*h++ - '0');
    }
    g_https = (hv < 65536 && std::strstr(buf, "\"vault\":true")) ? hv : 0;
    /* Idioma elegido para la app (vacío = el de la consola). */
    app_lang[0] = 0;
    const char *l = std::strstr(buf, "\"app_lang\":\"");
    if (l && l[12] && l[13] && l[14] == '"')
    {
        app_lang[0] = l[12];
        app_lang[1] = l[13];
        app_lang[2] = 0;
    }
    return true;
}

/* Guarda en el servidor el idioma elegido con CUADRADO. */
void save_app_lang(unsigned http, const char *code) noexcept
{
    const int s = connect_local(static_cast<std::uint16_t>(http));
    if (s < 0)
        return;
    char req[256];
    const int n = std::snprintf(req, sizeof(req),
                                "POST /api/app/lang HTTP/1.0\r\nHost: 127.0.0.1\r\n"
                                "X-PS5Share: 1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                                "Content-Length: 7\r\n\r\nlang=%s",
                                code);
    if (n > 0)
        (void)sceNetSend(s, req, static_cast<std::size_t>(n), 0);
    char sink[512];
    (void)sceNetRecv(s, sink, sizeof(sink), 0);
    (void)sceNetSocketClose(s);
}

void local_ip(char *out, std::size_t len) noexcept
{
    union
    {
        char ip[16];
        std::uint8_t raw[256];
    } info{};
    std::snprintf(out, len, "?");
    if (sceNetCtlGetInfo(14, &info) == 0 && info.ip[0])
        std::snprintf(out, len, "%.15s", info.ip);
}

/* ------------------------------------------------------------------ */
/* Estado y dibujo                                                     */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Idiomas.  La fuente solo tiene mayúsculas ASCII: sin tildes ni      */
/* diéresis (AE, OE, UE y SS en alemán).                               */
/* ------------------------------------------------------------------ */

enum Lang : int
{
    lang_es = 0,
    lang_en = 1,
    lang_de = 2,
    lang_count = 3,
};

struct Texts
{
    const char *code;       /* es / en / de (para la web) */
    const char *tagline;
    const char *checking;
    const char *starting;
    const char *waiting;
    const char *ready;
    const char *failed;
    const char *home;
    const char *away;
    const char *web;        /* etiquetas de 8 caracteres */
    const char *sftp;
    const char *vault;
    const char *port;
    const char *no_ts;
    const char *ts_hint;
    const char *vault_note;
    const char *sftp_note;
    const char *open_panel;
    const char *triangle;
    const char *restart;
    const char *square;
    const char *language;
    const char *no_browser; /* %08X y %s */
    const char *no_elf;
    const char *no_loader;
    const char *send_failed;
    const char *no_answer;  /* %u */
};

/* En .data a propósito: si el compilador deja esta tabla de punteros en
   .data.rel.ro, el conversor de la plantilla no alinea ese segmento a 16 KB y
   la consola rechaza el eboot (CE-107750-0 / 0x80AA001A).  tools/build.sh
   comprueba que .data.rel.ro quede vacío. */
__attribute__((section(".data.ps5nas_texts"))) Texts texts[lang_count] = {
    {
        "es",
        "TU NAS EN LA PS5: SFTP, WEB, CARPETAS PRIVADAS Y CONTRASENAS",
        "COMPROBANDO EL SERVIDOR...",
        "ARRANCANDO EL SERVIDOR...",
        "ESPERANDO A QUE EL SERVIDOR RESPONDA...",
        "SERVIDOR EN MARCHA",
        "NO SE PUDO ARRANCAR EL SERVIDOR",
        "EN CASA (MISMA WIFI)",
        "FUERA DE CASA (TAILSCALE)",
        "WEB     ",
        "SFTP    ",
        "CLAVES  ",
        "PUERTO",
        "NO SE ENCUENTRA LA IP DE TAILSCALE",
        "ARRANCA EL PAYLOAD DE TAILSCALE: SU IP APARECERA AQUI SOLA",
        "CLAVES: SERVIDOR PARA LAS APPS Y LA EXTENSION DE BITWARDEN (AUTOALOJADO)",
        "SFTP: MIS ARCHIVOS DE SAMSUNG, WINSCP, FILEZILLA... CON TU USUARIO",
        "ABRIR EL PANEL DE ADMINISTRACION",
        "TRIANGULO",
        "REINICIAR EL SERVIDOR",
        "CUADRADO",
        "IDIOMA: ESPANOL",
        "NO SE PUDO ABRIR EL NAVEGADOR (0X%08X). ABRE %s EN EL NAVEGADOR.",
        "NO SE ENCUENTRA PS5NAS.ELF EN LA APP",
        "EL CARGADOR DE PAYLOADS (9021) NO RESPONDE",
        "NO SE PUDO ENVIAR EL SERVIDOR AL CARGADOR",
        "EL SERVIDOR NO RESPONDE EN EL PUERTO %u",
    },
    {
        "en",
        "YOUR NAS ON THE PS5: SFTP, WEB, PRIVATE FOLDERS AND PASSWORDS",
        "CHECKING THE SERVER...",
        "STARTING THE SERVER...",
        "WAITING FOR THE SERVER TO ANSWER...",
        "SERVER RUNNING",
        "COULD NOT START THE SERVER",
        "AT HOME (SAME WI-FI)",
        "AWAY FROM HOME (TAILSCALE)",
        "WEB     ",
        "SFTP    ",
        "VAULT   ",
        "PORT",
        "TAILSCALE IP NOT FOUND",
        "START THE TAILSCALE PAYLOAD: ITS IP WILL SHOW UP HERE BY ITSELF",
        "VAULT: SERVER FOR THE BITWARDEN APPS AND BROWSER EXTENSION (SELF-HOSTED)",
        "SFTP: SAMSUNG MY FILES, WINSCP, FILEZILLA... WITH YOUR USER",
        "OPEN THE ADMIN PANEL",
        "TRIANGLE",
        "RESTART THE SERVER",
        "SQUARE",
        "LANGUAGE: ENGLISH",
        "COULD NOT OPEN THE BROWSER (0X%08X). OPEN %s IN THE BROWSER.",
        "PS5NAS.ELF IS MISSING FROM THE APP",
        "THE PAYLOAD LOADER (9021) DOES NOT ANSWER",
        "COULD NOT SEND THE SERVER TO THE LOADER",
        "THE SERVER DOES NOT ANSWER ON PORT %u",
    },
    {
        "de",
        "DEIN NAS AUF DER PS5: SFTP, WEB, PRIVATE ORDNER UND PASSWOERTER",
        "SERVER WIRD GEPRUEFT...",
        "SERVER WIRD GESTARTET...",
        "WARTE AUF ANTWORT DES SERVERS...",
        "SERVER LAEUFT",
        "SERVER KONNTE NICHT GESTARTET WERDEN",
        "ZU HAUSE (GLEICHES WLAN)",
        "UNTERWEGS (TAILSCALE)",
        "WEB     ",
        "SFTP    ",
        "TRESOR  ",
        "PORT",
        "TAILSCALE-IP NICHT GEFUNDEN",
        "STARTE DAS TAILSCALE-PAYLOAD: DIE IP ERSCHEINT DANN HIER",
        "TRESOR: SERVER FUER DIE BITWARDEN-APPS UND -BROWSERERWEITERUNG (SELBST GEHOSTET)",
        "SFTP: SAMSUNG EIGENE DATEIEN, WINSCP, FILEZILLA... MIT DEINEM BENUTZER",
        "VERWALTUNG OEFFNEN",
        "DREIECK",
        "SERVER NEU STARTEN",
        "QUADRAT",
        "SPRACHE: DEUTSCH",
        "BROWSER KONNTE NICHT GEOEFFNET WERDEN (0X%08X). OEFFNE %s IM BROWSER.",
        "PS5NAS.ELF FEHLT IN DER APP",
        "DER PAYLOAD-LOADER (9021) ANTWORTET NICHT",
        "SERVER KONNTE NICHT AN DEN LOADER GESENDET WERDEN",
        "DER SERVER ANTWORTET NICHT AUF PORT %u",
    },
};

/* Idioma de la consola: 3 y 20 español, 4 alemán; el resto, inglés. */
Lang system_lang() noexcept
{
    int v = 1;
    if (sceSystemServiceParamGetInt(1 /* SCE_SYSTEM_SERVICE_PARAM_ID_LANG */, &v) < 0)
        return lang_en;
    if (v == 3 || v == 20)
        return lang_es;
    if (v == 4)
        return lang_de;
    return lang_en;
}

Lang lang_from_code(const char *c, Lang fallback) noexcept
{
    for (int i = 0; i < lang_count; ++i)
        if (c[0] == texts[i].code[0] && c[1] == texts[i].code[1])
            return static_cast<Lang>(i);
    return fallback;
}

enum class Phase
{
    checking,
    starting,
    waiting,
    ready,
    failed,
};

struct State
{
    Phase phase = Phase::checking;
    unsigned http = 8000;
    unsigned sftp = 2222;
    char ip[32] = "?";
    char ts_ip[20] = "";
    Err err = Err::none;
    char browser[128] = "";
    Lang lang = lang_en;
    bool started_by_app = false;
    int frame = 0;
};

void draw(Canvas &c, const State &st) noexcept
{
    char buf[200];
    const Texts &t = texts[st.lang];
    c.rect(0, 0, frame_width, frame_height, bg);

    /* cabecera: servidor con candado */
    c.rect(140, 104, 64, 20, accent);
    c.rect(140, 130, 64, 20, accent);
    c.rect(140, 156, 44, 20, accent);
    for (unsigned i = 0; i < 3; ++i)
    {
        c.rect(148, 111 + i * 26, 6, 6, bg);
        c.rect(162, 112 + i * 26, 28, 4, bg);
    }
    c.rect(196, 150, 4, 14, white);
    c.rect(220, 150, 4, 14, white);
    c.rect(196, 146, 28, 4, white);
    c.rect(190, 162, 40, 30, lock);
    c.rect(207, 170, 6, 14, bg);
    c.text(260, 112, "PS5NAS", 9, white);
    c.text(262, 186, t.tagline, 3, muted);

    c.rect(140, 260, 1640, 2, line);

    /* estado */
    const char *label = t.checking;
    std::uint32_t col = warn;
    switch (st.phase)
    {
    case Phase::checking:
        break;
    case Phase::starting:
        label = t.starting;
        break;
    case Phase::waiting:
        label = t.waiting;
        break;
    case Phase::ready:
        label = t.ready;
        col = ok;
        break;
    case Phase::failed:
        label = t.failed;
        col = bad;
        break;
    }
    c.rect(140, 318, 28, 28, col);
    c.text(196, 314, label, 6, white);
    if (st.phase == Phase::failed)
    {
        const char *e = st.err == Err::no_elf      ? t.no_elf
                        : st.err == Err::no_loader ? t.no_loader
                        : st.err == Err::send_failed ? t.send_failed
                                                     : t.no_answer;
        std::snprintf(buf, sizeof(buf), e, st.http);
        c.text(196, 380, buf, 3, bad);
    }

    /* conexión */
    c.rect(140, 400, 1640, 520, panel);
    c.text(190, 424, t.home, 3, muted);
    std::snprintf(buf, sizeof(buf), "%sHTTP://%s:%u", t.web, st.ip, st.http);
    c.text(190, 460, buf, 5, white);
    std::snprintf(buf, sizeof(buf), "%s%s  %s %u", t.sftp, st.ip, t.port, st.sftp);
    c.text(190, 510, buf, 5, white);
    if (g_https)
    {
        std::snprintf(buf, sizeof(buf), "%sHTTPS://%s:%u", t.vault, st.ip, g_https);
        c.text(190, 560, buf, 5, white);
    }
    c.rect(190, 620, 1540, 2, line);
    c.text(190, 640, t.away, 3, muted);
    if (st.ts_ip[0])
    {
        std::snprintf(buf, sizeof(buf), "%sHTTP://%s:%u", t.web, st.ts_ip, st.http);
        c.text(190, 676, buf, 5, white);
        std::snprintf(buf, sizeof(buf), "%s%s  %s %u", t.sftp, st.ts_ip, t.port, st.sftp);
        c.text(190, 726, buf, 5, white);
        if (g_https)
        {
            std::snprintf(buf, sizeof(buf), "%sHTTPS://%s:%u", t.vault, st.ts_ip, g_https);
            c.text(190, 776, buf, 5, white);
        }
    }
    else
    {
        c.text(190, 676, t.no_ts, 5, warn);
        c.text(190, 734, t.ts_hint, 3, muted);
    }
    c.text(190, 846, t.vault_note, 3, muted);
    c.text(190, 880, t.sftp_note, 3, muted);

    /* controles */
    if (st.phase == Phase::ready)
    {
        unsigned x = c.text(140, 945, "X", 5, accent);
        c.text(x + 20, 945, t.open_panel, 5, white);
    }
    unsigned x = c.text(140, 995, t.triangle, 5, accent);
    c.text(x + 20, 995, t.restart, 5, white);
    x = c.text(140, 1040, t.square, 3, accent);
    c.text(x + 14, 1040, t.language, 3, white);
    if (st.browser[0])
        c.text(800, 1052, st.browser, 2, muted);

    /* indicador de actividad */
    if (st.phase == Phase::checking || st.phase == Phase::starting ||
        st.phase == Phase::waiting)
    {
        const unsigned dot = static_cast<unsigned>(st.frame / 8) % 3;
        for (unsigned i = 0; i < 3; ++i)
            c.rect(1700 + i * 28, 324, 16, 16, i == dot ? white : line);
    }
}

void open_panel(State &st) noexcept
{
    char url[64];
    std::snprintf(url, sizeof(url), "http://127.0.0.1:%u/?lang=%s", st.http, texts[st.lang].code);
    const int r = sceSystemServiceLaunchWebBrowser(url, nullptr);
    trace("abrir navegador %s: 0x%08x", url, static_cast<unsigned>(r));
    if (r < 0)
        std::snprintf(st.browser, sizeof(st.browser), texts[st.lang].no_browser,
                      static_cast<unsigned>(r), url);
    else
        st.browser[0] = 0;
}

[[noreturn]] void halt(const char *message) noexcept
{
    notify(message);
    for (;;)
        (void)sceKernelUsleep(1000000);
}

} // namespace

int main()
{
    (void)sceSystemServiceHideSplashScreen();
    (void)sceNetCtlInit();

    const int video = sceVideoOutOpen(0xff, 0, 0, nullptr);
    if (video < 0)
        halt("PS5NAS: sceVideoOutOpen failed");
    const std::size_t pool = sceKernelGetDirectMemorySize();
    std::int64_t phys = 0;
    if (pool < memory_bytes ||
        sceKernelAllocateDirectMemory(0, static_cast<std::int64_t>(pool), memory_bytes,
                                      memory_alignment, memory_type_wc_garlic, &phys) < 0)
        halt("PS5NAS: direct memory allocation failed");
    void *mapped = nullptr;
    if (sceKernelMapDirectMemory(&mapped, memory_bytes, map_protection, 0, phys,
                                 memory_alignment) < 0)
        halt("PS5NAS: direct memory mapping failed");

    auto *base = static_cast<std::uint8_t *>(mapped);
    std::array<VideoBuffer, 2> buffers{{
        {base, nullptr, nullptr, nullptr},
        {base + frame_bytes, nullptr, nullptr, nullptr},
    }};
    VideoAttribute attribute{};
    (void)sceVideoOutSetFlipRate(video, 0);
    sceVideoOutSetBufferAttribute2(&attribute, pixel_format_rgba8_srgb, 0, frame_width,
                                   frame_height, 0, 0, 0);
    if (sceVideoOutRegisterBuffers2(video, 0, 0, buffers.data(), 2, &attribute, 0, nullptr) < 0)
        halt("PS5NAS: buffer registration failed");

    /* mando */
    int pad = -1;
    int user = -1;
    (void)sceUserServiceInitialize(nullptr);
    if (sceUserServiceGetInitialUser(&user) == 0)
    {
        (void)scePadInit();
        for (int i = 0; i < 20 && pad < 0; ++i)
        {
            pad = scePadOpen(user, 0, 0, nullptr);
            if (pad < 0)
                (void)sceKernelUsleep(50000);
        }
    }

    State st{};
    st.lang = system_lang();
    read_ports(st.http, st.sftp);
    local_ip(st.ip, sizeof(st.ip));
    trace("inicio: pad=%d user=0x%x http=%u sftp=%u ip=%s", pad, static_cast<unsigned>(user),
          st.http, st.sftp, st.ip);

    int current = 0;
    int ticks = 0;          /* décimas de segundo en la fase actual */
    std::uint32_t prev_buttons = 0;
    bool opened = false;
    bool lang_chosen = false;   /* cambiado con CUADRADO en esta sesión */
    unsigned last_sig = 0xffffffffU;

    for (;;)
    {
        /* lógica, unas 10 veces por segundo */
        if (st.frame % 6 == 0)
        {
            switch (st.phase)
            {
            case Phase::checking:
                if (port_open(static_cast<std::uint16_t>(st.http)))
                {
                    trace("servidor ya en marcha");
                    st.phase = Phase::ready;
                    ticks = 0;
                }
                else if ((st.err = send_payload()) == Err::none)
                {
                    st.phase = Phase::waiting;
                    st.started_by_app = true;
                    ticks = 0;
                }
                else
                {
                    st.phase = Phase::failed;
                }
                break;
            case Phase::starting:
                if ((st.err = send_payload()) == Err::none)
                {
                    st.phase = Phase::waiting;
                    ticks = 0;
                }
                else
                {
                    st.phase = Phase::failed;
                }
                break;
            case Phase::waiting:
                /* la primera vez genera las claves SSH: puede tardar */
                if (++ticks % 5 == 0)
                {
                    read_ports(st.http, st.sftp);
                    if (port_open(static_cast<std::uint16_t>(st.http)))
                    {
                        st.phase = Phase::ready;
                        ticks = 0;
                    }
                    else if (ticks > 900)
                    {
                        st.phase = Phase::failed;
                        st.err = Err::no_answer;
                    }
                }
                break;
            case Phase::ready:
                /* IP de Tailscale: al empezar y luego cada ~10 s (puede arrancar después) */
                if (ticks++ % 100 == 0)
                {
                    char ts[20] = "";
                    char al[3] = "";
                    if (fetch_status(st.http, ts, sizeof(ts), st.sftp, al))
                    {
                        std::snprintf(st.ts_ip, sizeof(st.ts_ip), "%s", ts);
                        if (al[0] && !lang_chosen)
                            st.lang = lang_from_code(al, st.lang);
                    }
                }
                if (!opened)
                {
                    opened = true;
                    local_ip(st.ip, sizeof(st.ip));
                    open_panel(st);
                }
                break;
            case Phase::failed:
                break;
            }

            /* mando */
            if (pad >= 0)
            {
                std::uint8_t data[256]{};
                if (scePadReadState(pad, data) == 0)
                {
                    std::uint32_t buttons = 0;
                    std::memcpy(&buttons, data, sizeof(buttons));
                    const std::uint32_t pressed = buttons & ~prev_buttons;
                    prev_buttons = buttons;
                    if ((pressed & 0x4000U) && st.phase == Phase::ready)
                        open_panel(st);
                    if (pressed & 0x1000U)
                    {
                        st.phase = Phase::starting;
                        st.err = Err::none;
                        opened = true; /* no volver a abrir el navegador solo */
                    }
                    if (pressed & 0x8000U) /* CUADRADO: siguiente idioma */
                    {
                        st.lang = static_cast<Lang>((st.lang + 1) % lang_count);
                        lang_chosen = true;
                        st.browser[0] = 0;
                        if (st.phase == Phase::ready)
                            save_app_lang(st.http, texts[st.lang].code);
                    }
                }
            }
        }

        /* Solo se redibuja cuando cambia algo (el dibujo es por CPU). */
        const bool busy = st.phase == Phase::checking || st.phase == Phase::starting ||
                          st.phase == Phase::waiting;
        const unsigned sig = static_cast<unsigned>(st.phase) * 100000U +
                             (busy ? static_cast<unsigned>(st.frame / 8) % 3 : 0U) * 10000U +
                             static_cast<unsigned>(std::strlen(st.browser)) * 100U +
                             static_cast<unsigned>(std::strlen(st.ip)) +
                             static_cast<unsigned>(std::strlen(st.ts_ip)) * 13U + st.sftp * 5U +
                             static_cast<unsigned>(st.ts_ip[std::strlen(st.ts_ip) ? std::strlen(st.ts_ip) - 1 : 0]) * 17U +
                             static_cast<unsigned>(st.err) * 7U + st.http * 3U +
                             static_cast<unsigned>(st.lang) * 1000000U;
        if (sig != last_sig || st.frame < 2)
        {
            last_sig = sig;
            current ^= 1;
            Canvas canvas{base + static_cast<std::size_t>(current) * frame_bytes};
            draw(canvas, st);
            flush_range(base + static_cast<std::size_t>(current) * frame_bytes, frame_bytes);
            (void)sceVideoOutSubmitFlip(video, current, 1, 0);
        }
        (void)sceVideoOutWaitVblank(video);
        ++st.frame;
    }
}
