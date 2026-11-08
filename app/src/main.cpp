/*
 * PS5 Share - app de la pantalla de inicio.
 * Copyright (C) 2026 ps5share contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Basada en ps5-native-app-boilerplate (C) 2026 BlackBearReloaded
 * (salida de vídeo por CPU y fuente de mapa de bits).
 *
 * Al abrirla:
 *   1. comprueba si el servidor ps5share está en marcha (puerto web);
 *   2. si no, envía /app0/assets/ps5share.elf al cargador de payloads
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

/* Envía el ELF incluido en la app al cargador de payloads. */
bool send_payload(char *error, std::size_t error_len) noexcept
{
    const int fd = sceKernelOpen("/app0/assets/ps5share.elf", 0, 0);
    trace("abrir /app0/assets/ps5share.elf: %d", fd);
    if (fd < 0)
    {
        std::snprintf(error, error_len, "NO SE ENCUENTRA PS5SHARE.ELF EN LA APP");
        return false;
    }
    const int s = connect_local(9021);
    trace("conectar al cargador 9021: %d", s);
    if (s < 0)
    {
        (void)sceKernelClose(fd);
        std::snprintf(error, error_len, "EL CARGADOR DE PAYLOADS (9021) NO RESPONDE");
        return false;
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
    if (!ok)
        std::snprintf(error, error_len, "NO SE PUDO ENVIAR EL SERVIDOR AL CARGADOR");
    return ok;
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
    char error[128] = "";
    char browser[96] = "";
    bool started_by_app = false;
    int frame = 0;
};

void draw(Canvas &c, const State &st) noexcept
{
    char buf[160];
    c.rect(0, 0, frame_width, frame_height, bg);

    /* cabecera */
    c.rect(140, 110, 72, 72, accent);
    c.rect(158, 128, 36, 8, bg);
    c.rect(158, 146, 36, 8, bg);
    c.rect(158, 164, 24, 8, bg);
    c.text(240, 112, "PS5 SHARE", 9, white);
    c.text(242, 186, "SERVIDOR DE ARCHIVOS MULTIUSUARIO", 3, muted);

    c.rect(140, 260, 1640, 2, line);

    /* estado */
    const char *label = "COMPROBANDO EL SERVIDOR...";
    std::uint32_t col = warn;
    switch (st.phase)
    {
    case Phase::checking:
        break;
    case Phase::starting:
        label = "ARRANCANDO EL SERVIDOR...";
        break;
    case Phase::waiting:
        label = "ESPERANDO A QUE EL SERVIDOR RESPONDA...";
        break;
    case Phase::ready:
        label = "SERVIDOR EN MARCHA";
        col = ok;
        break;
    case Phase::failed:
        label = "NO SE PUDO ARRANCAR EL SERVIDOR";
        col = bad;
        break;
    }
    c.rect(140, 318, 28, 28, col);
    c.text(196, 314, label, 6, white);
    if (st.phase == Phase::failed)
        c.text(196, 380, st.error, 3, bad);

    /* conexión */
    c.rect(140, 450, 1640, 330, panel);
    c.text(190, 490, "PANEL WEB", 3, muted);
    std::snprintf(buf, sizeof(buf), "HTTP://%s:%u", st.ip, st.http);
    c.text(190, 530, buf, 6, white);
    c.text(190, 620, "SFTP (MIS ARCHIVOS, WINSCP, FILEZILLA...)", 3, muted);
    std::snprintf(buf, sizeof(buf), "%s  PUERTO %u", st.ip, st.sftp);
    c.text(190, 660, buf, 6, white);
    c.text(190, 730, "FUERA DE CASA: USA LA IP 100.X.Y.Z DE TAILSCALE", 3, muted);

    /* controles */
    if (st.phase == Phase::ready)
    {
        unsigned x = c.text(140, 850, "X", 5, accent);
        c.text(x + 20, 850, "ABRIR EL PANEL DE ADMINISTRACION", 5, white);
    }
    unsigned x = c.text(140, 920, "TRIANGULO", 5, accent);
    c.text(x + 20, 920, "REINICIAR EL SERVIDOR", 5, white);
    if (st.browser[0])
        c.text(140, 1000, st.browser, 3, muted);

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
    std::snprintf(url, sizeof(url), "http://127.0.0.1:%u/", st.http);
    const int r = sceSystemServiceLaunchWebBrowser(url, nullptr);
    trace("abrir navegador %s: 0x%08x", url, static_cast<unsigned>(r));
    if (r < 0)
        std::snprintf(st.browser, sizeof(st.browser),
                      "NO SE PUDO ABRIR EL NAVEGADOR (0X%08X). ABRE %s EN EL NAVEGADOR.",
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
        halt("PS5 Share: sceVideoOutOpen failed");
    const std::size_t pool = sceKernelGetDirectMemorySize();
    std::int64_t phys = 0;
    if (pool < memory_bytes ||
        sceKernelAllocateDirectMemory(0, static_cast<std::int64_t>(pool), memory_bytes,
                                      memory_alignment, memory_type_wc_garlic, &phys) < 0)
        halt("PS5 Share: direct memory allocation failed");
    void *mapped = nullptr;
    if (sceKernelMapDirectMemory(&mapped, memory_bytes, map_protection, 0, phys,
                                 memory_alignment) < 0)
        halt("PS5 Share: direct memory mapping failed");

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
        halt("PS5 Share: buffer registration failed");

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
    read_ports(st.http, st.sftp);
    local_ip(st.ip, sizeof(st.ip));
    trace("inicio: pad=%d user=0x%x http=%u sftp=%u ip=%s", pad, static_cast<unsigned>(user),
          st.http, st.sftp, st.ip);

    int current = 0;
    int ticks = 0;          /* décimas de segundo en la fase actual */
    std::uint32_t prev_buttons = 0;
    bool opened = false;
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
                }
                else if (send_payload(st.error, sizeof(st.error)))
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
                if (send_payload(st.error, sizeof(st.error)))
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
                        st.phase = Phase::ready;
                    else if (ticks > 900)
                    {
                        st.phase = Phase::failed;
                        std::snprintf(st.error, sizeof(st.error),
                                      "EL SERVIDOR NO RESPONDE EN EL PUERTO %u", st.http);
                    }
                }
                break;
            case Phase::ready:
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
                        st.error[0] = 0;
                        opened = true; /* no volver a abrir el navegador solo */
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
                             static_cast<unsigned>(std::strlen(st.error)) * 7U + st.http * 3U;
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
