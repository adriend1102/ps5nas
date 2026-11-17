/* ps5share - vigilancia de temperatura y control del ventilador
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Lectura de sensores y acceso al ventilador basados en Breeze
   (https://github.com/MiladRTX/Breeze, GPLv3, (C) Milad):
   - sceKernelGetCpuTemperature / sceKernelGetSocSensorTemperature /
     sceKernelGetCurrentFanDuty para leer;
   - ioctl 0xC01C8F08 (leer) y 0xC01C8F07 (escribir) sobre /dev/icc_fan
     para el objetivo de temperatura del canal 0 (bytes 4..7, en 1/256 °C).

   Reglas para convivir con otras apps que también tocan el ventilador
   (Machete IA, Breeze, el ayudante de PS5Upload):
   - Solo se escribe cuando hace falta y se recuerda qué se escribió.
   - Si al volver a mirar el objetivo es otro distinto del de fábrica, lo
     ha puesto otra app: PS5NAS no se pelea con ella (lo indica en la web).
   - Al terminar una intervención se deja el valor que había antes, y solo
     si nadie lo ha cambiado mientras tanto.
   - Nunca se escribe un objetivo mayor de 91 °C (el de fábrica) ni menor
     de FAN_MIN_C: en el peor caso el ventilador gira más de la cuenta.  */

#include "fan.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include "log.h"
#include "notify.h"

#define TICK_S        2       /* cada cuánto se mira */
#define HIST_STEP_S   30      /* un punto del historial cada 30 s */
#define HIST_N        2880    /* 24 h */
#define HYST_C        8       /* se vuelve a la normalidad 8 °C por debajo… */
#define CALM_S        60      /* …tras 60 s seguidos */

#define STOCK_DEFAULT (91 * 256)

typedef struct {
  int16_t cpu, soc, duty, tgt;   /* -1: sin dato; tgt en °C */
} hpoint_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_path[512];

/* Ajustes */
static int g_mode = FAN_MODE_PROTECT;
static int g_trip = 80;
static int g_cool = 65;
static int g_fixed = 70;
static int g_notify = 1;

/* Lecturas */
static int g_sensors = 0, g_icc = 0;
static int g_cpu = -1, g_soc = -1, g_duty = -1, g_tgt = -1;  /* g_tgt en 1/256 °C */
static int g_stock = STOCK_DEFAULT;

/* Control */
static int g_ours = -1;          /* último objetivo escrito por PS5NAS */
static int g_before = -1;        /* el que había antes de intervenir */
static int g_active = 0;         /* intervención (modo protección o fijo) en curso */
static int g_conflict = 0;       /* otra app controla el ventilador */
static int g_takeover = 0;       /* aplicar el modo fijo aunque haya otra app (tras guardar) */
static time_t g_since = 0;
static time_t g_calm_since = 0;

/* Historial */
static hpoint_t g_hist[HIST_N];
static int g_hhead = 0, g_hcount = 0;
static time_t g_hend = 0;
static int g_wmax_cpu = -1, g_wmax_soc = -1;


/* ------------------------------------------------------------------ */
/* Hardware                                                            */
/* ------------------------------------------------------------------ */

#ifdef __PROSPERO__

extern int sceKernelGetCpuTemperature(int *t) __attribute__((weak));
extern int sceKernelGetSocSensorTemperature(int id, int *t) __attribute__((weak));
extern int sceKernelGetCurrentFanDuty(uint16_t *duty, uint64_t *chassis) __attribute__((weak));

#define ICC_FAN_DEV  "/dev/icc_fan"
#define ICC_FAN_SET  0xC01C8F07
#define ICC_FAN_GET  0xC01C8F08
#define ICC_OBJ      28
#define ICC_BUF      32

static void
hw_read(int *cpu, int *soc, int *duty) {
  *cpu = *soc = *duty = -1;
  if(sceKernelGetCpuTemperature) {
    int t = 0;
    if(!sceKernelGetCpuTemperature(&t) && t > 0 && t < 150) *cpu = t;
  }
  if(sceKernelGetSocSensorTemperature) {
    int t = 0;
    if(!sceKernelGetSocSensorTemperature(0, &t) && t > 0 && t < 150) *soc = t;
  }
  if(sceKernelGetCurrentFanDuty) {
    uint16_t d = 0;
    uint64_t ch = 0;
    if(!sceKernelGetCurrentFanDuty(&d, &ch)) *duty = (int)(((uint32_t)d * 100u + 512u) / 1024u);
  }
}

static int
icc_ioctl(unsigned long req, unsigned char *buf) {
  int fd = open(ICC_FAN_DEV, O_RDONLY, 0);
  if(fd < 0) return -1;
  int rc = ioctl(fd, req, buf);
  close(fd);
  return rc < 0 ? -1 : 0;
}

/* Objetivo actual del canal 0 en 1/256 °C, o -1. */
static int
hw_target(unsigned char obj[ICC_BUF]) {
  memset(obj, 0, ICC_BUF);
  if(icc_ioctl(ICC_FAN_GET, obj) || obj[0] || obj[1]) return -1;
  uint32_t v = (uint32_t)obj[4] | (uint32_t)obj[5] << 8 | (uint32_t)obj[6] << 16 |
               (uint32_t)obj[7] << 24;
  return v > 255u * 256u ? -1 : (int)v;
}

static int
hw_set_target(int c256) {
  unsigned char b[ICC_BUF];
  if(hw_target(b) < 0) return -1;       /* sin leer antes no se escribe */
  b[0] = b[1] = 0;
  b[2] = 0;                             /* canal 0 */
  b[4] = (unsigned char)(c256 & 0xff);
  b[5] = (unsigned char)(c256 >> 8 & 0xff);
  b[6] = b[7] = 0;
  if(icc_ioctl(ICC_FAN_SET, b) || b[0] || b[1]) return -1;
  return 0;
}

#else  /* Linux: sin sensores */

static void hw_read(int *cpu, int *soc, int *duty) { *cpu = *soc = *duty = -1; }
static int  hw_target(unsigned char *obj) { (void)obj; return -1; }
static int  hw_set_target(int c256) { (void)c256; return -1; }
#define ICC_BUF 32

#endif


/* ------------------------------------------------------------------ */
/* Ajustes                                                             */
/* ------------------------------------------------------------------ */

static int
clampi(int v, int lo, int hi) {
  return v < lo ? lo : v > hi ? hi : v;
}

static int
stock_ok(int c256) {
  /* Valores de fábrica: grados enteros entre 60 y 91 (77 lo escriben
     otras herramientas, no el firmware). */
  return c256 >= 60 * 256 && c256 <= STOCK_DEFAULT && c256 % 256 == 0 && c256 != 77 * 256;
}

/* Valores que pone el propio firmware (91 °C, y 86 °C en algunos casos). */
static int
is_fw(int c256) {
  return c256 == STOCK_DEFAULT || c256 == 86 * 256 || c256 == g_stock;
}

static void
load_conf(void) {
  FILE *f = fopen(g_path, "r");
  char line[128];
  if(!f) return;
  while(fgets(line, sizeof(line), f)) {
    char *eq = strchr(line, '=');
    if(!eq) continue;
    *eq = 0;
    int v = atoi(eq + 1);
    if(!strcmp(line, "mode") && v >= 0 && v <= 2) g_mode = v;
    else if(!strcmp(line, "trip")) g_trip = clampi(v, 60, 90);
    else if(!strcmp(line, "cool")) g_cool = clampi(v, FAN_MIN_C, 85);
    else if(!strcmp(line, "fixed")) g_fixed = clampi(v, FAN_MIN_C, FAN_MAX_C);
    else if(!strcmp(line, "notify")) g_notify = v != 0;
    else if(!strcmp(line, "stock") && stock_ok(v)) g_stock = v;
  }
  fclose(f);
}

static int
save_conf(void) {
  char tmp[sizeof(g_path) + 8];
  snprintf(tmp, sizeof(tmp), "%s.tmp", g_path);
  FILE *f = fopen(tmp, "w");
  if(!f) return -1;
  fprintf(f, "mode=%d\ntrip=%d\ncool=%d\nfixed=%d\nnotify=%d\nstock=%d\n",
          g_mode, g_trip, g_cool, g_fixed, g_notify, g_stock);
  if(fclose(f)) return -1;
  return rename(tmp, g_path);
}


/* ------------------------------------------------------------------ */
/* Control                                                             */
/* ------------------------------------------------------------------ */

static void
say(const char *fmt, ...) {
  char msg[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  LOG_PRINTF("ps5share: %s\n", msg);
  if(g_notify) notify("PS5NAS: %s", msg);
}

/* Escribe C256 y lo recuerda.  Con g_lock. */
static int
write_target(int c256) {
  c256 = clampi(c256, FAN_MIN_C * 256, FAN_MAX_C * 256);
  if(hw_set_target(c256)) return -1;
  g_ours = c256;
  g_tgt = c256;
  return 0;
}

/* Deja el valor de antes si el actual sigue siendo el nuestro.  Con g_lock. */
static void
release(int cur) {
  if(g_ours >= 0 && cur == g_ours) {
    int back = g_before >= 0 ? g_before : g_stock;
    if(back > STOCK_DEFAULT) back = STOCK_DEFAULT;
    hw_set_target(clampi(back, FAN_MIN_C * 256, FAN_MAX_C * 256));
  }
  g_ours = g_before = -1;
  g_active = 0;
  g_since = 0;
}

static void
tick(void) {
  int cpu, soc, duty;
  unsigned char obj[ICC_BUF];
  time_t now = time(NULL);

  hw_read(&cpu, &soc, &duty);
  int cur = hw_target(obj);

  pthread_mutex_lock(&g_lock);
  g_cpu = cpu; g_soc = soc; g_duty = duty; g_tgt = cur;
  g_sensors = cpu >= 0 || soc >= 0;
  g_icc = cur >= 0;
  int t = cpu > soc ? cpu : soc;

  if(g_icc && t > 0) {
    switch(g_mode) {
    case FAN_MODE_WATCH:
      if(g_active) release(cur);
      g_conflict = 0;
      break;

    case FAN_MODE_PROTECT:
      if(!g_active) {
        g_conflict = !is_fw(cur) && cur != g_ours;
        if(t >= g_trip && cur > g_cool * 256) {
          g_before = cur;
          if(!write_target(g_cool * 256)) {
            g_active = 1;
            g_since = now;
            g_calm_since = 0;
            say("%d °C: ventilador acelerado (objetivo %d °C)", t, g_cool);
          }
        }
      } else {
        if(cur != g_ours) {
          if(is_fw(cur)) {
            /* El firmware recarga su valor al abrir o cerrar un juego. */
            write_target(g_ours);
          } else {
            /* Otra app ha tomado el control: no se pelea. */
            g_ours = g_before = -1;
            g_active = 0;
            g_conflict = 1;
            break;
          }
        }
        if(t <= g_trip - HYST_C) {
          if(!g_calm_since) g_calm_since = now;
          if(now - g_calm_since >= CALM_S) {
            release(g_ours);
            say("temperatura normal (%d °C): ventilador como antes", t);
          }
        } else {
          g_calm_since = 0;
        }
      }
      break;

    case FAN_MODE_FIXED: {
      int want = g_fixed * 256;
      if(cur == want) {
        if(!g_active) { g_active = 1; g_since = now; g_ours = want; }
        g_conflict = 0;
      } else if(g_takeover || is_fw(cur) || (g_ours >= 0 && cur == g_ours)) {
        if(!g_active) g_before = cur;
        if(!write_target(want)) {
          if(!g_active) g_since = now;
          g_active = 1;
          g_conflict = 0;
        }
      } else {
        g_conflict = 1;   /* otra app ha puesto su propio objetivo */
      }
      g_takeover = 0;
      break;
    }
    }
  }

  /* Historial: un punto cada HIST_STEP_S con la máxima del intervalo. */
  if(cpu > g_wmax_cpu) g_wmax_cpu = cpu;
  if(soc > g_wmax_soc) g_wmax_soc = soc;
  if(!g_hend) g_hend = now;
  if(now - g_hend >= HIST_STEP_S) {
    hpoint_t *p = &g_hist[g_hhead];
    p->cpu = (int16_t)g_wmax_cpu;
    p->soc = (int16_t)g_wmax_soc;
    p->duty = (int16_t)duty;
    p->tgt = (int16_t)(cur >= 0 ? (cur + 128) / 256 : -1);
    g_hhead = (g_hhead + 1) % HIST_N;
    if(g_hcount < HIST_N) g_hcount++;
    g_hend = now;
    g_wmax_cpu = g_wmax_soc = -1;
  }
  pthread_mutex_unlock(&g_lock);
}

static void*
fan_thread(void *arg) {
  (void)arg;
  for(;;) {
    tick();
    sleep(TICK_S);
  }
  return NULL;
}


/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

void
fan_init(const char *confdir) {
  pthread_t t;
  pthread_attr_t attr;
  snprintf(g_path, sizeof(g_path), "%s/fan.conf", confdir);
  pthread_mutex_lock(&g_lock);
  load_conf();
  pthread_mutex_unlock(&g_lock);
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, 128 * 1024);
  if(pthread_create(&t, &attr, fan_thread, NULL)) {
    LOG_PUTS("ps5share: no se pudo arrancar la vigilancia del ventilador");
  }
  pthread_attr_destroy(&attr);
}


int
fan_configure(int mode, int trip_c, int cool_c, int fixed_c, int notify_on,
              char *err, size_t errlen) {
  pthread_mutex_lock(&g_lock);
  int m = mode >= 0 ? mode : g_mode;
  int tr = trip_c >= 0 ? trip_c : g_trip;
  int co = cool_c >= 0 ? cool_c : g_cool;
  int fx = fixed_c >= 0 ? fixed_c : g_fixed;
  if(m < 0 || m > 2) {
    pthread_mutex_unlock(&g_lock);
    snprintf(err, errlen, "Modo no válido");
    return -1;
  }
  if(tr < 60 || tr > 90 || co < FAN_MIN_C || co > 85 || co >= tr ||
     fx < FAN_MIN_C || fx > FAN_MAX_C) {
    pthread_mutex_unlock(&g_lock);
    snprintf(err, errlen, "Temperaturas no válidas");
    return -1;
  }
  int cur = g_tgt;
  if(m != g_mode || (m == FAN_MODE_FIXED && fx != g_fixed) ||
     (m == FAN_MODE_PROTECT && co != g_cool)) {
    if(g_active) release(cur);
    g_conflict = 0;
    g_takeover = m == FAN_MODE_FIXED;   /* al guardarlo, el fijo se aplica ya */
  }
  g_mode = m; g_trip = tr; g_cool = co; g_fixed = fx;
  if(notify_on >= 0) g_notify = notify_on != 0;
  int rc = save_conf();
  pthread_mutex_unlock(&g_lock);
  if(rc) {
    snprintf(err, errlen, "No se pudo guardar la configuración");
    return -1;
  }
  return 0;
}


static void
jint(char *buf, size_t len, size_t *o, int v) {
  if(*o >= len) return;
  if(v < 0) *o += (size_t)snprintf(buf + *o, len - *o, "null");
  else *o += (size_t)snprintf(buf + *o, len - *o, "%d", v);
}

char*
fan_status_json(void) {
  size_t len = 4096 + (size_t)HIST_N * 24;
  char *b = malloc(len);
  size_t o = 0;
  if(!b) return NULL;

  pthread_mutex_lock(&g_lock);
  const char *state = !g_icc ? "noicc"
                    : g_mode == FAN_MODE_WATCH ? "watch"
                    : g_conflict ? "other"
                    : g_mode == FAN_MODE_FIXED ? (g_active ? "fixed" : "pending")
                    : g_active ? "cooling" : "idle";
  int max24 = -1;
  for(int i=0; i<g_hcount; i++) {
    const hpoint_t *p = &g_hist[i];
    if(p->cpu > max24) max24 = p->cpu;
    if(p->soc > max24) max24 = p->soc;
  }
  o += (size_t)snprintf(b + o, len - o,
        "{\"sensors\":%s,\"icc\":%s,\"cpu\":", g_sensors ? "true" : "false",
        g_icc ? "true" : "false");
  jint(b, len, &o, g_cpu);
  o += (size_t)snprintf(b + o, len - o, ",\"soc\":");
  jint(b, len, &o, g_soc);
  o += (size_t)snprintf(b + o, len - o, ",\"duty\":");
  jint(b, len, &o, g_duty);
  o += (size_t)snprintf(b + o, len - o, ",\"target\":");
  if(g_tgt >= 0) o += (size_t)snprintf(b + o, len - o, "%.1f", g_tgt / 256.0);
  else o += (size_t)snprintf(b + o, len - o, "null");
  o += (size_t)snprintf(b + o, len - o,
        ",\"stock\":%d,\"mode\":%d,\"trip\":%d,\"cool\":%d,\"fixed\":%d,\"notify\":%s,"
        "\"state\":\"%s\",\"since\":%lld,\"max24\":",
        (g_stock + 128) / 256, g_mode, g_trip, g_cool, g_fixed, g_notify ? "true" : "false",
        state, (long long)g_since);
  jint(b, len, &o, max24);
  o += (size_t)snprintf(b + o, len - o, ",\"min_c\":%d,\"max_c\":%d,\"hist_step\":%d,\"hist_end\":%lld,\"hist\":[",
                        FAN_MIN_C, FAN_MAX_C, HIST_STEP_S, (long long)g_hend);
  int start = (g_hhead - g_hcount + HIST_N) % HIST_N;
  for(int i=0; i<g_hcount && o + 32 < len; i++) {
    const hpoint_t *p = &g_hist[(start + i) % HIST_N];
    o += (size_t)snprintf(b + o, len - o, "%s[", i ? "," : "");
    jint(b, len, &o, p->cpu); b[o++] = ',';
    jint(b, len, &o, p->soc); b[o++] = ',';
    jint(b, len, &o, p->duty); b[o++] = ',';
    jint(b, len, &o, p->tgt); b[o++] = ']';
  }
  pthread_mutex_unlock(&g_lock);
  if(o + 3 >= len) { free(b); return NULL; }
  b[o++] = ']'; b[o++] = '}'; b[o] = 0;
  return b;
}
