/* ps5share - vigilancia de temperatura y control del ventilador
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Lectura de sensores basada en Breeze (https://github.com/MiladRTX/Breeze,
   GPLv3, (C) Milad).  Los modos son los de Machete IA / PS5SD
   (ps5/fan/fan_policy.h, GPLv3), que a su vez siguen drakmor/fan_target:

   - La consola acelera el ventilador para no pasar de su «objetivo» de
     temperatura (/dev/icc_fan, objeto autoservo, canal 0).  El de fábrica
     suele ser 91 °C.  Los modos solo bajan ese objetivo; quien decide la
     velocidad sigue siendo la consola.
   - Silencioso: el de la consola.  Equilibrado: 3 °C menos.  Frío: 6 °C
     menos.  Manual: el que elijas (70-95 °C, nunca por encima del de la
     consola).  Ningún modo baja de 70 °C.
   - Se baja un grado cada 20 s (bajarlo de golpe pone el ventilador al
     máximo en dos segundos) y se sube de golpe.
   - Si la consola sube su objetivo (al abrir o cerrar un juego), ese es el
     nuevo de fábrica.  Si otra app lo baja por debajo del nuestro, PS5NAS no
     se pelea con ella hasta que lo vuelva a subir.
   - El de fábrica y el último escrito se guardan en fan.conf, así tras un
     cuelgue se sabe a qué valor volver.  */

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
#define FAN_STEP_S    20      /* se baja un grado cada 20 s */

typedef struct {
  int16_t cpu, soc, duty, tgt;   /* -1: sin dato; tgt en °C */
} hpoint_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_path[512];

/* Ajustes */
static int g_mode = FAN_MODE_QUIET;
static int g_manual = 85;
static int g_notify = 1;
static int g_saved_stock = -1, g_saved_written = -1;   /* de fan.conf (tras un cuelgue) */
static int g_conf_new = 0;       /* fan.conf ya es del formato con modos de Machete */

/* Lecturas */
static int g_sensors = 0, g_icc = 0;
static int g_cpu = -1, g_soc = -1, g_duty = -1, g_tgt = -1;  /* g_tgt en 1/256 °C */

/* Control (en °C) */
static int g_stock = -1;         /* objetivo de la consola */
static int g_written = -1;       /* lo último que escribimos, si está por debajo del de fábrica */
static int g_wanted = -1;        /* lo que pide el modo */
static int g_other = 0;          /* otra app lo ha bajado más: no se toca */
static time_t g_last_step = 0;
static time_t g_hot_warned = 0;

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

#elif defined(FAN_SIM)  /* pruebas: consola simulada (test/fan_sim.c) */

extern int sim_cpu, sim_target, sim_writes;
static void hw_read(int *cpu, int *soc, int *duty) { *cpu = sim_cpu; *soc = sim_cpu - 10; *duty = 50; }
#define ICC_BUF 32
static int  hw_target(unsigned char *obj) { (void)obj; return sim_target * 256; }
static int  hw_set_target(int c256) { sim_target = c256 / 256; sim_writes++; return 0; }

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

/* Un objetivo «de consola»: grados enteros entre 60 y 100. */
static int
stock_ok(int c) {
  return c >= 60 && c <= 100;
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
    if(!strcmp(line, "fanmode") && v >= 0 && v <= 3) { g_mode = v; g_conf_new = 1; }
    else if(!strcmp(line, "manual")) g_manual = clampi(v, FAN_LOWEST_C, FAN_TOP_C);
    else if(!strcmp(line, "notify")) g_notify = v != 0;
    else if(!strcmp(line, "stockc") && stock_ok(v)) g_saved_stock = v;
    else if(!strcmp(line, "written") && stock_ok(v)) g_saved_written = v;
  }
  fclose(f);
}

static int
save_conf(void) {
  char tmp[sizeof(g_path) + 8];
  snprintf(tmp, sizeof(tmp), "%s.tmp", g_path);
  FILE *f = fopen(tmp, "w");
  if(!f) return -1;
  fprintf(f, "fanmode=%d\nmanual=%d\nnotify=%d\n", g_mode, g_manual, g_notify);
  /* Solo mientras hay un objetivo nuestro por debajo del de fábrica. */
  if(g_stock > 0 && g_written > 0 && g_written < g_stock)
    fprintf(f, "stockc=%d\nwritten=%d\n", g_stock, g_written);
  if(fclose(f)) return -1;
  return rename(tmp, g_path);
}


/* ------------------------------------------------------------------ */
/* Control                                                             */
/* ------------------------------------------------------------------ */

/* El objetivo que pide un modo (igual que fan_wanted de Machete). */
static int
wanted_for(int mode, int manual, int stock) {
  int w = stock;
  if(mode == FAN_MODE_BALANCED) w = stock - 3;
  else if(mode == FAN_MODE_COOL) w = stock - 6;
  else if(mode == FAN_MODE_MANUAL) w = manual;
  if(w > stock) w = stock;
  if(w < FAN_LOWEST_C) w = stock < FAN_LOWEST_C ? stock : FAN_LOWEST_C;
  return w;
}

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

static void
tick(void) {
  int cpu, soc, duty;
  unsigned char obj[ICC_BUF];
  time_t now = time(NULL);

  hw_read(&cpu, &soc, &duty);
  int raw = hw_target(obj);
  int cur = raw >= 0 ? (raw + 128) / 256 : -1;

  pthread_mutex_lock(&g_lock);
  g_cpu = cpu; g_soc = soc; g_duty = duty; g_tgt = raw;
  g_sensors = cpu >= 0 || soc >= 0;
  g_icc = raw >= 0;
  int hot = cpu > soc ? cpu : soc;

  if(g_icc) {
    if(g_stock < 0) {
      /* Arranque: si sigue puesto lo que dejamos antes de un cuelgue, el de
         fábrica es el que apuntamos entonces. */
      if(g_saved_written > 0 && cur == g_saved_written && g_saved_stock > cur) {
        g_stock = g_saved_stock;
        g_written = cur;
      } else if(!g_conf_new && cur > 0 && cur < 91) {
        /* La versión anterior (protección automática) pudo dejar su objetivo
           bajado: se toma como nuestro y el de fábrica, 91 °C. */
        g_stock = 91;
        g_written = cur;
        g_conf_new = 1;
        save_conf();
      } else {
        g_stock = stock_ok(cur) ? cur : 91;
      }
      LOG_PRINTF("ps5share: objetivo de fábrica del ventilador %d °C (ahora %d °C)\n", g_stock, cur);
    } else if(g_written > 0 && cur != g_written) {
      if(cur > g_written) {
        /* La consola ha recargado su valor (juego abierto o cerrado). */
        if(stock_ok(cur)) g_stock = cur;
        g_written = -1;
        g_other = 0;
        g_last_step = now;
      } else {
        /* Otra app lo ha bajado más: no se pelea. */
        g_written = -1;
        g_other = 1;
      }
    } else if(g_other && g_written < 0 && cur >= g_stock) {
      g_other = 0;   /* la otra app lo ha devuelto */
    } else if(g_written < 0 && !g_other && cur > g_stock && stock_ok(cur)) {
      g_stock = cur;
    }

    g_wanted = wanted_for(g_mode, g_manual, g_stock);
    if(!g_other) {
      int next = cur;
      if(g_wanted > cur) next = g_wanted;                                   /* subir: ya */
      else if(g_wanted < cur && now - g_last_step >= FAN_STEP_S) next = cur - 1;  /* bajar: de uno en uno */
      /* Solo se toca un objetivo que es el de fábrica o el nuestro. */
      if(next != cur && (cur == g_stock || cur == g_written || g_written < 0)) {
        if(!hw_set_target(next * 256)) {
          unsigned char back[ICC_BUF];
          int chk = hw_target(back);
          if(chk >= 0 && (chk + 128) / 256 == next) {
            g_written = next < g_stock ? next : -1;
            g_tgt = chk;
            cur = next;
            g_last_step = now;
            save_conf();
          }
        }
      }
    }
  }

  /* Aviso si se calienta mucho (una vez cada hora como mucho). */
  if(hot >= FAN_HOT_C && now - g_hot_warned >= 3600) {
    g_hot_warned = now;
    pthread_mutex_unlock(&g_lock);
    say("la consola está a %d °C", hot);
    pthread_mutex_lock(&g_lock);
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
    p->tgt = (int16_t)cur;
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
fan_mode_from(const char *s) {
  static const char *const names[] = {"quiet", "balanced", "cool", "manual"};
  for(int i=0; i<4; i++) if(s && !strcmp(s, names[i])) return i;
  return -1;
}


int
fan_configure(int mode, int manual_c, int notify_on, char *err, size_t errlen) {
  pthread_mutex_lock(&g_lock);
  if(mode > 3 || (manual_c >= 0 && (manual_c < FAN_LOWEST_C || manual_c > FAN_TOP_C))) {
    pthread_mutex_unlock(&g_lock);
    snprintf(err, errlen, mode > 3 ? "Modo no válido" : "Temperaturas no válidas");
    return -1;
  }
  if(mode >= 0) g_mode = mode;
  if(manual_c >= 0) g_manual = manual_c;
  if(notify_on >= 0) g_notify = notify_on != 0;
  g_other = 0;   /* al elegir un modo, se vuelve a aplicar */
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
  static const char *const names[] = {"quiet", "balanced", "cool", "manual"};
  size_t len = 4096 + (size_t)HIST_N * 24;
  char *b = malloc(len);
  size_t o = 0;
  if(!b) return NULL;

  pthread_mutex_lock(&g_lock);
  int cur = g_tgt >= 0 ? (g_tgt + 128) / 256 : -1;
  const char *state = !g_icc ? "noicc"
                    : g_other ? "other"
                    : g_mode == FAN_MODE_QUIET ? "quiet"
                    : cur > g_wanted ? "lowering" : "holding";
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
  jint(b, len, &o, cur);
  o += (size_t)snprintf(b + o, len - o, ",\"stock\":");
  jint(b, len, &o, g_stock);
  o += (size_t)snprintf(b + o, len - o, ",\"wanted\":");
  jint(b, len, &o, g_wanted);
  o += (size_t)snprintf(b + o, len - o,
        ",\"mode\":\"%s\",\"manual\":%d,\"notify\":%s,\"state\":\"%s\",\"step_s\":%d,"
        "\"lowest_c\":%d,\"top_c\":%d,\"hot_c\":%d,\"max24\":",
        names[g_mode], g_manual, g_notify ? "true" : "false", state, FAN_STEP_S,
        FAN_LOWEST_C, FAN_TOP_C, FAN_HOT_C);
  jint(b, len, &o, max24);
  o += (size_t)snprintf(b + o, len - o, ",\"hist_step\":%d,\"hist_end\":%lld,\"hist\":[",
                        HIST_STEP_S, (long long)g_hend);
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
