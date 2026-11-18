/* Prueba del control del ventilador con una consola simulada y un reloj falso. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
int sim_cpu = 60, sim_target = 91, sim_writes = 0;
static time_t fake_now = 1000000;
#define time(x) (fake_now)
#include "../src/fan.c"
#undef time
static int fails = 0;
#define CHECK(c, ...) do { if(!(c)) { printf("FALLO: " __VA_ARGS__); printf("\n"); fails++; } } while(0)
static void run(int secs) { for(int i=0;i<secs;i+=2){ fake_now+=2; tick(); } }
int main(void) {
  char err[64];
  snprintf(g_path, sizeof g_path, "/tmp/fan-sim.conf"); unlink(g_path);
  sim_target = 65; run(4); CHECK(g_stock == 91 && sim_target == 91, "migración desde la versión anterior: stock %d, objetivo %d", g_stock, sim_target);
  run(4); CHECK(g_stock == 91, "stock %d", g_stock); CHECK(sim_target == 91, "quiet toca: %d", sim_target);
  fan_configure(FAN_MODE_COOL, -1, -1, err, sizeof err);
  run(22); CHECK(sim_target == 90, "primer paso %d", sim_target);
  run(20); CHECK(sim_target == 89, "1 grado/20s: %d", sim_target);
  run(200); CHECK(sim_target == 85, "llega a 85: %d", sim_target);
  fan_configure(FAN_MODE_BALANCED, -1, -1, err, sizeof err);
  run(2); CHECK(sim_target == 88, "sube de golpe a 88: %d", sim_target);
  fan_configure(FAN_MODE_MANUAL, 60, -1, err, sizeof err); /* rechazado: < 70 */
  CHECK(g_mode == FAN_MODE_BALANCED, "manual 60 debería rechazarse");
  fan_configure(FAN_MODE_MANUAL, 95, -1, err, sizeof err);
  run(2); CHECK(sim_target == 91, "manual 95 limitado al de la consola: %d", sim_target);
  fan_configure(FAN_MODE_COOL, -1, -1, err, sizeof err); run(60);
  int w = sim_target;
  sim_target = 72; run(4);  /* otra app lo baja más */
  CHECK(g_other == 1, "detecta otra app"); run(60); CHECK(sim_target == 72, "no se pelea: %d", sim_target);
  sim_target = 91; run(4); CHECK(g_other == 0, "la otra app lo devolvió");
  run(200); CHECK(sim_target == 85, "vuelve a bajar a 85: %d", sim_target);
  sim_target = 91; run(2); CHECK(sim_target == 91, "espera tras recarga: %d", sim_target); run(22); CHECK(g_stock == 91 && sim_target == 90, "la consola recarga (juego): %d", sim_target);
  /* cuelgue: reinicio con el objetivo bajado */
  run(200); CHECK(sim_target == 85, "85 antes de cuelgue");
  g_stock = -1; g_written = -1; g_saved_stock = g_saved_written = -1; load_conf();
  run(2); CHECK(g_stock == 91, "tras cuelgue recuerda stock 91: %d", g_stock);
  fan_configure(FAN_MODE_QUIET, -1, -1, err, sizeof err);
  run(2); CHECK(sim_target == 91, "silencioso devuelve 91: %d", sim_target);
  /* consola con objetivo propio bajo: no se baja de 70 ni por encima de stock */
  sim_target = 72; g_stock = -1; g_written = -1; unlink(g_path); g_saved_stock = g_saved_written = -1;
  fan_configure(FAN_MODE_COOL, -1, -1, err, sizeof err); run(300);
  CHECK(sim_target == 70, "suelo 70: %d", sim_target);
  (void)w;
  char *j = fan_status_json(); CHECK(j && strstr(j, "\"mode\":\"cool\""), "json"); free(j);
  printf(fails ? "%d FALLOS\n" : "todo bien\n", fails);
  return fails != 0;
}
