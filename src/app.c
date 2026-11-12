/* ps5share - arranque común a PS5 y Linux
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "app.h"
#include "config.h"
#include "ftp.h"
#include "http.h"
#include "sftp.h"
#include "tls.h"
#include "vault.h"
#include "log.h"


static void*
sftp_thread(void *arg) {
  for(;;) {
    cfg_lock();
    uint16_t port = cfg_settings()->sftp_port;
    cfg_unlock();
    sftp_serve(port);
    sleep(5);
  }
  return NULL;
}


static void*
https_thread(void *arg) {
  http_serve_tls();
  return NULL;
}


static void*
ftp_thread(void *arg) {
  for(;;) {
    cfg_lock();
    uint16_t port = cfg_settings()->ftp_port;
    cfg_unlock();
    ftp_serve(port);
    sleep(5);
  }
  return NULL;
}


/* Devuelve la primera IPv4 que no sea loopback, o "" si aún no hay red. */
static void
first_ip(char *out, size_t outlen) {
  struct ifaddrs *ifa = NULL;
  out[0] = 0;
  if(getifaddrs(&ifa)) return;
  for(struct ifaddrs *i = ifa; i; i = i->ifa_next) {
    if(!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
    if(!strncmp(i->ifa_name, "lo", 2)) continue;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in*)i->ifa_addr)->sin_addr, ip, sizeof(ip));
    if(!strncmp(ip, "0.", 2) || !strncmp(ip, "127.", 4)) continue;
    snprintf(out, outlen, "%s", ip);
    break;
  }
  freeifaddrs(ifa);
}


int
app_run(const char *confdir, void (*notify_fn)(const char *msg)) {
  char ip[INET_ADDRSTRLEN];
  char msg[512];
  pthread_t t;
  pthread_attr_t attr;

  signal(SIGPIPE, SIG_IGN);

  if(cfg_init(confdir)) {
    LOG_PUTS("ps5share: no se pudo cargar la configuración");
    return -1;
  }

  /* Espera a tener red (al arrancar la consola puede tardar). */
  for(int i=0; i<200; i++) {
    first_ip(ip, sizeof(ip));
    if(ip[0]) break;
    sleep(3);
  }

  cfg_lock();
  settings_t s = *cfg_settings();
  int setup = cfg_nusers() == 0;
  cfg_unlock();

  int sftp_ok = s.sftp_enabled && !sftp_init(confdir);
  vault_init(confdir);
  int tls_ok = !tls_init(confdir);

  int n = snprintf(msg, sizeof(msg), "PS5NAS %s\nWeb: http://%s:%u",
                   VERSION_TAG, ip[0] ? ip : "?", s.http_port);
  if(sftp_ok) n += snprintf(msg + n, sizeof(msg) - n, "\nSFTP: %s:%u", ip[0] ? ip : "?", s.sftp_port);
  if(s.ftp_enabled) n += snprintf(msg + n, sizeof(msg) - n, "\nFTP: %s:%u", ip[0] ? ip : "?", s.ftp_port);
  if(tls_ok && s.https_enabled && s.vault_enabled) {
    n += snprintf(msg + n, sizeof(msg) - n, "\nContraseñas: https://%s:%u", ip[0] ? ip : "?",
                  s.https_port);
  }
  if(setup) snprintf(msg + n, sizeof(msg) - n, "\nAbre la web para crear el administrador");
  LOG_PRINTF("%s\n", msg);
  if(notify_fn) notify_fn(msg);

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, 512 * 1024);
  if(sftp_ok) pthread_create(&t, &attr, sftp_thread, NULL);
  if(s.ftp_enabled) pthread_create(&t, &attr, ftp_thread, NULL);
  if(tls_ok) pthread_create(&t, &attr, https_thread, NULL);
  pthread_attr_destroy(&attr);

  for(;;) {
    cfg_lock();
    uint16_t port = cfg_settings()->http_port;
    cfg_unlock();
    http_serve(port);
    sleep(5);
  }
  return 0;
}
