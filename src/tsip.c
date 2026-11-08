/* ps5share - IP de Tailscale de la consola
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   El payload de Tailscale para PS5 funciona en espacio de usuario: no crea
   ninguna interfaz de red, así que la IP 100.x.y.z no aparece en
   getifaddrs().  Se intenta, por orden:
     1. una interfaz con IP de Tailscale (por si algún día la hay);
     2. la API de estado del payload (http://127.0.0.1:8090/api/status,
        clave "ips").  No se usa su registro: solo trae IP de otros equipos.
   El resultado se guarda unos minutos. */

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "io.h"
#include "tsip.h"

#define TS_WEB_PORT  8090
#define TS_CACHE_OK  300
#define TS_CACHE_NO  30


static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char   g_ip[INET_ADDRSTRLEN];
static time_t g_when;


/* ¿Es una IP de Tailscale (100.64.0.0/10)? */
static int
is_cgnat(uint32_t host_order) {
  return (host_order & 0xffc00000u) == 0x64400000u;
}


/* Busca la primera IP 100.64/10 en TEXT a partir de START. */
static const char *
find_ip(const char *text, const char *start, char *out, size_t outlen) {
  for(const char *p = start; (p = strstr(p, "100.")); p++) {
    if(p > text && ((p[-1] >= '0' && p[-1] <= '9') || p[-1] == '.')) continue;
    char buf[INET_ADDRSTRLEN];
    size_t n = 0;
    while(n < sizeof(buf) - 1 && ((p[n] >= '0' && p[n] <= '9') || p[n] == '.')) {
      buf[n] = p[n];
      n++;
    }
    buf[n] = 0;
    while(n && buf[n-1] == '.') buf[--n] = 0;
    struct in_addr a;
    if(inet_pton(AF_INET, buf, &a) == 1 && is_cgnat(ntohl(a.s_addr))) {
      snprintf(out, outlen, "%s", buf);
      return p;
    }
  }
  return NULL;
}


/* Busca la IP propia en la respuesta JSON del payload de Tailscale.  Solo
   se aceptan las claves de la IP del propio equipo: la respuesta también
   trae las IP de los demás dispositivos de la red ("peers"). */
static int
pick_ip(const char *text, char *out, size_t outlen) {
  static const char *keys[] = {
    "\"ips\":", "\"TailscaleIPs\":", "\"tailscale_ip\":", "\"tailscaleIPs\":", "\"selfIP\":",
  };
  for(size_t i=0; i<sizeof(keys)/sizeof(keys[0]); i++) {
    const char *k = strstr(text, keys[i]);
    if(!k) continue;
    /* Solo dentro del valor de esa clave (hasta el cierre de la lista o la coma). */
    const char *v = k + strlen(keys[i]);
    while(*v == ' ') v++;
    const char *end = *v == '[' ? strchr(v, ']') : strpbrk(v, ",}");
    if(!end) continue;
    size_t n = (size_t)(end - v);
    char buf[512];
    if(n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, v, n);
    buf[n] = 0;
    if(find_ip(buf, buf, out, outlen)) return 0;
  }
  return -1;
}


static int
from_ifaddrs(char *out, size_t outlen) {
  struct ifaddrs *ifa = NULL;
  int r = -1;
  if(getifaddrs(&ifa)) return -1;
  for(struct ifaddrs *i = ifa; i && r; i = i->ifa_next) {
    if(!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
    struct in_addr a = ((struct sockaddr_in*)i->ifa_addr)->sin_addr;
    if(is_cgnat(ntohl(a.s_addr))) {
      inet_ntop(AF_INET, &a, out, (socklen_t)outlen);
      r = 0;
    }
  }
  freeifaddrs(ifa);
  return r;
}


static int
http_get_local(uint16_t port, const char *path, char *buf, size_t buflen) {
  struct sockaddr_in sa = {0};
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) return -1;
  io_sock_timeouts(fd, 2);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(connect(fd, (struct sockaddr*)&sa, sizeof(sa))) {
    close(fd);
    return -1;
  }
  char req[256];
  int n = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n"
                   "Accept: application/json, text/html\r\nConnection: close\r\n\r\n", path);
  if(io_writeall(fd, req, (size_t)n)) {
    close(fd);
    return -1;
  }
  size_t have = 0;
  for(;;) {
    if(have + 1 >= buflen) break;
    ssize_t r = recv(fd, buf + have, buflen - 1 - have, 0);
    if(r <= 0) break;
    have += (size_t)r;
  }
  close(fd);
  buf[have] = 0;
  if(have < 12 || strncmp(buf, "HTTP/1.", 7) || strncmp(buf + 9, "200", 3)) return -1;
  return 0;
}


static int
from_web(char *out, size_t outlen) {
  static const char *paths[] = {"/api/status", "/status", "/api/state"};
  size_t cap = 256 * 1024;
  char *buf = malloc(cap);
  int r = -1;
  if(!buf) return -1;
  for(size_t i=0; i<sizeof(paths)/sizeof(paths[0]) && r; i++) {
    if(http_get_local(TS_WEB_PORT, paths[i], buf, cap)) continue;
    char *body = strstr(buf, "\r\n\r\n");
    if(body && !pick_ip(body, out, outlen)) r = 0;
  }
  free(buf);
  return r;
}


void
tsip_get(char *out, size_t outlen) {
  time_t now = time(NULL);
  char ip[INET_ADDRSTRLEN] = "";

  pthread_mutex_lock(&g_lock);
  if(g_when && now - g_when < (g_ip[0] ? TS_CACHE_OK : TS_CACHE_NO)) {
    snprintf(out, outlen, "%s", g_ip);
    pthread_mutex_unlock(&g_lock);
    return;
  }
  pthread_mutex_unlock(&g_lock);

  if(from_ifaddrs(ip, sizeof(ip)) && from_web(ip, sizeof(ip))) {
    ip[0] = 0;
  }

  pthread_mutex_lock(&g_lock);
  snprintf(g_ip, sizeof(g_ip), "%s", ip);
  g_when = now;
  pthread_mutex_unlock(&g_lock);
  snprintf(out, outlen, "%s", ip);
}
