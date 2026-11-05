/* ps5share - punto de entrada para PS5 (payload ELF)
   Copyright (C) 2026  ps5share contributors.
   Basado en main-prospero.c de ftpsrv (C) 2025 John Törnblom.
   GPLv3, ver LICENSE.  */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/sysctl.h>
#include <sys/syscall.h>

#include <ps5/kernel.h>

#include "app.h"
#include "config.h"
#include "log.h"
#include "notify.h"

#define DEFAULT_CONFDIR "/data/ps5share"


/* Busca el pid de un proceso por el nombre de su hilo (como ftpsrv). */
static pid_t
find_pid(const char *name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) return -1;
  if(!(buf = malloc(buf_size))) return -1;
  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    free(buf);
    return -1;
  }

  for(uint8_t *ptr = buf; ptr < (buf + buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    if(ki_structsize <= 0) break;
    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && ki_pid != mypid) pid = ki_pid;
  }

  free(buf);
  return pid;
}


static void
kill_all(const char *name) {
  pid_t pid;
  for(int i=0; i<10 && (pid = find_pid(name)) > 0; i++) {
    LOG_PRINTF("ps5share: deteniendo %s (pid %d)\n", name, pid);
    kill(pid, SIGKILL);
    sleep(1);
  }
}


static void
notify_cb(const char *msg) {
  notify("%s", msg);
}


int
main(int argc, char *argv[]) {
  const char *dir = DEFAULT_CONFDIR;
  int c;

  syscall(SYS_thr_set_name, -1, "ps5share.elf");

  while((c = getopt(argc, argv, "d:h")) != -1) {
    switch(c) {
    case 'd': dir = optarg; break;
    default:
      printf("uso: %s [-d CARPETA_CONFIG]\n", argv[0]);
      return EXIT_FAILURE;
    }
  }

  /* Solo una instancia de ps5share. */
  kill_all("ps5share.elf");

  /* El ftpsrv original no tiene contraseña y daría acceso a todo el
     disco a cualquiera que llegue por Tailscale, así que lo paramos. */
  cfg_init(dir);
  cfg_lock();
  int kill_ftpsrv = cfg_settings()->kill_ftpsrv;
  cfg_unlock();
  if(kill_ftpsrv) kill_all("ftpsrv.elf");

  /* Mismo AuthID que ftpsrv para poder acceder a todo el almacenamiento. */
  if(kernel_set_ucred_authid(getpid(), 0x4801000000000013L)) {
    LOG_PUTS("ps5share: no se pudo cambiar el AuthID");
  }

  return app_run(dir, notify_cb) ? EXIT_FAILURE : EXIT_SUCCESS;
}
