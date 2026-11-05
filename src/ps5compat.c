/* ps5share - funciones que faltan en la libc de la PS5
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

/* wolfSSL usa accept4() al ver FreeBSD >= 10, pero la PS5 no la exporta. */
int
accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags) {
  int fd = accept(s, addr, addrlen);
  if(fd >= 0 && (flags & SOCK_CLOEXEC)) {
    fcntl(fd, F_SETFD, FD_CLOEXEC);
  }
  return fd;
}
