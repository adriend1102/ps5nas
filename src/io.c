/* ps5share - utilidades de E/S
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "io.h"


int
io_writeall(int fd, const void *buf, size_t n) {
  const char *p = buf;
  while(n > 0) {
    ssize_t w = write(fd, p, n);
    if(w < 0) {
      if(errno == EINTR) continue;
      return -1;
    }
    if(w == 0) {
      errno = EPIPE;
      return -1;
    }
    p += w;
    n -= (size_t)w;
  }
  return 0;
}


int
io_copy(int fd_in, int fd_out, size_t n, void *buf, size_t buflen) {
  while(n > 0) {
    size_t want = n < buflen ? n : buflen;
    ssize_t r = read(fd_in, buf, want);
    if(r < 0) {
      if(errno == EINTR) continue;
      return -1;
    }
    if(r == 0) {
      return (n == (size_t)-1) ? 0 : 0;   /* EOF: el archivo pudo encogerse */
    }
    if(io_writeall(fd_out, buf, (size_t)r)) return -1;
    if(n != (size_t)-1) n -= (size_t)r;
  }
  return 0;
}


int
io_wait_readable(int fd, int timeout_ms) {
  struct pollfd pfd;
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = fd;
  pfd.events = POLLIN;
  for(;;) {
    int r = poll(&pfd, 1, timeout_ms);
    if(r < 0 && errno == EINTR) continue;
    return r < 0 ? -1 : (r > 0 ? 1 : 0);
  }
}


void
io_sock_timeouts(int fd, int seconds) {
  struct timeval tv;
  tv.tv_sec = seconds;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}
