/* ps5share - punto de entrada para Linux (pruebas)
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "app.h"


int
main(int argc, char *argv[]) {
  const char *dir = "./ps5share-data";
  int c;

  while((c = getopt(argc, argv, "d:h")) != -1) {
    switch(c) {
    case 'd': dir = optarg; break;
    default:
      printf("uso: %s [-d CARPETA_CONFIG]\n", argv[0]);
      return EXIT_FAILURE;
    }
  }
  return app_run(dir, NULL) ? EXIT_FAILURE : EXIT_SUCCESS;
}
