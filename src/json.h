/* ps5share - lector JSON mínimo (respuestas de la API de Spotify)
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#pragma once

#include <stddef.h>

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype_t;

typedef struct jv {
  jtype_t     type;
  char       *key;      /* nombre del campo si está dentro de un objeto */
  char       *str;      /* J_STR (UTF-8, ya sin escapes) */
  double      num;      /* J_NUM y J_BOOL */
  struct jv  *child;    /* J_ARR / J_OBJ: primer elemento */
  struct jv  *next;     /* siguiente hermano */
} jv_t;

/* Devuelve el árbol o NULL si el texto no es JSON válido. */
jv_t       *json_parse(const char *s, size_t len);
void        json_free(jv_t *v);

/* Accesos tolerantes: con V NULL o del tipo equivocado devuelven NULL/0/"". */
jv_t       *json_get(const jv_t *obj, const char *key);
/* Ruta con puntos: "item.album.name" */
jv_t       *json_path(const jv_t *obj, const char *path);
const char *json_str(const jv_t *v);
double      json_num(const jv_t *v);
int         json_count(const jv_t *arr);
