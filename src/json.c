/* ps5share - lector JSON mínimo
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <stdlib.h>
#include <string.h>

#include "json.h"

#define JSON_MAX_DEPTH 64

typedef struct jp {
  const char *s, *e;
  int depth;
} jp_t;


static void
ws(jp_t *p) {
  while(p->s < p->e && (*p->s == ' ' || *p->s == '\t' || *p->s == '\n' || *p->s == '\r')) p->s++;
}


static int
hex4(const char *s, unsigned *out) {
  unsigned v = 0;
  for(int i=0; i<4; i++) {
    char c = s[i];
    v <<= 4;
    if(c >= '0' && c <= '9') v |= (unsigned)(c - '0');
    else if(c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
    else if(c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
    else return -1;
  }
  *out = v;
  return 0;
}


static size_t
utf8(unsigned cp, char *o) {
  if(cp < 0x80) { o[0] = (char)cp; return 1; }
  if(cp < 0x800) { o[0] = (char)(0xc0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 63)); return 2; }
  if(cp < 0x10000) {
    o[0] = (char)(0xe0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 63));
    o[2] = (char)(0x80 | (cp & 63)); return 3;
  }
  o[0] = (char)(0xf0 | (cp >> 18)); o[1] = (char)(0x80 | ((cp >> 12) & 63));
  o[2] = (char)(0x80 | ((cp >> 6) & 63)); o[3] = (char)(0x80 | (cp & 63)); return 4;
}


static char *
pstring(jp_t *p) {
  if(p->s >= p->e || *p->s != '"') return NULL;
  p->s++;
  const char *start = p->s;
  /* el texto decodificado nunca es más largo que el original */
  while(p->s < p->e && *p->s != '"') {
    if(*p->s == '\\') p->s++;
    p->s++;
  }
  if(p->s >= p->e) return NULL;
  size_t n = (size_t)(p->s - start);
  p->s++;
  char *out = malloc(n + 1), *o = out;
  if(!out) return NULL;
  for(const char *c = start; c < start + n; c++) {
    if(*c != '\\') { *o++ = *c; continue; }
    c++;
    switch(*c) {
    case 'n': *o++ = '\n'; break;
    case 't': *o++ = '\t'; break;
    case 'r': *o++ = '\r'; break;
    case 'b': *o++ = '\b'; break;
    case 'f': *o++ = '\f'; break;
    case 'u': {
      unsigned cp, lo;
      if(c + 4 >= start + n || hex4(c + 1, &cp)) { free(out); return NULL; }
      c += 4;
      if(cp >= 0xd800 && cp < 0xdc00 && c + 6 < start + n && c[1] == '\\' && c[2] == 'u' &&
         !hex4(c + 3, &lo) && lo >= 0xdc00 && lo < 0xe000) {
        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        c += 6;
      }
      o += utf8(cp, o);
      break;
    }
    default: *o++ = *c;
    }
  }
  *o = 0;
  return out;
}


static jv_t *pvalue(jp_t *p);


static jv_t *
pcontainer(jp_t *p, char close, int obj) {
  jv_t *v = calloc(1, sizeof(*v)), *last = NULL;
  if(!v) return NULL;
  v->type = obj ? J_OBJ : J_ARR;
  if(++p->depth > JSON_MAX_DEPTH) goto fail;
  p->s++;
  ws(p);
  if(p->s < p->e && *p->s == close) { p->s++; p->depth--; return v; }
  for(;;) {
    char *key = NULL;
    ws(p);
    if(obj) {
      if(!(key = pstring(p))) goto fail;
      ws(p);
      if(p->s >= p->e || *p->s != ':') { free(key); goto fail; }
      p->s++;
    }
    jv_t *c = pvalue(p);
    if(!c) { free(key); goto fail; }
    c->key = key;
    if(last) last->next = c; else v->child = c;
    last = c;
    ws(p);
    if(p->s < p->e && *p->s == ',') { p->s++; continue; }
    if(p->s < p->e && *p->s == close) { p->s++; break; }
    goto fail;
  }
  p->depth--;
  return v;
 fail:
  json_free(v);
  return NULL;
}


static jv_t *
pvalue(jp_t *p) {
  ws(p);
  if(p->s >= p->e) return NULL;
  char c = *p->s;
  if(c == '{') return pcontainer(p, '}', 1);
  if(c == '[') return pcontainer(p, ']', 0);
  jv_t *v = calloc(1, sizeof(*v));
  if(!v) return NULL;
  if(c == '"') {
    v->type = J_STR;
    if(!(v->str = pstring(p))) { free(v); return NULL; }
  } else if(p->e - p->s >= 4 && !strncmp(p->s, "true", 4)) {
    v->type = J_BOOL; v->num = 1; p->s += 4;
  } else if(p->e - p->s >= 5 && !strncmp(p->s, "false", 5)) {
    v->type = J_BOOL; p->s += 5;
  } else if(p->e - p->s >= 4 && !strncmp(p->s, "null", 4)) {
    v->type = J_NULL; p->s += 4;
  } else if(c == '-' || (c >= '0' && c <= '9')) {
    char tmp[64];
    size_t n = 0;
    while(p->s < p->e && n < sizeof(tmp) - 1 && strchr("+-0123456789.eE", *p->s)) tmp[n++] = *p->s++;
    tmp[n] = 0;
    v->type = J_NUM;
    v->num = strtod(tmp, NULL);
  } else {
    free(v);
    return NULL;
  }
  return v;
}


jv_t *
json_parse(const char *s, size_t len) {
  if(!s) return NULL;
  jp_t p = {s, s + len, 0};
  jv_t *v = pvalue(&p);
  if(!v) return NULL;
  ws(&p);
  if(p.s != p.e) { json_free(v); return NULL; }
  return v;
}


void
json_free(jv_t *v) {
  while(v) {
    jv_t *n = v->next;
    json_free(v->child);
    free(v->key);
    free(v->str);
    free(v);
    v = n;
  }
}


jv_t *
json_get(const jv_t *obj, const char *key) {
  if(!obj || obj->type != J_OBJ) return NULL;
  for(jv_t *c = obj->child; c; c = c->next) if(c->key && !strcmp(c->key, key)) return c;
  return NULL;
}


jv_t *
json_path(const jv_t *obj, const char *path) {
  char part[64];
  const jv_t *v = obj;
  while(v && *path) {
    const char *dot = strchr(path, '.');
    size_t l = dot ? (size_t)(dot - path) : strlen(path);
    if(l >= sizeof(part)) return NULL;
    memcpy(part, path, l);
    part[l] = 0;
    v = json_get(v, part);
    path += l + (dot ? 1 : 0);
  }
  return (jv_t*)v;
}


const char *
json_str(const jv_t *v) {
  return v && v->type == J_STR ? v->str : "";
}


double
json_num(const jv_t *v) {
  return v && (v->type == J_NUM || v->type == J_BOOL) ? v->num : 0;
}


int
json_count(const jv_t *arr) {
  int n = 0;
  if(!arr || (arr->type != J_ARR && arr->type != J_OBJ)) return 0;
  for(jv_t *c = arr->child; c; c = c->next) n++;
  return n;
}
