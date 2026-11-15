/* ps5share - biblioteca de música de las playlists de Spotify
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.  */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "io.h"
#include "library.h"
#include "log.h"

#define INBOX     "Entrada"
#define DUPS      "_duplicados"
#define LISTS     "Listas"
#define TAG_MAX   (512 * 1024)


static const char *MONTHS[] = {
  "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio",
  "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"
};


const char *
lib_month_name(int m) {
  return (m >= 1 && m <= 12) ? MONTHS[m - 1] : "?";
}


static int
is_audio(const char *name) {
  static const char *ext[] = {".flac", ".mp3", ".m4a", ".alac", ".ogg", ".opus", ".wav", ".aac", ".aiff", ".wma"};
  const char *dot = strrchr(name, '.');
  if(!dot || name[0] == '.') return 0;
  for(size_t i=0; i<sizeof(ext)/sizeof(ext[0]); i++) if(!strcasecmp(dot, ext[i])) return 1;
  return 0;
}


/* ------------------------------------------------------------------ */
/* Normalización para comparar nombres                                 */
/* ------------------------------------------------------------------ */

/* U+00C0..U+00FF sin tildes ("" = se descarta). */
static const char *LATIN1[64] = {
  "a","a","a","a","a","a","ae","c","e","e","e","e","i","i","i","i",
  "d","n","o","o","o","o","o","","o","u","u","u","u","y","th","ss",
  "a","a","a","a","a","a","ae","c","e","e","e","e","i","i","i","i",
  "d","n","o","o","o","o","o","","o","u","u","u","u","y","th","y"
};


static void
norm(const char *s, size_t n, char *out, size_t outlen) {
  size_t o = 0;
  const unsigned char *p = (const unsigned char*)s, *e = p + n;
  while(p < e && *p && o + 4 < outlen) {
    if(*p < 0x80) {
      unsigned char c = *p++;
      if(c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
      if((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) out[o++] = (char)c;
    } else if(*p == 0xc3 && p + 1 < e && p[1] >= 0x80 && p[1] <= 0xbf) {
      const char *r = LATIN1[p[1] - 0x80];
      while(*r && o + 1 < outlen) out[o++] = *r++;
      p += 2;
    } else {
      out[o++] = (char)*p++;    /* otros alfabetos: tal cual */
    }
  }
  out[o] = 0;
}


/* Longitud de S hasta el primer separador de LIST (sin distinguir mayúsculas). */
static size_t
cut_at(const char *s, const char *const *list) {
  size_t best = strlen(s);
  for(const char *const *l = list; *l; l++) {
    const char *f = strcasestr(s, *l);
    if(f && (size_t)(f - s) < best && f != s) best = (size_t)(f - s);
  }
  return best;
}


void
lib_key(const char *artist, const char *title, int strip, char *out, size_t outlen) {
  static const char *const ASEP[] = {", ", ";", " & ", " feat", " ft.", " x ", " y ", NULL};
  static const char *const TSEP[] = {" - ", " (", " [", " feat", " ft.", NULL};
  char a[256], t[256];
  norm(artist, cut_at(artist, ASEP), a, sizeof(a));
  norm(title, strip ? cut_at(title, TSEP) : strlen(title), t, sizeof(t));
  snprintf(out, outlen, "%s|%s", a, t);
}


/* ------------------------------------------------------------------ */
/* Etiquetas                                                           */
/* ------------------------------------------------------------------ */

static void
set_tag(char *dst, size_t dstlen, const char *s, size_t n) {
  if(dst[0]) return;        /* nos quedamos con el primero */
  if(n >= dstlen) n = dstlen - 1;
  memcpy(dst, s, n);
  dst[n] = 0;
}


static uint32_t le32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }


static int
read_flac(int fd, char *artist, size_t al, char *title, size_t tl) {
  uint8_t h[4];
  if(read(fd, h, 4) != 4 || memcmp(h, "fLaC", 4)) return -1;
  for(int blocks = 0; blocks < 64; blocks++) {
    if(read(fd, h, 4) != 4) return -1;
    int type = h[0] & 0x7f, last = h[0] & 0x80;
    uint32_t len = ((uint32_t)h[1] << 16) | (h[2] << 8) | h[3];
    if(type == 4 && len < TAG_MAX) {
      uint8_t *b = malloc(len);
      if(!b) return -1;
      if(read(fd, b, len) == (ssize_t)len && len >= 8) {
        size_t o = 4 + le32(b);
        uint32_t cnt = o + 4 <= len ? le32(b + o) : 0;
        o += 4;
        for(uint32_t i=0; i<cnt && o + 4 <= len; i++) {
          uint32_t l = le32(b + o);
          o += 4;
          if(o + l > len) break;
          const char *c = (const char*)b + o;
          if(l > 7 && !strncasecmp(c, "ARTIST=", 7)) set_tag(artist, al, c + 7, l - 7);
          else if(l > 6 && !strncasecmp(c, "TITLE=", 6)) set_tag(title, tl, c + 6, l - 6);
          o += l;
        }
      }
      free(b);
      return 0;
    }
    if(last || lseek(fd, len, SEEK_CUR) < 0) break;
  }
  return 0;
}


/* Texto de un marco ID3v2 a UTF-8 (solo el primer valor). */
static void
id3_text(const uint8_t *b, size_t n, char *out, size_t outlen) {
  size_t o = 0;
  if(!n || out[0]) return;
  int enc = b[0];
  b++; n--;
  if(enc == 0 || enc == 3) {
    for(size_t i=0; i<n && b[i] && o + 3 < outlen; i++) {
      if(enc == 3 || b[i] < 0x80) out[o++] = (char)b[i];
      else { out[o++] = (char)(0xc0 | (b[i] >> 6)); out[o++] = (char)(0x80 | (b[i] & 63)); }
    }
  } else {
    int be = enc == 2;
    size_t i = 0;
    if(enc == 1 && n >= 2) {
      if(b[0] == 0xfe && b[1] == 0xff) be = 1;
      i = 2;
    }
    for(; i + 1 < n && o + 5 < outlen; i += 2) {
      unsigned cp = be ? (b[i] << 8) | b[i+1] : b[i] | (b[i+1] << 8);
      if(!cp) break;
      if(cp >= 0xd800 && cp < 0xdc00 && i + 3 < n) {
        unsigned lo = be ? (b[i+2] << 8) | b[i+3] : b[i+2] | (b[i+3] << 8);
        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        i += 2;
      }
      if(cp < 0x80) out[o++] = (char)cp;
      else if(cp < 0x800) { out[o++] = (char)(0xc0 | (cp >> 6)); out[o++] = (char)(0x80 | (cp & 63)); }
      else if(cp < 0x10000) {
        out[o++] = (char)(0xe0 | (cp >> 12)); out[o++] = (char)(0x80 | ((cp >> 6) & 63));
        out[o++] = (char)(0x80 | (cp & 63));
      } else {
        out[o++] = (char)(0xf0 | (cp >> 18)); out[o++] = (char)(0x80 | ((cp >> 12) & 63));
        out[o++] = (char)(0x80 | ((cp >> 6) & 63)); out[o++] = (char)(0x80 | (cp & 63));
      }
    }
  }
  out[o] = 0;
}


static int
read_id3(int fd, char *artist, size_t al, char *title, size_t tl) {
  uint8_t h[10];
  if(read(fd, h, 10) != 10 || memcmp(h, "ID3", 3) || (h[3] != 3 && h[3] != 4)) return -1;
  int v4 = h[3] == 4;
  uint32_t size = ((h[6] & 0x7f) << 21) | ((h[7] & 0x7f) << 14) | ((h[8] & 0x7f) << 7) | (h[9] & 0x7f);
  if(size > TAG_MAX) size = TAG_MAX;
  uint8_t *b = malloc(size);
  if(!b) return -1;
  ssize_t n = read(fd, b, size);
  size_t o = 0;
  if(n > 0 && (h[5] & 0x40) && n >= 4) {            /* cabecera extendida */
    uint32_t es = v4 ? ((b[0] & 0x7f) << 21) | ((b[1] & 0x7f) << 14) | ((b[2] & 0x7f) << 7) | (b[3] & 0x7f)
                     : ((uint32_t)b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) + 4;
    o = es;
  }
  while(n > 0 && o + 10 <= (size_t)n && b[o]) {
    const uint8_t *f = b + o;
    uint32_t fs = v4 ? ((f[4] & 0x7f) << 21) | ((f[5] & 0x7f) << 14) | ((f[6] & 0x7f) << 7) | (f[7] & 0x7f)
                     : ((uint32_t)f[4] << 24 | f[5] << 16 | f[6] << 8 | f[7]);
    o += 10;
    if(o + fs > (size_t)n) break;
    if(!memcmp(f, "TPE1", 4)) id3_text(b + o, fs, artist, al);
    else if(!memcmp(f, "TIT2", 4)) id3_text(b + o, fs, title, tl);
    o += fs;
  }
  free(b);
  return 0;
}


/* "Artista - Título.ext" */
static int
from_filename(const char *name, char *artist, size_t al, char *title, size_t tl) {
  const char *sep = strstr(name, " - ");
  const char *dot = strrchr(name, '.');
  if(!sep || !dot || dot < sep) return -1;
  if(!artist[0]) set_tag(artist, al, name, (size_t)(sep - name));
  if(!title[0]) set_tag(title, tl, sep + 3, (size_t)(dot - sep - 3));
  return 0;
}


static void
read_tags(const char *path, const char *name, char *artist, size_t al, char *title, size_t tl) {
  artist[0] = title[0] = 0;
  int fd = open(path, O_RDONLY);
  if(fd >= 0) {
    if(read_flac(fd, artist, al, title, tl)) {
      lseek(fd, 0, SEEK_SET);
      read_id3(fd, artist, al, title, tl);
    }
    close(fd);
  }
  if(!artist[0] || !title[0]) from_filename(name, artist, al, title, tl);
}


/* Quita caracteres que no admite exFAT/FAT y recorta. */
static void
safe_name(const char *in, char *out, size_t outlen) {
  size_t o = 0;
  for(const char *p = in; *p && o + 1 < outlen; p++) {
    char c = *p;
    if(strchr("/\\:*?\"<>|", c) || (unsigned char)c < 0x20) c = '_';
    out[o++] = c;
  }
  while(o && (out[o-1] == ' ' || out[o-1] == '.')) o--;
  out[o] = 0;
}


/* ------------------------------------------------------------------ */
/* Entrada                                                             */
/* ------------------------------------------------------------------ */

static int
move_file(const char *from, const char *to) {
  if(!rename(from, to)) return 0;
  if(errno != EXDEV) return -1;
  int in = open(from, O_RDONLY), out = -1, r = -1;
  char *buf = malloc(IO_BUFSIZE);
  if(in >= 0 && buf && (out = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666)) >= 0) {
    r = io_copy(in, out, (size_t)-1, buf, IO_BUFSIZE);
  }
  if(in >= 0) close(in);
  if(out >= 0 && close(out)) r = -1;
  free(buf);
  if(r) unlink(to);
  else unlink(from);
  return r;
}


static int
ingest_dir(const char *root, const char *dir, int depth) {
  DIR *d = opendir(dir);
  int moved = 0;
  if(!d) return 0;
  struct dirent *e;
  while((e = readdir(d))) {
    if(e->d_name[0] == '.' || !strcmp(e->d_name, DUPS)) continue;
    char path[PATH_MAX];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
    if(stat(path, &st)) continue;
    if(S_ISDIR(st.st_mode)) {
      if(depth < 3) moved += ingest_dir(root, path, depth + 1);
      continue;
    }
    if(!S_ISREG(st.st_mode) || !is_audio(e->d_name)) continue;

    char artist[256], title[256], base[400], dest[PATH_MAX];
    read_tags(path, e->d_name, artist, sizeof(artist), title, sizeof(title));
    if(!artist[0] || !title[0]) {
      LOG_PRINTF("ps5share: %s no tiene artista y título; llámalo «Artista - Título»\n", e->d_name);
      continue;
    }
    char raw[600];
    snprintf(raw, sizeof(raw), "%s - %s", artist, title);
    safe_name(raw, base, 240);
    snprintf(dest, sizeof(dest), "%s/%s%s", root, base, strrchr(e->d_name, '.'));
    if(!access(dest, F_OK)) {
      snprintf(dest, sizeof(dest), "%s/%s/%s", root, INBOX, DUPS);
      mkdir(dest, 0777);
      snprintf(dest, sizeof(dest), "%s/%s/%s/%s", root, INBOX, DUPS, e->d_name);
    }
    if(move_file(path, dest)) {
      LOG_PRINTF("ps5share: no se pudo mover %s: %s\n", path, strerror(errno));
      continue;
    }
    moved++;
  }
  closedir(d);
  if(depth > 0) rmdir(dir);     /* carpetas de álbum que quedan vacías */
  return moved;
}


int
lib_ingest(const char *dir) {
  char in[PATH_MAX];
  struct stat st;
  if(stat(dir, &st) || !S_ISDIR(st.st_mode)) return 0;
  snprintf(in, sizeof(in), "%s/%s", dir, INBOX);
  mkdir(in, 0777);
  return ingest_dir(dir, in, 0);
}


/* ------------------------------------------------------------------ */
/* Índice de archivos y listas                                         */
/* ------------------------------------------------------------------ */

typedef struct fent {
  char  key[200];
  char *rel;          /* compartido entre las dos claves de un archivo */
} fent_t;

typedef struct findex {
  fent_t *e;
  size_t  n, cap;
  char  **rels;
  size_t  nrels, caprels;
} findex_t;


static void
fi_add(findex_t *fi, const char *key, char *rel) {
  if(fi->n == fi->cap) {
    size_t nc = fi->cap ? fi->cap * 2 : 256;
    fent_t *ne = realloc(fi->e, nc * sizeof(*ne));
    if(!ne) return;
    fi->e = ne;
    fi->cap = nc;
  }
  snprintf(fi->e[fi->n].key, sizeof(fi->e[fi->n].key), "%s", key);
  fi->e[fi->n].rel = rel;
  fi->n++;
}


static void
fi_scan(findex_t *fi, const char *root, const char *rel, int depth) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s%s%s", root, rel[0] ? "/" : "", rel);
  DIR *d = opendir(path);
  if(!d) return;
  struct dirent *e;
  while((e = readdir(d))) {
    if(e->d_name[0] == '.') continue;
    if(!rel[0] && (!strcmp(e->d_name, INBOX) || !strcmp(e->d_name, LISTS))) continue;
    char r[PATH_MAX], full[PATH_MAX];
    struct stat st;
    snprintf(r, sizeof(r), "%s%s%s", rel, rel[0] ? "/" : "", e->d_name);
    if(snprintf(full, sizeof(full), "%s/%s", root, r) >= (int)sizeof(full)) continue;
    if(stat(full, &st)) continue;
    if(S_ISDIR(st.st_mode)) {
      if(depth < 3) fi_scan(fi, root, r, depth + 1);
      continue;
    }
    if(!is_audio(e->d_name)) continue;
    char artist[256] = "", title[256] = "";
    if(from_filename(e->d_name, artist, sizeof(artist), title, sizeof(title))) continue;
    if(fi->nrels == fi->caprels) {
      size_t nc = fi->caprels ? fi->caprels * 2 : 256;
      char **nr = realloc(fi->rels, nc * sizeof(*nr));
      if(!nr) break;
      fi->rels = nr;
      fi->caprels = nc;
    }
    char *dup = strdup(r);
    if(!dup) break;
    fi->rels[fi->nrels++] = dup;
    char k[200];
    lib_key(artist, title, 0, k, sizeof(k));
    fi_add(fi, k, dup);
    lib_key(artist, title, 1, k, sizeof(k));
    fi_add(fi, k, dup);
  }
  closedir(d);
}


static int fent_cmp(const void *a, const void *b) { return strcmp(((const fent_t*)a)->key, ((const fent_t*)b)->key); }


static const char *
fi_find(const findex_t *fi, const char *key) {
  fent_t k;
  snprintf(k.key, sizeof(k.key), "%s", key);
  fent_t *f = bsearch(&k, fi->e, fi->n, sizeof(fent_t), fent_cmp);
  return f ? f->rel : NULL;
}


static void
fi_free(findex_t *fi) {
  for(size_t i=0; i<fi->nrels; i++) free(fi->rels[i]);
  free(fi->rels);
  free(fi->e);
}


/* Busca el archivo de un tema de Spotify. */
static const char *
match(const findex_t *fi, const lib_track_t *t) {
  char k[200];
  const char *r;
  lib_key(t->artist, t->title, 0, k, sizeof(k));
  if((r = fi_find(fi, k))) return r;
  lib_key(t->artist, t->title, 1, k, sizeof(k));
  return fi_find(fi, k);
}


/* Escribe PATH con el contenido S solo si ha cambiado (menos escrituras al USB). */
static int
write_if_changed(const char *path, const char *s, size_t n) {
  int fd = open(path, O_RDONLY);
  if(fd >= 0) {
    struct stat st;
    if(!fstat(fd, &st) && (size_t)st.st_size == n) {
      char *old = malloc(n + 1);
      int same = old && read(fd, old, n) == (ssize_t)n && !memcmp(old, s, n);
      free(old);
      if(same) { close(fd); return 0; }
    }
    close(fd);
  }
  char tmp[PATH_MAX];
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if(fd < 0) return -1;
  int r = io_writeall(fd, s, n);
  if(close(fd)) r = -1;
  if(r || rename(tmp, path)) { unlink(tmp); return -1; }
  return 0;
}


typedef struct buf { char *p; size_t len, cap; } buf_t;


static void
bprintf(buf_t *b, const char *fmt, ...) {
  va_list ap;
  for(;;) {
    va_start(ap, fmt);
    int n = vsnprintf(b->p ? b->p + b->len : NULL, b->p ? b->cap - b->len : 0, fmt, ap);
    va_end(ap);
    if(n < 0) return;
    if(b->p && b->len + (size_t)n < b->cap) { b->len += (size_t)n; return; }
    size_t nc = b->cap ? b->cap : 4096;
    while(nc <= b->len + (size_t)n) nc *= 2;
    char *np = realloc(b->p, nc);
    if(!np) return;
    b->p = np;
    b->cap = nc;
  }
}


int
lib_build(const char *dir, const lib_track_t *tracks, int ntracks,
          lib_month_t *months, int nmonths, lib_list_t *extra, int nextra) {
  struct stat st;
  char path[PATH_MAX];
  findex_t fi = {0};
  buf_t miss = {0};

  if(stat(dir, &st) || !S_ISDIR(st.st_mode)) return -1;
  snprintf(path, sizeof(path), "%s/%s", dir, LISTS);
  mkdir(path, 0777);

  fi_scan(&fi, dir, "", 0);
  qsort(fi.e, fi.n, sizeof(fent_t), fent_cmp);

  bprintf(&miss, "Canciones de las playlists que aún no están en la carpeta de música.\n"
                 "Pon los archivos en %s/ y PS5NAS los colocará solo.\n", INBOX);

  for(int m=0; m<nmonths; m++) {
    buf_t pl = {0};
    int ym = months[m].ym, year = ym / 12, mon = ym % 12 + 1;
    int total = 0, have = 0, header = 0;
    bprintf(&pl, "#EXTM3U\n#PLAYLIST:pl %d/%d\n", mon, year);
    for(int i=0; i<ntracks; i++) {
      const lib_track_t *t = &tracks[i];
      if(t->ym != ym) continue;
      total++;
      const char *rel = match(&fi, t);
      if(rel) {
        have++;
        bprintf(&pl, "#EXTINF:%d,%s - %s\n../%s\n", t->duration_ms / 1000, t->artist, t->title, rel);
      } else {
        bprintf(&pl, "# FALTA: %s - %s\n", t->artist, t->title);
        if(!header) {
          bprintf(&miss, "\n== %s %d ==\n", lib_month_name(mon), year);
          header = 1;
        }
        bprintf(&miss, "%s - %s   [%s]\n", t->artist, t->title, t->album);
      }
    }
    months[m].total = total;
    months[m].have = have;
    int pn = snprintf(path, sizeof(path), "%s/%s/%04d-%02d %s %d.m3u8", dir, LISTS, year, mon,
                      lib_month_name(mon), year);
    if(pl.p && pn > 0 && pn < (int)sizeof(path) && write_if_changed(path, pl.p, pl.len)) LOG_PERROR(path);
    free(pl.p);
  }
  for(int x=0; x<nextra; x++) {
    lib_list_t *l = &extra[x];
    buf_t pl = {0};
    int have = 0;
    bprintf(&pl, "#EXTM3U\n#PLAYLIST:%s\n", l->title);
    for(int i=0; i<l->n; i++) {
      const lib_track_t *t = &l->tracks[i];
      const char *rel = match(&fi, t);
      if(rel) {
        have++;
        bprintf(&pl, "#EXTINF:%d,%s - %s\n../%s\n", t->duration_ms / 1000, t->artist, t->title, rel);
      } else {
        bprintf(&pl, "# FALTA: %s - %s\n", t->artist, t->title);
      }
    }
    l->have = have;
    int pn = snprintf(path, sizeof(path), "%s/%s/%s.m3u8", dir, LISTS, l->file);
    if(pl.p && pn > 0 && pn < (int)sizeof(path) && write_if_changed(path, pl.p, pl.len)) LOG_PERROR(path);
    free(pl.p);
  }
  snprintf(path, sizeof(path), "%s/%s/Faltan.txt", dir, LISTS);
  if(miss.p) write_if_changed(path, miss.p, miss.len);
  free(miss.p);
  fi_free(&fi);
  return 0;
}
