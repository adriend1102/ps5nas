/* ps5share - carpetas privadas cifradas
   Copyright (C) 2026  ps5share contributors.  GPLv3, ver LICENSE.

   Cada usuario con carpetas cifradas tiene una clave de datos (DEK) de 256
   bits, aleatoria, que solo se guarda envuelta (AES-256-GCM) con una clave
   derivada de su contraseña (PBKDF2-SHA256).  Al iniciar sesión por SFTP o
   por la web se desenvuelve en memoria; el administrador, que no conoce la
   contraseña, no puede leer nada.

   - Nombres: SIV determinista (IV = HMAC-SHA256, AES-256-CTR), codificado en
     base32 en minúsculas (válido también en exFAT, que no distingue
     mayúsculas).  Máximo CRYPT_NAME_MAX bytes por nombre.
   - Contenido: cabecera de 32 bytes y bloques de 64 KiB, cada uno con su
     nonce aleatorio y su etiqueta GCM.  Clave propia por archivo.  Admite
     lectura y escritura en cualquier posición.  */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define CRYPT_KEY_LEN    32
#define CRYPT_NAME_MAX   140          /* bytes del nombre en claro */
#define CRYPT_CHUNK      65536
#define CRYPT_HDR        32
#define CRYPT_OVERHEAD   28           /* nonce 12 + etiqueta 16 por bloque */
#define CRYPT_WRAP_HEX   120          /* (12 + 32 + 16) * 2 */


typedef struct ukey {
  int     ok;
  uint8_t dek[CRYPT_KEY_LEN];
  uint8_t name_mac[CRYPT_KEY_LEN];
  uint8_t name_enc[CRYPT_KEY_LEN];
} ukey_t;


/* Prepara las subclaves a partir de la DEK. */
void crypt_key_init(ukey_t *k, const uint8_t dek[CRYPT_KEY_LEN]);
void crypt_key_wipe(ukey_t *k);

/* Envuelve / desenvuelve la DEK con una KEK (hex de 120 caracteres). */
int  crypt_wrap(const uint8_t kek[CRYPT_KEY_LEN], const uint8_t dek[CRYPT_KEY_LEN],
                char out_hex[CRYPT_WRAP_HEX + 1]);
int  crypt_unwrap(const uint8_t kek[CRYPT_KEY_LEN], const char *hex,
                  uint8_t dek[CRYPT_KEY_LEN]);

/* Secretos cortos (p. ej. contraseñas) con AES-256-GCM.  Hex de
   (12 + len + 16) * 2 caracteres. */
#define CRYPT_SEAL_MAX   160
#define CRYPT_SEAL_HEX   ((12 + CRYPT_SEAL_MAX + 16) * 2)
int  crypt_seal(const uint8_t key[CRYPT_KEY_LEN], const char *aad, const void *plain,
                size_t len, char *out_hex, size_t outlen);
int  crypt_open(const uint8_t key[CRYPT_KEY_LEN], const char *aad, const char *hex,
                char *out, size_t outlen);

/* Nombres.  Devuelven 0, o -1 con errno (ENAMETOOLONG, EINVAL). */
int  crypt_name_enc(const ukey_t *k, const char *plain, char *out, size_t outlen);
int  crypt_name_dec(const ukey_t *k, const char *enc, char *out, size_t outlen);

/* Tamaño en claro a partir del tamaño en disco. */
off_t crypt_plain_size(off_t disk_size);


/* Archivo cifrado abierto. */
typedef struct cfile {
  int      fd;
  int      writable;
  uint8_t  file_id[16];
  uint8_t  key[CRYPT_KEY_LEN];
  /* caché de un bloque en claro */
  int64_t  c_idx;      /* -1 = vacía */
  size_t   c_len;
  int      c_dirty;
  uint8_t *c_buf;      /* CRYPT_CHUNK */
  uint8_t *io_buf;     /* CRYPT_CHUNK + CRYPT_OVERHEAD */
} cfile_t;


/* Abre FD (ya abierto en O_RDWR o O_RDONLY).  Si FRESH, escribe una cabecera
   nueva (archivo nuevo o truncado). */
int     cfile_open(cfile_t *f, int fd, int writable, int fresh, const ukey_t *k);
ssize_t cfile_pread(cfile_t *f, void *buf, size_t len, off_t off);
ssize_t cfile_pwrite(cfile_t *f, const void *buf, size_t len, off_t off);
off_t   cfile_size(cfile_t *f);
int     cfile_flush(cfile_t *f);
int     cfile_close(cfile_t *f);   /* cierra también el fd */
