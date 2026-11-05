# Fuentes de wolfSSL (solo wolfCrypt) y wolfSSH (servidor) para ps5share.
WOLF_DIR := third_party
WOLFCRYPT_SRC := aes.c asn.c coding.c curve25519.c fe_operations.c fe_low_mem.c ecc.c dh.c \
  rsa.c random.c sha.c sha256.c sha512.c hmac.c hash.c memory.c wc_port.c \
  wolfmath.c sp_int.c error.c logging.c signature.c kdf.c wc_encrypt.c
WOLFSSH_SRC := internal.c ssh.c io.c log.c port.c keygen.c ossh.c

WOLF_SRC := $(addprefix $(WOLF_DIR)/wolfssl/wolfcrypt/src/,$(WOLFCRYPT_SRC)) \
            $(addprefix $(WOLF_DIR)/wolfssh/src/,$(WOLFSSH_SRC))
WOLF_CFLAGS := -DWOLFSSL_USER_SETTINGS -I$(WOLF_DIR) -I$(WOLF_DIR)/wolfssl \
               -I$(WOLF_DIR)/wolfssh -Wno-error
