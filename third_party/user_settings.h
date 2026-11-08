/* Configuración de wolfSSL/wolfSSH para ps5share: servidor SFTP y cliente
   TLS (solo para enviar correos de recuperación por SMTP).  Algoritmos
   modernos más los necesarios para clientes SFTP antiguos (Android, JSch). */

#ifndef PS5SHARE_USER_SETTINGS_H
#define PS5SHARE_USER_SETTINGS_H

#define WOLFSSL_WOLFSSH
#define NO_FILESYSTEM
#define WOLFSSL_NO_SOCK
#define WOLFSSL_USER_IO

/* Cliente TLS 1.2/1.3 con verificación de certificados */
#define NO_WOLFSSL_SERVER
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_SNI
#define HAVE_HKDF
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define WOLFSSL_ALT_CERT_CHAINS
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH
#define HAVE_FFDHE_2048
#define NO_WOLFSSL_DIR
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define WOLFSSL_IGNORE_FILE_WARN

/* Matemáticas y resistencia a canales laterales */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_INT_NEGATIVE
#define SP_INT_BITS 8192
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define WOLFSSL_PUBLIC_MP
#define WOLFSSL_KEY_GEN
#define HAVE_HASHDRBG

/* Algoritmos */
#define HAVE_ECC
#define ECC_SHAMIR
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WC_RSA_PSS
#define WOLFSSL_ASN_TEMPLATE

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_PSK
#define NO_OLD_TLS
#define NO_PWDBASED
#define NO_PKCS12
#define NO_PKCS8
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

/* Aleatoriedad: la proporciona ps5share (kern.arandom en PS5). */
extern int ps5share_rand_seed(unsigned char *out, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED ps5share_rand_seed

/* wolfSSH: solo servidor, sin SFTP/SCP/agente/shell propios. */
#define NO_WOLFSSH_CLIENT
#define WOLFSSH_KEYGEN
#define WOLFSSH_NO_MLDSA

#endif
