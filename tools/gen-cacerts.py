#!/usr/bin/env python3
"""Genera src/cacerts.h con las CA raíz usadas para verificar el servidor
SMTP (Gmail y otros proveedores habituales).  Uso:
    python3 tools/gen-cacerts.py /etc/ssl/certs > src/cacerts.h"""
import os, sys

ROOTS = [
    "GTS_Root_R1", "GTS_Root_R3", "GTS_Root_R4",          # Gmail
    "GlobalSign_Root_CA_-_R3", "GlobalSign_Root_R46",
    "ISRG_Root_X1", "ISRG_Root_X2",                       # Let's Encrypt
    "DigiCert_Global_Root_G2", "DigiCert_Global_Root_G3", # Outlook / Office 365
    "Microsoft_RSA_Root_Certificate_Authority_2017",
    "Microsoft_ECC_Root_Certificate_Authority_2017",
    "USERTrust_RSA_Certification_Authority",              # Sectigo
    "Amazon_Root_CA_1",                                   # Amazon SES, Brevo...
]

d = sys.argv[1] if len(sys.argv) > 1 else "/etc/ssl/certs"
out = ["/* Generado por tools/gen-cacerts.py: CA raíz para el cliente SMTP. */",
       "#pragma once", "static const char CA_CERTS_PEM[] ="]
for name in ROOTS:
    pem = open(os.path.join(d, name + ".pem")).read().strip()
    out.append(f"  /* {name} */")
    for line in pem.splitlines():
        out.append(f'  "{line}\\n"')
out.append("  ;")
print("\n".join(out))
