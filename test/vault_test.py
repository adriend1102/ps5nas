#!/usr/bin/env python3
"""Pruebas del gestor de contraseñas (API compatible con Bitwarden + web).

Hace de cliente de Bitwarden con su mismo cifrado (PBKDF2, HKDF, AES-CBC +
HMAC) contra un servidor en marcha, por HTTPS con la CA de la consola.
Si está instalada la CLI oficial (variable BW_CLI con la ruta a «bw»), la
usa además para iniciar sesión, crear y leer elementos.

Uso:  python3 test/vault_test.py BASE_DIR   (BASE_DIR = carpeta de configuración)
"""
import base64, hashlib, hmac, http.cookiejar, json, os, ssl, subprocess, sys, tempfile
import urllib.parse, urllib.request
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CONF = sys.argv[1]
WEB = "http://127.0.0.1:8000"
API = "https://127.0.0.1:8443"
FAILS = 0


def check(cond, msg):
    global FAILS
    print(("  ok  " if cond else "  FALLO ") + msg)
    if not cond:
        FAILS += 1


# ---------------------------------------------------------------- cliente web
class Web:
    def __init__(self):
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def req(self, method, path, data=None):
        h = {"X-PS5Share": "1"}
        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(WEB + path, data=data, method=method, headers=h)
        try:
            resp = self.op.open(r, timeout=60)
            body = resp.read()
            try:
                return resp.status, json.loads(body or b"{}")
            except ValueError:
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body)
            except ValueError:
                return e.code, body


# ---------------------------------------------------------------- cliente Bitwarden
ca_pem = urllib.request.urlopen(WEB + "/ps5nas-ca.crt", timeout=10).read()
CTX = ssl.create_default_context(cadata=ca_pem.decode())


def bw(method, path, data=None, token=None, form=False):
    h = {}
    if token:
        h["Authorization"] = "Bearer " + token
    if data is not None:
        if form:
            data = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
    r = urllib.request.Request(API + path, data=data, method=method, headers=h)
    try:
        resp = urllib.request.urlopen(r, context=CTX, timeout=60)
        body = resp.read()
        return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, (json.loads(body) if body else None)


def master_key(pw, email, it):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), email.lower().encode(), it)


def stretch(mk):
    e = hmac.new(mk, b"enc\x01", hashlib.sha256).digest()
    m = hmac.new(mk, b"mac\x01", hashlib.sha256).digest()
    return e + m


def enc(key, data):
    if isinstance(data, str):
        data = data.encode()
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder()
    pt = p.update(data) + p.finalize()
    e = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    ct = e.update(pt) + e.finalize()
    mac = hmac.new(key[32:], iv + ct, hashlib.sha256).digest()
    b = lambda x: base64.b64encode(x).decode()
    return "2." + b(iv) + "|" + b(ct) + "|" + b(mac)


def dec(key, s):
    t, rest = s.split(".", 1)
    assert t == "2"
    iv, ct, mac = [base64.b64decode(x) for x in rest.split("|")]
    assert hmac.compare_digest(mac, hmac.new(key[32:], iv + ct, hashlib.sha256).digest())
    d = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    u = padding.PKCS7(128).unpadder()
    return u.update(pt) + u.finalize()


def login(email, pw):
    s, pre = bw("POST", "/identity/accounts/prelogin", {"email": email})
    if s != 200:
        return s, pre, None
    it = pre["kdfIterations"]
    mk = master_key(pw, email, it)
    h = base64.b64encode(hashlib.pbkdf2_hmac("sha256", mk, pw.encode(), 1)).decode()
    s, tok = bw("POST", "/identity/connect/token", {
        "grant_type": "password", "username": email, "password": h, "scope": "api offline_access",
        "client_id": "cli", "deviceType": "8", "deviceIdentifier": "11111111-2222-3333-4444-555555555555",
        "deviceName": "pruebas"}, form=True)
    if s != 200:
        return s, tok, None
    ukey = dec(stretch(mk), tok["Key"])
    return s, tok, ukey


# ---------------------------------------------------------------- pruebas
admin = Web()
s, j = admin.req("POST", "/api/login", {"user": "admin", "pass": "adminpass"})
check(s == 200, "admin inicia sesión")
s, j = admin.req("POST", "/api/admin/user", {"name": "Vera", "password": "verapass1", "admin": "0",
                                             "enabled": "1", "can_chpass": "1", "vault": "1", "mounts": ""})
check(s == 200, "alta de Vera con gestor")

print("== HTTPS y prelogin")
s, cfg = bw("GET", "/api/config")
check(s == 200 and cfg["object"] == "config", "config por HTTPS con la CA de la consola")
s, pre = bw("POST", "/identity/accounts/prelogin", {"email": "vera@ps5nas.local"})
check(s == 200 and pre["kdf"] == 0 and pre["kdfIterations"] == 600000 and pre["kdfSettings"]["kdfType"] == 0,
      "prelogin PBKDF2 600000")

print("== Inicio de sesión")
s, tok, _ = login("vera@ps5nas.local", "mala")
check(s == 400 and tok.get("error") == "invalid_grant", "contraseña incorrecta rechazada")
s, tok, ukey = login("VERA@ps5nas.local", "verapass1")
check(s == 200 and len(ukey) == 64, "login y descifrado de la clave de usuario")
at = tok["access_token"]
priv = dec(ukey, tok["PrivateKey"])
k = serialization.load_der_private_key(priv, None)
check(k.key_size == 2048, "clave privada RSA en PKCS#8 válida")
s, _ = bw("GET", "/api/sync", token="x.y.z")
check(s == 401, "token falso rechazado")

print("== Elementos y carpetas")
s, f = bw("POST", "/api/folders", {"name": enc(ukey, "Trabajo")}, token=at)
check(s == 200 and f["object"] == "folder", "crear carpeta")
item = {"type": 1, "name": enc(ukey, "GitHub"), "notes": None, "favorite": True, "folderId": f["id"],
        "login": {"username": enc(ukey, "vera"), "password": enc(ukey, "gh-secreto"),
                  "uris": [{"uri": enc(ukey, "https://github.com"), "match": None}]},
        "fields": [{"name": enc(ukey, "PIN"), "value": enc(ukey, "4321"), "type": 1}]}
s, c = bw("POST", "/api/ciphers", item, token=at)
check(s == 200 and c["object"] == "cipherDetails" and c["login"]["uri"], "crear elemento")
s, sync = bw("GET", "/api/sync?excludeDomains=true", token=at)
check(s == 200 and len(sync["ciphers"]) == 1 and len(sync["folders"]) == 1, "sync")
check(dec(ukey, sync["ciphers"][0]["login"]["password"]) == b"gh-secreto", "contraseña descifrada tras sync")
item["login"]["password"] = enc(ukey, "gh-nuevo")
item["lastKnownRevisionDate"] = "2000-01-01T00:00:00Z"
s, e = bw("PUT", "/api/ciphers/" + c["id"], item, token=at)
check(s == 400, "edición con copia desactualizada rechazada")
item["lastKnownRevisionDate"] = c["revisionDate"]
s, c2 = bw("PUT", "/api/ciphers/" + c["id"], item, token=at)
check(s == 200 and dec(ukey, c2["login"]["password"]) == b"gh-nuevo", "editar elemento")
s, _ = bw("PUT", "/api/ciphers/" + c["id"] + "/delete", None, token=at)
s2, sync = bw("GET", "/api/sync", token=at)
check(s == 200 and sync["ciphers"][0]["deletedDate"], "mover a la papelera")
s, _ = bw("PUT", "/api/ciphers/" + c["id"] + "/restore", None, token=at)
check(s == 200, "restaurar")
imp = {"ciphers": [{"type": 2, "name": enc(ukey, "Nota"), "notes": enc(ukey, "texto"), "secureNote": {"type": 0}}],
       "folders": [{"name": enc(ukey, "Importadas")}], "folderRelationships": [{"key": 0, "value": 0}]}
s, _ = bw("POST", "/api/ciphers/import", imp, token=at)
s2, sync = bw("GET", "/api/sync", token=at)
check(s == 200 and len(sync["ciphers"]) == 2 and len(sync["folders"]) == 2, "importar")

print("== Web de PS5NAS")
vera = Web()
s, j = vera.req("POST", "/api/login", {"user": "Vera", "pass": "verapass1"})
s, j = vera.req("GET", "/api/pw/items")
names = sorted(i["name"] for i in j.get("items", []))
gh = [i for i in j.get("items", []) if i["name"] == "GitHub"]
check(s == 200 and names == ["GitHub", "Nota"], "la web descifra lo creado con la app")
check(gh and gh[0]["login"]["password"] == "gh-nuevo" and gh[0]["fields"][0]["value"] == "4321",
      "contraseña y campos visibles en la web")
s, j = vera.req("POST", "/api/pw/item", {"id": gh[0]["id"], "type": "1", "name": "GitHub",
                                         "username": "vera", "password": "desde-web", "uris": "https://github.com"})
check(s == 200, "editar desde la web")
s, j = vera.req("POST", "/api/pw/item", {"type": "1", "name": "Banco", "username": "1234",
                                         "password": "pin!", "uris": "https://banco.es\nhttps://app.banco.es"})
check(s == 200, "crear desde la web")
s, j = vera.req("POST", "/api/pw/import", {"items": json.dumps([
    {"name": "Correo", "url": "https://mail.es", "username": "v", "password": "m1", "folder": "Personal"}])})
check(s == 200 and j.get("imported") == 1, "importar CSV (Google/Chrome) desde la web")
s, sync = bw("GET", "/api/sync", token=at)
byname = {dec(ukey, x["name"]).decode(): x for x in sync["ciphers"]}
check(dec(ukey, byname["GitHub"]["login"]["password"]) == b"desde-web", "la app ve la edición de la web")
check(len(byname["GitHub"]["passwordHistory"]) == 1 and
      dec(ukey, byname["GitHub"]["passwordHistory"][0]["password"]) == b"gh-nuevo", "historial de contraseñas")
check(len(byname["GitHub"]["fields"]) == 1, "la web conserva los campos personalizados")
u = byname["Banco"]["login"]["uris"]
check(len(u) == 2 and dec(ukey, u[0]["uriChecksum"]) ==
      base64.b64encode(hashlib.sha256(b"https://banco.es").digest()), "URIs con suma de comprobación")
check("Correo" in byname and any(dec(ukey, x["name"]) == b"Personal" for x in sync["folders"]),
      "elemento importado en su carpeta")
s, csv = vera.req("POST", "/api/pw/export", {"pass": "mala"})
check(s == 403, "exportar pide la contraseña")
s, csv = vera.req("POST", "/api/pw/export", {"pass": "verapass1"})
check(s == 200 and b"desde-web" in csv and b"login_password" in csv, "exportar CSV")

print("== Cambios de contraseña")
s, j = vera.req("POST", "/api/me/password", {"old": "verapass1", "new": "veranueva2"})
check(s == 200, "Vera cambia su contraseña en la web")
s, _ = bw("GET", "/api/sync", token=at)
check(s == 401, "los tokens anteriores dejan de valer")
s, tok, _ = login("vera@ps5nas.local", "verapass1")
check(s == 400, "la contraseña antigua ya no entra")
s, tok, ukey2 = login("vera@ps5nas.local", "veranueva2")
check(s == 200 and ukey2 == ukey, "la nueva entra y la clave de datos es la misma")
s, j = admin.req("POST", "/api/admin/user", {"name": "Vera", "password": "porelAdmin3", "admin": "0",
                                             "enabled": "1", "can_chpass": "1", "vault": "1", "mounts": ""})
s, tok, ukey3 = login("vera@ps5nas.local", "porelAdmin3")
check(s == 200 and ukey3 == ukey, "contraseña puesta por el administrador")
s, _ = bw("POST", "/api/accounts/password", {}, token=tok["access_token"])
check(s == 400, "cambiar la contraseña desde la app se rechaza con explicación")
s, rt = bw("POST", "/identity/connect/token", {"grant_type": "refresh_token",
                                               "refresh_token": tok["refresh_token"]}, form=True)
check(s == 200 and rt["access_token"], "renovar el token")

print("== Contraseña temporal y desactivación")
s, j = admin.req("POST", "/api/admin/user", {"name": "tmpuser", "password": "temporal1", "admin": "0",
                                             "enabled": "1", "must_chpass": "1", "vault": "1", "mounts": ""})
s, tok, _ = login("tmpuser@ps5nas.local", "temporal1")
check(s == 400 and "temporal" in json.dumps(tok, ensure_ascii=False), "con cambio pendiente no entra en la app")
s, j = admin.req("POST", "/api/admin/settings", {"vault_enabled": "0"})
s, tok, _ = login("vera@ps5nas.local", "porelAdmin3")
check(s != 200, "gestor desactivado: no se puede entrar")
s, j = admin.req("POST", "/api/admin/settings", {"vault_enabled": "1"})
s, j = admin.req("POST", "/api/admin/user", {"name": "Vera", "password": "", "admin": "0", "enabled": "1",
                                             "can_chpass": "1", "vault": "0", "mounts": ""})
s, tok, _ = login("vera@ps5nas.local", "porelAdmin3")
check(s == 400, "sin permiso de gestor no entra")
admin.req("POST", "/api/admin/user", {"name": "Vera", "password": "", "admin": "0", "enabled": "1",
                                      "can_chpass": "1", "vault": "1", "mounts": ""})

print("== Carpeta de datos")
newdir = os.path.join(CONF, "otra", "claves")
s, j = admin.req("POST", "/api/admin/settings", {"vault_dir": newdir})
check(s == 200 and os.path.exists(os.path.join(newdir, "Vera.json")), "las bóvedas se mueven a la carpeta nueva")
s, tok, ukey4 = login("vera@ps5nas.local", "porelAdmin3")
s, sync = bw("GET", "/api/sync", token=tok["access_token"])
check(s == 200 and len(sync["ciphers"]) == 4, "todo sigue ahí tras moverla")
raw = open(os.path.join(newdir, "Vera.json")).read()
check("desde-web" not in raw and "GitHub" not in raw, "en el disco solo hay datos cifrados")

print("== Verificación en dos pasos en las apps de Bitwarden")
import struct, time as _t
def totp(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = d[-1] & 15
    return "%06d" % ((struct.unpack(">I", d[o:o+4])[0] & 0x7fffffff) % 1000000)
def login2(email, pw, dev="99999999-2222-3333-4444-555555555555", **extra):
    s, pre = bw("POST", "/identity/accounts/prelogin", {"email": email})
    mk = master_key(pw, email, pre["kdfIterations"])
    h = base64.b64encode(hashlib.pbkdf2_hmac("sha256", mk, pw.encode(), 1)).decode()
    d = {"grant_type": "password", "username": email, "password": h, "scope": "api offline_access",
         "client_id": "mobile", "deviceType": "0", "deviceIdentifier": dev, "deviceName": "android"}
    d.update(extra)
    return bw("POST", "/identity/connect/token", d, form=True)
admin.req("POST", "/api/admin/user", {"name": "tom", "password": "tompass11", "admin": "0",
                                      "enabled": "1", "can_chpass": "1", "vault": "1", "mounts": ""})
tom = Web()
tom.req("POST", "/api/login", {"user": "tom", "pass": "tompass11"})
s, tok = login2("tom@ps5nas.local", "tompass11")
check(s == 200 and "access_token" in tok, "sin 2FA, la app entra solo con la contraseña")
s, j = tom.req("POST", "/api/me/2fa/setup", {"pass": "tompass11"})
secret = j["secret"]
step = int(_t.time()) // 30
s, j = tom.req("POST", "/api/me/2fa/enable", {"code": totp(secret, step)})
check(s == 200, "tom activa la 2FA")
s, tok = login2("tom@ps5nas.local", "tompass11")
check(s == 400 and tok.get("TwoFactorProviders") == ["0"] and "0" in tok.get("TwoFactorProviders2", {})
      and "access_token" not in tok, "la app recibe «Two factor required» con la app de autenticación")
s, tok = login2("tom@ps5nas.local", "tompass11", twoFactorToken="000001", twoFactorProvider="0")
check(s == 400 and "access_token" not in tok, "código erróneo rechazado")
s, tok = login2("tom@ps5nas.local", "tompass11", twoFactorToken=totp(secret, step + 1), twoFactorProvider="0",
                twoFactorRemember="1")
check(s == 200 and "access_token" in tok and len(tok.get("TwoFactorToken", "")) == 64,
      "con el código entra y recibe el token de «recordar dispositivo»")
rem = tok.get("TwoFactorToken", "")
s, tok = login2("tom@ps5nas.local", "tompass11", twoFactorToken=rem, twoFactorProvider="5")
check(s == 200 and "access_token" in tok, "el dispositivo recordado entra sin código")
s, tok = login2("tom@ps5nas.local", "tompass11", dev="00000000-0000-0000-0000-000000000001",
                twoFactorToken=rem, twoFactorProvider="5")
check(s == 400 and "TwoFactorProviders" in tok, "el token recordado no vale en otro dispositivo")
s, prof = bw("GET", "/api/accounts/profile", token=login2("tom@ps5nas.local", "tompass11", twoFactorToken=rem,
                                                          twoFactorProvider="5")[1]["access_token"])
check(s == 200 and prof["twoFactorEnabled"] is True, "el perfil indica 2FA activada")
admin.req("POST", "/api/admin/user/2fa/reset", {"name": "tom"})
s, j = tom.req("POST", "/api/me/2fa/setup", {"pass": "tompass11"})
secret2 = j["secret"]
step = int(_t.time()) // 30
tom.req("POST", "/api/me/2fa/enable", {"code": totp(secret2, step)})
s, tok = login2("tom@ps5nas.local", "tompass11", twoFactorToken=rem, twoFactorProvider="5")
check(s == 400 and "TwoFactorProviders" in tok, "al cambiar el secreto, los dispositivos recordados vuelven a pedir código")
admin.req("POST", "/api/admin/user/delete", {"name": "tom"})

# ---------------------------------------------------------------- CLI oficial (opcional)
cli = os.environ.get("BW_CLI")
if cli:
    print("== CLI oficial de Bitwarden")
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "ca.pem"), "wb") as fh:
        fh.write(ca_pem)
    env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", d), "BITWARDENCLI_APPDATA_DIR": d,
           "NODE_EXTRA_CA_CERTS": os.path.join(d, "ca.pem")}
    run = lambda *a, **kw: subprocess.run([cli, *a], env=env, capture_output=True, text=True, timeout=120, **kw)
    run("config", "server", API)
    r = run("login", "vera@ps5nas.local", "porelAdmin3", "--raw")
    check(r.returncode == 0 and r.stdout.strip(), "bw login")
    env["BW_SESSION"] = r.stdout.strip()
    r = run("list", "items")
    items = json.loads(r.stdout or "[]")
    check(sorted(i["name"] for i in items) == ["Banco", "Correo", "GitHub", "Nota"], "bw list items")
    tpl = json.loads(run("get", "template", "item").stdout)
    tpl.update(name="Desde bw", login={"username": "x", "password": "bw-pass", "uris": []})
    data = run("encode", input=json.dumps(tpl)).stdout.strip()
    r = run("create", "item", data)
    check(r.returncode == 0, "bw create item")
    s, j = vera.req("POST", "/api/login", {"user": "Vera", "pass": "porelAdmin3"})
    s, j = vera.req("GET", "/api/pw/items")
    check(any(i["name"] == "Desde bw" and i["login"]["password"] == "bw-pass" for i in j["items"]),
          "la web ve lo creado con bw")
    # Verificación en dos pasos con la CLI oficial
    admin.req("POST", "/api/admin/user", {"name": "cli2", "password": "cli2pass1", "admin": "0",
                                          "enabled": "1", "can_chpass": "1", "vault": "1", "mounts": ""})
    c2 = Web()
    c2.req("POST", "/api/login", {"user": "cli2", "pass": "cli2pass1"})
    s, j = c2.req("POST", "/api/me/2fa/setup", {"pass": "cli2pass1"})
    sec = j["secret"]
    stp = int(_t.time()) // 30
    c2.req("POST", "/api/me/2fa/enable", {"code": totp(sec, stp)})
    d2 = tempfile.mkdtemp()
    env2 = dict(env, BITWARDENCLI_APPDATA_DIR=d2)
    env2.pop("BW_SESSION", None)
    run2 = lambda *a: subprocess.run([cli, *a], env=env2, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    run2("config", "server", API)
    r = run2("login", "cli2@ps5nas.local", "cli2pass1", "--method", "0", "--code", totp(sec, stp + 1), "--raw")
    check(r.returncode == 0 and r.stdout.strip(), "bw login con --method 0 --code " + (r.stderr or "").strip()[:120])

print("\nRESULTADO:", "TODO OK" if not FAILS else f"{FAILS} FALLO(S)")
sys.exit(1 if FAILS else 0)
