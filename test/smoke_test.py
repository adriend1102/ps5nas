#!/usr/bin/env python3
"""Pruebas de humo de ps5share (FTP + web) contra un servidor en marcha.

Uso:  python3 test/smoke_test.py HOST BASE_DIR
BASE_DIR debe contener share/movies (con big.bin, sub/a.txt y el symlink
'escape' -> carpeta secreta) y share/inbox, como prepara test/run_tests.sh.
"""
import ftplib, http.cookiejar, io, json, os, sys, time, urllib.parse, urllib.request

HOST, BASE = sys.argv[1], sys.argv[2]
WEB = f"http://{HOST}:8000"
FAILS = 0


def check(cond, msg):
    global FAILS
    print(("  ok  " if cond else "  FALLO ") + msg)
    if not cond:
        FAILS += 1


class Web:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method, path, data=None, headers=None, csrf=True, raw=False):
        h = dict(headers or {})
        if csrf:
            h["X-PS5Share"] = "1"
        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(WEB + path, data=data, method=method, headers=h)
        try:
            resp = self.op.open(r, timeout=30)
            body = resp.read()
            return resp.status, (body if raw else json.loads(body or b"{}")), resp.headers
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body), e.headers
            except Exception:
                return e.code, body, e.headers


def q(**kw):
    return "?" + urllib.parse.urlencode(kw)


print("== Web: configuración inicial")
admin = Web()
s, j, _ = admin.req("GET", "/api/status")
check(s == 200 and j["setup"] is True, "status indica que falta configurar")
s, j, _ = admin.req("POST", "/api/setup", {"user": "admin", "pass": "adminpass"}, csrf=False)
check(s == 403, "setup sin cabecera CSRF rechazado")
s, j, _ = admin.req("POST", "/api/setup", {"user": "admin", "pass": "adminpass"})
check(s == 200, "setup crea administrador")
s, j, _ = Web().req("POST", "/api/setup", {"user": "evil", "pass": "evilpass"})
check(s == 403, "setup no se puede repetir")
s, j, _ = admin.req("GET", "/api/me")
check(s == 200 and j["admin"], "admin con sesión")

print("== Web: gestión de usuarios")
mounts = f"ro|Peliculas|{BASE}/share/movies\nrw|Buzon|{BASE}/share/inbox"
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "bob", "password": "bobpass1",
                                                "admin": "0", "enabled": "1", "mounts": mounts})
check(s == 200, "alta de bob")
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "mal/user", "password": "xxxxxxx",
                                                "admin": "0", "enabled": "1", "mounts": ""})
check(s == 400, "nombre de usuario inválido rechazado")
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "eve", "password": "evepass1", "admin": "0",
                                                "enabled": "1", "mounts": "ro|X|/tmp/../etc"})
check(s == 400, "ruta con '..' rechazada")
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "admin", "password": "", "admin": "0",
                                                "enabled": "1", "mounts": ""})
check(s == 400, "el admin no puede quitarse el rol")
s, j, _ = admin.req("GET", "/api/admin/users")
check(s == 200 and [u["name"] for u in j["users"]] == ["admin", "bob"], "listado de usuarios")
s, j, _ = admin.req("GET", "/api/admin/browse" + q(path=BASE + "/share"))
check(s == 200 and sorted(j["dirs"]) == ["inbox", "movies"], "explorador de carpetas reales")

print("== FTP: autenticación")
f = ftplib.FTP()
f.connect(HOST, 2121, timeout=20)
try:
    f.login("bob", "malapass")
    check(False, "login con contraseña mala rechazado")
except ftplib.error_perm as e:
    check(str(e).startswith("530"), "login con contraseña mala rechazado")
f.close()

f = ftplib.FTP()
f.connect(HOST, 2121, timeout=20)
try:
    f.nlst()
    check(False, "comandos sin login rechazados")
except ftplib.error_perm as e:
    check(str(e).startswith("530"), "comandos sin login rechazados")
f.login("bob", "bobpass1")
check(True, "login bob")

print("== FTP: VFS y permisos")
check(sorted(f.nlst()) == ["Buzon", "Peliculas"], "raíz virtual muestra solo sus carpetas")
f.cwd("/Peliculas")
names = sorted(f.nlst())
check(names == ["big.bin", "sub"], "symlink 'escape' oculto en el listado")
mlsd = dict(f.mlsd())
check(mlsd["big.bin"]["size"] == "3000000" and mlsd["sub"]["type"] == "dir", "MLSD correcto")
buf = io.BytesIO()
f.retrbinary("RETR big.bin", buf.write)
check(buf.getvalue() == open(f"{BASE}/share/movies/big.bin", "rb").read(), "descarga completa (EPSV)")
f.set_pasv(True)
f.af = 2
buf = io.BytesIO()
f.sendcmd("TYPE I")
conn = f.transfercmd("RETR big.bin", rest=2999990)
while True:
    d = conn.recv(65536)
    if not d:
        break
    buf.write(d)
conn.close()
f.voidresp()
check(len(buf.getvalue()) == 10, "REST (reanudar descarga)")

for cmd in ["STOR nuevo.txt", "DELE big.bin", "MKD x", "RNFR big.bin"]:
    try:
        if cmd.startswith("STOR"):
            f.storbinary(cmd, io.BytesIO(b"x"))
        else:
            f.sendcmd(cmd)
        check(False, f"{cmd} denegado en carpeta de solo lectura")
    except ftplib.error_perm as e:
        check(str(e).startswith("550"), f"{cmd} denegado en carpeta de solo lectura")

for path in ["/Peliculas/../../secret/pw.txt", "../../../etc/passwd", "/Peliculas/escape/pw.txt",
             "/etc/passwd", f"/Peliculas/{'/..' * 10}/etc/passwd"]:
    try:
        f.retrbinary("RETR " + path, lambda b: None)
        check(False, f"escape bloqueado: {path}")
    except ftplib.error_perm:
        check(True, f"escape bloqueado: {path}")

f.cwd("/Buzon")
f.storbinary("STOR subido.bin", io.BytesIO(b"A" * 100000))
check(os.path.getsize(f"{BASE}/share/inbox/subido.bin") == 100000, "subida en carpeta rw")
f.storbinary("APPE subido.bin", io.BytesIO(b"B" * 10))
check(os.path.getsize(f"{BASE}/share/inbox/subido.bin") == 100010, "APPE")
f.mkd("carpeta")
f.rename("subido.bin", "carpeta/movido.bin")
check(os.path.exists(f"{BASE}/share/inbox/carpeta/movido.bin"), "MKD + RNFR/RNTO")
try:
    f.rename("carpeta/movido.bin", "/Peliculas/robado.bin")
    check(False, "mover a carpeta de solo lectura denegado")
except ftplib.error_perm:
    check(True, "mover a carpeta de solo lectura denegado")
try:
    f.rmd("/Buzon")
    check(False, "no se puede borrar la raíz del montaje")
except ftplib.error_perm:
    check(True, "no se puede borrar la raíz del montaje")
f.delete("carpeta/movido.bin")
f.rmd("carpeta")
check(not os.path.exists(f"{BASE}/share/inbox/carpeta"), "DELE + RMD")

f.sendcmd("TYPE I")
r = f.sendcmd("PASV")
check(r.startswith("227"), "PASV responde: " + r)
lst = []
f.retrlines("LIST", lst.append)  # usa EPSV de nuevo
check(len(lst) == 0, "LIST de carpeta vacía")
f.sendcmd("CWD /")
lst = []
f.retrlines("LIST", lst.append)
check(any("Peliculas" in l and l.startswith("dr-x") for l in lst), "LIST raíz marca solo lectura")

print("== Web: archivos como bob")
bob = Web()
s, j, _ = bob.req("POST", "/api/login", {"user": "bob", "pass": "mal"})
check(s == 401, "login web con contraseña mala")
s, j, _ = bob.req("POST", "/api/login", {"user": "bob", "pass": "bobpass1"})
check(s == 200, "login web bob")
s, j, _ = bob.req("GET", "/api/admin/users")
check(s == 403, "bob no puede administrar")
s, j, _ = bob.req("GET", "/api/fs/list" + q(path="/"))
check(s == 200 and sorted(e["name"] for e in j["entries"]) == ["Buzon", "Peliculas"], "listado raíz web")
s, j, _ = bob.req("GET", "/api/fs/list" + q(path="/Peliculas/../../"))
check(s == 200 and j["path"] == "/", "'..' en web se queda en la raíz virtual")
s, body, h = bob.req("GET", "/api/fs/get" + q(path="/Peliculas/big.bin"),
                     headers={"Range": "bytes=100-199"}, raw=True)
check(s == 206 and len(body) == 100 and h["Content-Range"] == "bytes 100-199/3000000", "descarga con Range")
s, body, h = bob.req("GET", "/api/fs/get" + q(path="/Peliculas/escape/pw.txt"), raw=True)
check(s == 403, "symlink bloqueado en web")
s, j, _ = bob.req("PUT", "/api/fs/put" + q(path="/Buzon/web.txt"), data=b"hola web")
check(s == 200 and open(f"{BASE}/share/inbox/web.txt").read() == "hola web", "subida web (PUT)")
s, j, _ = bob.req("PUT", "/api/fs/put" + q(path="/Peliculas/x.txt"), data=b"no")
check(s == 403, "subida web a solo lectura denegada")
s, j, _ = bob.req("POST", "/api/fs/mkdir" + q(path="/Buzon/d1"))
s2, j, _ = bob.req("PUT", "/api/fs/put" + q(path="/Buzon/d1/f.txt"), data=b"x")
s3, j, _ = bob.req("POST", "/api/fs/rename" + q(**{"from": "/Buzon/d1", "to": "/Buzon/d2"}))
s4, j, _ = bob.req("POST", "/api/fs/delete" + q(path="/Buzon/d2"))
check((s, s2, s3, s4) == (200, 200, 200, 200) and not os.path.exists(f"{BASE}/share/inbox/d2"),
      "mkdir, rename y borrado recursivo web")
s, j, _ = bob.req("POST", "/api/fs/delete" + q(path="/Buzon"))
check(s == 403, "no se puede borrar la raíz del montaje (web)")

print("== SFTP")
import paramiko, hashlib, socket, stat as pystat


def sftp_connect(user, pw):
    t = paramiko.Transport((HOST, 2222))
    t.connect(username=user, password=pw)
    return t, paramiko.SFTPClient.from_transport(t)


try:
    sftp_connect("bob", "malapass")
    check(False, "SFTP: contraseña mala rechazada")
except paramiko.AuthenticationException:
    check(True, "SFTP: contraseña mala rechazada")

t, sf = sftp_connect("bob", "bobpass1")
check(sorted(sf.listdir("/")) == ["Buzon", "Peliculas"], "SFTP: raíz virtual con sus carpetas")
check(sf.normalize(".") == "/", "SFTP: REALPATH '.' es '/'")
check(sorted(sf.listdir("/Peliculas")) == ["big.bin", "sub"], "SFTP: symlink oculto en listado")
st = sf.stat("/Peliculas/big.bin")
check(st.st_size == 3000000 and not (st.st_mode & 0o222), "SFTP: stat, solo lectura sin bits de escritura")
data = sf.open("/Peliculas/big.bin").read()
check(data == open(f"{BASE}/share/movies/big.bin", "rb").read(), "SFTP: descarga completa")
f2 = sf.open("/Peliculas/big.bin")
f2.seek(2999990)
check(len(f2.read()) == 10, "SFTP: lectura con offset")
f2.close()

for desc, fn in [
    ("subir a solo lectura", lambda: sf.open("/Peliculas/x.txt", "w").write(b"x")),
    ("borrar en solo lectura", lambda: sf.remove("/Peliculas/big.bin")),
    ("mkdir en solo lectura", lambda: sf.mkdir("/Peliculas/d")),
    ("mkdir en la raíz virtual", lambda: sf.mkdir("/nueva")),
    ("borrar raíz de montaje", lambda: sf.rmdir("/Buzon")),
    ("renombrar raíz de montaje", lambda: sf.rename("/Buzon", "/Buzon2")),
]:
    try:
        fn()
        check(False, "SFTP: denegado " + desc)
    except (PermissionError, IOError, OSError):
        check(True, "SFTP: denegado " + desc)

for path in ["/Peliculas/../../secret/pw.txt", "../../etc/passwd", "/Peliculas/escape/pw.txt",
             "/etc/passwd", "/Peliculas/sub/../../../../etc/passwd"]:
    try:
        sf.open(path).read()
        check(False, f"SFTP: escape bloqueado {path}")
    except (IOError, OSError):
        check(True, f"SFTP: escape bloqueado {path}")

payload = os.urandom(20_000_000)
with sf.open("/Buzon/grande.bin", "wb") as fh:
    fh.set_pipelined(True)
    fh.write(payload)
check(hashlib.sha256(open(f"{BASE}/share/inbox/grande.bin", "rb").read()).digest()
      == hashlib.sha256(payload).digest(), "SFTP: subida de 20 MB íntegra")
back = sf.open("/Buzon/grande.bin").read()
check(back == payload, "SFTP: descarga de 20 MB íntegra")
sf.mkdir("/Buzon/dir")
sf.rename("/Buzon/grande.bin", "/Buzon/dir/g.bin")
sf.posix_rename("/Buzon/dir/g.bin", "/Buzon/dir/g2.bin")
check(sf.listdir("/Buzon/dir") == ["g2.bin"], "SFTP: mkdir, rename y posix-rename")
try:
    sf.rename("/Buzon/dir/g2.bin", "/Peliculas/robado.bin")
    check(False, "SFTP: mover a solo lectura denegado")
except (IOError, OSError):
    check(True, "SFTP: mover a solo lectura denegado")
sf.remove("/Buzon/dir/g2.bin")
sf.rmdir("/Buzon/dir")
check(not os.path.exists(f"{BASE}/share/inbox/dir"), "SFTP: remove y rmdir")
for i in range(150):
    open(f"{BASE}/share/inbox/n{i:03d}.txt", "w").close()
check(len(sf.listdir("/Buzon")) >= 150, "SFTP: READDIR en varias tandas")
for i in range(150):
    os.remove(f"{BASE}/share/inbox/n{i:03d}.txt")

try:
    ch = t.open_session()
    ch.exec_command("id")
    check(False, "SFTP: exec/shell denegado")
except (paramiko.SSHException, paramiko.ChannelException):
    check(True, "SFTP: exec/shell denegado")
try:
    t.open_channel("direct-tcpip", ("127.0.0.1", 8000), ("127.0.0.1", 1))
    check(False, "SFTP: reenvío de puertos denegado")
except paramiko.ChannelException:
    check(True, "SFTP: reenvío de puertos denegado")

print("== Cambio de contraseña por el propio usuario")
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "dani", "password": "inicial1", "admin": "0",
                                                "enabled": "1", "can_chpass": "1", "must_chpass": "1",
                                                "mounts": f"rw|Buzon|{BASE}/share/inbox"})
check(s == 200, "alta de dani con cambio obligatorio")
try:
    sftp_connect("dani", "inicial1")
    check(False, "SFTP bloqueado hasta cambiar la contraseña")
except paramiko.AuthenticationException:
    check(True, "SFTP bloqueado hasta cambiar la contraseña")
dani = Web()
s, j, _ = dani.req("POST", "/api/login", {"user": "dani", "pass": "inicial1"})
check(s == 200, "dani entra en la web con la inicial")
s, j, _ = dani.req("GET", "/api/me")
check(s == 200 and j["must_chpass"] is True, "la web indica cambio pendiente")
s, j, _ = dani.req("GET", "/api/fs/list" + q(path="/"))
check(s == 403, "sin cambiarla no puede ver archivos")
s, j, _ = dani.req("POST", "/api/me/password", {"old": "malamala", "new": "nueva123"})
check(s == 400, "contraseña actual incorrecta rechazada")
s, j, _ = dani.req("POST", "/api/me/password", {"old": "inicial1", "new": "inicial1"})
check(s == 400, "no puede repetir la misma")
s, j, _ = dani.req("POST", "/api/me/password", {"old": "inicial1", "new": "nueva123"}, csrf=False)
check(s == 403, "cambio sin cabecera CSRF rechazado")
s, j, _ = dani.req("POST", "/api/me/password", {"old": "inicial1", "new": "nueva123"})
check(s == 200, "cambio de contraseña correcto")
s, j, _ = dani.req("GET", "/api/fs/list" + q(path="/"))
check(s == 200, "tras cambiarla ya ve sus carpetas")
t2, sf2 = sftp_connect("dani", "nueva123")
check(sf2.listdir("/") == ["Buzon"], "SFTP funciona con la nueva contraseña")
t2.close()
try:
    sftp_connect("dani", "inicial1")
    check(False, "la contraseña antigua ya no vale")
except paramiko.AuthenticationException:
    check(True, "la contraseña antigua ya no vale")
s, j, _ = admin.req("GET", "/api/admin/users")
d = [u for u in j["users"] if u["name"] == "dani"][0]
check(d["must_chpass"] is False and d["can_chpass"] is True, "el admin ve el cambio completado")
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "dani", "password": "", "admin": "0",
                                                "enabled": "1", "can_chpass": "0", "must_chpass": "0",
                                                "mounts": f"rw|Buzon|{BASE}/share/inbox"})
s, j, _ = dani.req("POST", "/api/me/password", {"old": "nueva123", "new": "otra1234"})
check(s == 400, "si el admin no lo permite, no puede cambiarla")
t2, sf2 = sftp_connect("dani", "nueva123")
t2.close()
check(True, "editar permisos sin contraseña mantiene la actual")

print("== Revocación en caliente")
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "bob", "password": "", "admin": "0",
                                                "enabled": "0", "mounts": mounts})
check(s == 200, "admin desactiva a bob")
try:
    f.nlst()
    check(False, "sesión FTP de bob cortada")
except (ftplib.error_temp, ftplib.error_perm, EOFError) as e:
    check(True, "sesión FTP de bob cortada")
s, j, _ = bob.req("GET", "/api/me")
check(s == 401, "sesión web de bob invalidada")
try:
    sf.listdir("/Buzon")
    check(False, "sesión SFTP de bob cortada")
except Exception:
    check(True, "sesión SFTP de bob cortada")
try:
    sftp_connect("bob", "bobpass1")
    check(False, "bob desactivado no entra por SFTP")
except paramiko.AuthenticationException:
    check(True, "bob desactivado no entra por SFTP")
s, j, _ = admin.req("POST", "/api/admin/user/delete", {"name": "bob"})
check(s == 200, "borrar usuario")
s, j, _ = admin.req("POST", "/api/admin/user/delete", {"name": "admin"})
check(s == 400, "no se puede borrar a sí mismo")

print("== Web: ajustes y página")
s, j, _ = admin.req("POST", "/api/admin/settings", {"pasv_address": "100.64.1.2"})
check(s == 200, "guardar IP pasiva")
s, j, _ = admin.req("POST", "/api/admin/settings", {"pasv_address": "1.2.3.4; rm"})
check(s == 400, "IP pasiva inválida rechazada")
s, body, h = admin.req("GET", "/", raw=True)
check(s == 200 and b"PS5 Share" in body, "página web servida")

print()
print("RESULTADO:", "TODO OK" if FAILS == 0 else f"{FAILS} FALLOS")
sys.exit(1 if FAILS else 0)
