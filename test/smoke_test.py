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
binario = os.urandom(500000)
s, j, _ = bob.req("PUT", "/api/fs/put" + q(path="/Buzon/binario.bin"), data=binario)
check(s == 200 and open(f"{BASE}/share/inbox/binario.bin", "rb").read() == binario,
      "subida web de un binario aleatorio íntegra")
os.remove(f"{BASE}/share/inbox/binario.bin")
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

print("== Carpetas privadas cifradas")
import random
PRIV = f"{BASE}/share/privada"
mk = lambda extra: {"name": "eva", "password": extra.get("password", ""), "admin": "0", "enabled": "1",
                    "can_chpass": "1", "must_chpass": extra.get("must", "0"),
                    "mounts": extra["mounts"]}
os.makedirs(f"{BASE}/share/llena", exist_ok=True)
open(f"{BASE}/share/llena/algo.txt", "w").write("x")
s, j, _ = admin.req("POST", "/api/admin/user", mk({"password": "temporal1", "must": "1",
                                                     "mounts": f"enc|Privado|{BASE}/share/llena"}))
check(s == 400 and "vacía" in j["error"], "no se puede cifrar una carpeta con archivos")
s, j, _ = admin.req("POST", "/api/admin/user", mk({"password": "temporal1", "must": "1",
                                                     "mounts": f"enc|Privado|{BASE}/share/inbox"}))
check(s == 400, "no se puede cifrar una carpeta que usa otro usuario")
s, j, _ = admin.req("POST", "/api/admin/user", mk({"password": "temporal1", "must": "1",
                                                     "mounts": f"enc|Privado|{PRIV}\nrw|Comun|{BASE}/share/inbox"}))
check(s == 200 and os.path.isdir(PRIV), "carpeta privada creada para eva")
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "admin", "password": "", "admin": "1", "enabled": "1",
                                                "can_chpass": "1", "must_chpass": "0",
                                                "mounts": f"rw|Todo|{PRIV}"})
check(s == 400, "el admin no puede montarse la carpeta privada de eva")

eva = Web()
eva.req("POST", "/api/login", {"user": "eva", "pass": "temporal1"})
s, j, _ = eva.req("POST", "/api/me/password", {"old": "temporal1", "new": "secreta99"})
check(s == 200, "eva cambia su contraseña temporal")
s, j, _ = admin.req("GET", "/api/admin/users")
check([u for u in j["users"] if u["name"] == "eva"][0]["has_key"] is True,
      "la clave se crea al poner su contraseña propia")
s, j, _ = eva.req("GET", "/api/fs/list" + q(path="/Privado"))
check(s == 200, "y la carpeta privada se abre sin volver a entrar")

t3, sf3 = sftp_connect("eva", "secreta99")
check(sorted(sf3.listdir("/")) == ["Comun", "Privado"], "eva ve su carpeta privada por SFTP")
s, j, _ = admin.req("GET", "/api/admin/users")
check([u for u in j["users"] if u["name"] == "eva"][0]["has_key"] is True, "la clave se conserva")

MARK = b"TEXTO-EN-CLARO-QUE-NO-DEBE-APARECER-"
files = {}
for size in [0, 1, 65535, 65536, 65537, 200000, 3 * 65536 + 17]:
    data = (MARK * (size // len(MARK) + 1))[:size] if size < 1000 else os.urandom(size // 2) + (MARK * 2000)[: size - size // 2]
    name = f"archivo secreto {size}.bin"
    with sf3.open("/Privado/" + name, "wb") as fh:
        fh.set_pipelined(True)
        fh.write(data)
    files[name] = data
ok = all(sf3.open("/Privado/" + n).read() == d for n, d in files.items())
check(ok, "SFTP cifrado: lectura igual a lo escrito (0 B a 200 KB, bordes de bloque)")
check(all(sf3.stat("/Privado/" + n).st_size == len(d) for n, d in files.items()), "SFTP cifrado: tamaños en claro")
check(sorted(sf3.listdir("/Privado")) == sorted(files), "SFTP cifrado: nombres en claro para eva")

# escrituras en posiciones arbitrarias y huecos
model = bytearray(files["archivo secreto 200000.bin"])
rnd = random.Random(7)
with sf3.open("/Privado/archivo secreto 200000.bin", "r+") as fh:
    for _ in range(40):
        off = rnd.randrange(0, len(model) + 70000)
        chunk = os.urandom(rnd.randrange(1, 90000))
        fh.seek(off)
        fh.write(chunk)
        if off > len(model):
            model.extend(b"\0" * (off - len(model)))
        model[off:off + len(chunk)] = chunk
back = sf3.open("/Privado/archivo secreto 200000.bin").read()
check(back == bytes(model), "SFTP cifrado: escrituras aleatorias y huecos")
with sf3.open("/Privado/log.txt", "a") as fh:
    fh.write(b"uno\n")
with sf3.open("/Privado/log.txt", "a") as fh:
    fh.write(b"dos\n")
check(sf3.open("/Privado/log.txt").read() == b"uno\ndos\n", "SFTP cifrado: añadir al final")
sf3.mkdir("/Privado/Fotos de vacaciones")
sf3.open("/Privado/Fotos de vacaciones/playa.jpg", "wb").write(MARK * 10)
sf3.rename("/Privado/Fotos de vacaciones/playa.jpg", "/Privado/Fotos de vacaciones/mar.jpg")
check(sf3.listdir("/Privado/Fotos de vacaciones") == ["mar.jpg"], "SFTP cifrado: carpetas y renombrar")
try:
    sf3.open("/Privado/" + "x" * 150, "wb").write(b"1")
    check(False, "nombre demasiado largo rechazado")
except (IOError, OSError):
    check(True, "nombre demasiado largo rechazado")

# lo que hay de verdad en el disco
disk_names, leaked = [], False
for root, dirs, fnames in os.walk(PRIV):
    for n in dirs + fnames:
        disk_names.append(n)
    for n in fnames:
        raw = open(os.path.join(root, n), "rb").read()
        if MARK in raw:
            leaked = True
plain_names = set(files) | {"log.txt", "Fotos de vacaciones", "mar.jpg"}
check(disk_names and not any(n in plain_names or "secreto" in n or "vacaciones" in n for n in disk_names),
      "en el disco no aparecen los nombres")
check(not leaked, "en el disco no aparece el contenido")
check(all(n == n.lower() for n in disk_names), "nombres en disco aptos para exFAT (minúsculas)")

# web de eva
s, j, _ = eva.req("GET", "/api/fs/list" + q(path="/Privado"))
check(s == 403 or s == 200, "lista web antes de volver a entrar")
eva2 = Web()
eva2.req("POST", "/api/login", {"user": "eva", "pass": "secreta99"})
s, j, _ = eva2.req("GET", "/api/fs/list" + q(path="/Privado"))
names_web = sorted(e["name"] for e in j.get("entries", []))
check(s == 200 and "log.txt" in names_web and "Fotos de vacaciones" in names_web, "web: lista descifrada")
sizes = {e["name"]: e["size"] for e in j["entries"]}
check(sizes.get("archivo secreto 65537.bin") == 65537, "web: tamaño en claro")
s, body, h = eva2.req("GET", "/api/fs/get" + q(path="/Privado/archivo secreto 200000.bin"),
                      headers={"Range": "bytes=65530-65545"}, raw=True)
check(s == 206 and body == bytes(model)[65530:65546], "web: descarga parcial descifrada")
up = os.urandom(300000)
s, j, _ = eva2.req("PUT", "/api/fs/put" + q(path="/Privado/subido web.bin"), data=up)
got = sf3.open("/Privado/subido web.bin").read() if s == 200 else b""
check(s == 200 and got == up, "web: subida cifrada %s %d/%d" % (j if s != 200 else "", len(got), len(up)))
s, j, _ = eva2.req("POST", "/api/fs/delete" + q(path="/Privado/Fotos de vacaciones"))
check(s == 200 and "Fotos de vacaciones" not in sf3.listdir("/Privado"), "web: borrar carpeta cifrada")

# el admin y el FTP no ven nada útil
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "admin", "password": "", "admin": "1", "enabled": "1",
                                                "can_chpass": "1", "must_chpass": "0",
                                                "mounts": f"ro|Disco|{BASE}/share"})
s, j, _ = admin.req("GET", "/api/fs/list" + q(path="/Disco/privada"))
admin_sees = [e["name"] for e in j["entries"]]
check(s == 200 and admin_sees and not any(n in plain_names or "secreto" in n for n in admin_sees),
      "el admin solo ve nombres cifrados")
s, body, _ = admin.req("GET", "/api/fs/get" + q(path="/Disco/privada/" + admin_sees[0]), raw=True)
check(MARK not in body, "el admin solo puede bajar datos cifrados")
fe = ftplib.FTP()
fe.connect(HOST, 2121, timeout=20)
fe.login("eva", "secreta99")
check(fe.nlst("/") == ["Comun"], "FTP no muestra la carpeta privada")
try:
    fe.nlst("/Privado")
    check(False, "FTP no entra en la carpeta privada")
except ftplib.error_perm:
    check(True, "FTP no entra en la carpeta privada")
fe.quit()

# cambio de contraseña por eva: la clave se vuelve a envolver
s, j, _ = eva2.req("POST", "/api/me/password", {"old": "secreta99", "new": "otraClave7"})
t3.close()
t3, sf3 = sftp_connect("eva", "otraClave7")
check(sf3.open("/Privado/log.txt").read() == b"uno\ndos\n", "tras cambiar su contraseña sigue leyendo sus archivos")
s, j, _ = admin.req("POST", "/api/admin/user", mk({"mounts": f"rw|Privado|{PRIV}"}))
check(s == 400, "no se puede quitar el cifrado de una carpeta con archivos")

# el admin le pone otra contraseña: como se conocía la anterior, no pierde nada
s, j, _ = admin.req("POST", "/api/admin/user", mk({"password": "reseteada1",
                                                     "mounts": f"enc|Privado|{PRIV}\nrw|Comun|{BASE}/share/inbox"}))
check(s == 200, "el admin cambia la contraseña de eva")
try:
    sf3.listdir("/Privado")
    t3.close()
except Exception:
    pass
t3, sf3 = sftp_connect("eva", "reseteada1")
check(sf3.open("/Privado/log.txt").read() == b"uno\ndos\n",
      "tras el cambio del admin conserva sus archivos cifrados")
sf3.open("/Privado/nuevo.txt", "wb").write(b"sigo igual")
check(sf3.open("/Privado/nuevo.txt").read() == b"sigo igual", "y puede seguir usando la carpeta")
t3.close()

print("== Contraseñas visibles para el administrador")
s, j, _ = admin.req("POST", "/api/admin/user/password", {"name": "eva"})
check(s == 200 and j.get("password") == "reseteada1", "el admin ve la contraseña de eva")
s, j, _ = admin.req("POST", "/api/admin/user/password", {"name": "bob"})
check(s == 200 and j.get("password") == "bobpass1", "el admin ve la contraseña de bob")
s, j, _ = admin.req("POST", "/api/admin/user/password", {"name": "eva"}, csrf=False)
check(s == 403, "ver contraseñas exige la cabecera CSRF")
s, j, _ = bob.req("POST", "/api/admin/user/password", {"name": "eva"})
check(s == 403, "un usuario normal no puede ver contraseñas")
conf = open(f"{BASE}/conf/users.conf").read()
check("reseteada1" not in conf and "bobpass1" not in conf, "users.conf no guarda contraseñas en claro")
check(os.path.exists(f"{BASE}/conf/master.key") and (os.stat(f"{BASE}/conf/master.key").st_mode & 0o077) == 0,
      "clave maestra creada y privada")

print("== Carpeta privada nueva con la sesión ya abierta")
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "bob", "password": "", "admin": "0", "enabled": "1",
                                                "can_chpass": "1", "must_chpass": "0",
                                                "mounts": mounts + f"\nenc|Cofre|{BASE}/share/cofre_bob"})
check(s == 200, "el admin da a bob una carpeta privada")
s, j, _ = bob.req("PUT", "/api/fs/put" + q(path="/Cofre/nota.txt"), data=b"hola cofre")
check(s == 200, "bob la usa sin cerrar sesión (clave abierta con la contraseña guardada)")
s, body, _ = bob.req("GET", "/api/fs/get" + q(path="/Cofre/nota.txt"), raw=True)
check(body == b"hola cofre" and os.listdir(f"{BASE}/share/cofre_bob") != ["nota.txt"], "y se guarda cifrada")

print("== Correo saliente (SMTP con TLS)")
sys.path.insert(0, os.path.dirname(__file__))
from fake_smtp import FakeSMTP
CA = BASE + "/ca"
smtps = FakeSMTP(465, CA + "/srv.pem", CA + "/srv.key", True, "nas@example.com", "abcdefghijklmnop")
smtp_st = FakeSMTP(2525, CA + "/srv.pem", CA + "/srv.key", False, "nas@example.com", "abcdefghijklmnop")
def wait_mail(srv, n, t=8):
    for _ in range(t * 10):
        if len(srv.msgs) >= n:
            return True
        time.sleep(0.1)
    return False
s, j, _ = Web().req("GET", "/api/status")
check(s == 200 and j["recover_email"] is False and j["recover_admin"] is True and j["name"] == "PS5NAS",
      "sin correo configurado solo se ofrece pedirla al admin")
s, j, _ = admin.req("POST", "/api/admin/mail/test", {"to": "yo@example.com"})
check(s == 400 and "configurado" in j["error"], "prueba sin configurar: error claro")
s, j, _ = admin.req("POST", "/api/admin/settings", {"smtp_user": "nas@example.com", "smtp_pass": "abcd efgh ijkl mnop",
                                                    "smtp_host": "localhost", "smtp_port": "465"})
check(s == 200, "guardar cuenta de correo")
conf = open(f"{BASE}/conf/users.conf").read()
check("abcdefghijklmnop" not in conf and "abcd efgh" not in conf, "la contraseña de correo se guarda cifrada")
s, j, _ = admin.req("GET", "/api/admin/settings")
check(j["smtp_pass_set"] is True and "smtp_pass" not in j, "los ajustes no devuelven la contraseña de correo")
s, j, _ = admin.req("POST", "/api/admin/mail/test", {"to": "yo@example.com"})
check(s == 200 and len(smtps.msgs) == 1 and smtps.msgs[0]["to"] == ["yo@example.com"]
      and smtps.msgs[0]["subject"] == "PS5NAS: correo de prueba", "correo de prueba por TLS directo (465) %s" % j)
admin.req("POST", "/api/admin/settings", {"smtp_port": "2525"})
s, j, _ = admin.req("POST", "/api/admin/mail/test", {"to": "yo@example.com"})
check(s == 200 and len(smtp_st.msgs) == 1, "correo de prueba con STARTTLS (2525) %s" % j)
admin.req("POST", "/api/admin/settings", {"smtp_host": "127.0.0.1"})
s, j, _ = admin.req("POST", "/api/admin/mail/test", {"to": "yo@example.com"})
check(s == 400 and len(smtp_st.msgs) == 1 and "no una IP" in j["error"],
      "servidor por IP rechazado (no se podría comprobar su certificado)")
untrusted = FakeSMTP(2526, CA + "/self.pem", CA + "/self.key", False, "nas@example.com", "abcdefghijklmnop")
admin.req("POST", "/api/admin/settings", {"smtp_host": "localhost", "smtp_port": "2526"})
s, j, _ = admin.req("POST", "/api/admin/mail/test", {"to": "yo@example.com"})
check(s == 400 and not untrusted.msgs, "certificado de una CA no reconocida: rechazado")
admin.req("POST", "/api/admin/settings", {"smtp_host": "localhost", "smtp_port": "465", "smtp_pass": "mala"})
s, j, _ = admin.req("POST", "/api/admin/mail/test", {"to": "yo@example.com"})
check(s == 400 and "contraseña de aplicación" in j["error"], "contraseña de correo mala: error claro")
admin.req("POST", "/api/admin/settings", {"smtp_pass": "abcdefghijklmnop"})
s, j, _ = admin.req("POST", "/api/admin/settings", {"smtp_user": "no es un correo"})
check(s == 400, "cuenta de correo no válida rechazada")

print("== Olvidé mi contraseña: por correo")
s, j, _ = admin.req("POST", "/api/admin/user", mk({"mounts": f"enc|Privado|{PRIV}\nrw|Comun|{BASE}/share/inbox"}) |
                    {"email": "Eva@Example.com"})
check(s == 200, "el admin pone el correo de recuperación de eva")
s, j, _ = admin.req("POST", "/api/admin/user", mk({"mounts": f"enc|Privado|{PRIV}"}) | {"email": "no-vale"})
check(s == 400, "correo de recuperación no válido rechazado")
s, j, _ = admin.req("GET", "/api/admin/users")
check([u for u in j["users"] if u["name"] == "eva"][0]["email"] == "Eva@Example.com", "el correo aparece en la ficha")
s, j, _ = Web().req("GET", "/api/status")
check(j["recover_email"] is True, "con el correo configurado se ofrece la recuperación por correo")
n0 = len(smtps.msgs)
s, j, _ = Web().req("POST", "/api/forgot/email", {"user": "eva", "email": "otro@example.com"})
check(s == 200, "correo equivocado: misma respuesta")
s, j, _ = Web().req("POST", "/api/forgot/email", {"user": "nadie", "email": "eva@example.com"})
check(s == 200, "usuario inexistente: misma respuesta")
time.sleep(1)
check(len(smtps.msgs) == n0, "y no se envía nada")
s, j, _ = Web().req("POST", "/api/forgot/email", {"user": "eva", "email": "eva@example.com"})
check(s == 200 and wait_mail(smtps, n0 + 1), "correo correcto (sin distinguir mayúsculas): se envía")
m = smtps.msgs[-1]
check(m["to"] == ["Eva@Example.com"] and "reseteada1" in m["body"] and "eva" in m["body"],
      "el correo lleva su usuario y su contraseña actual")
s, j, _ = Web().req("POST", "/api/forgot/email", {"user": "eva", "email": "eva@example.com"})
time.sleep(1)
check(len(smtps.msgs) == n0 + 1, "no se repite el envío enseguida")
admin.req("POST", "/api/admin/settings", {"recover_email": "0"})
s, j, _ = Web().req("POST", "/api/forgot/email", {"user": "eva", "email": "eva@example.com"})
check(s == 403, "se puede desactivar la recuperación por correo")
admin.req("POST", "/api/admin/settings", {"recover_email": "1"})

print("== Olvidé mi contraseña: lo acepta un administrador")
anon = Web()
s, j, _ = anon.req("POST", "/api/forgot/request", {"user": "bob"})
tok = j.get("token", "")
check(s == 200 and len(tok) == 64, "bob pide su contraseña al admin")
s, j, _ = anon.req("GET", "/api/forgot/status" + q(token=tok))
check(j["state"] == "pending", "queda pendiente")
s, j, _ = admin.req("GET", "/api/admin/requests")
reqs = [r for r in j["requests"] if r["user"] == "bob"]
check(len(reqs) == 1 and reqs[0]["pw_known"], "el admin ve la solicitud")
s, j, _ = bob.req("GET", "/api/admin/requests")
check(s == 403, "un usuario normal no ve las solicitudes")
s, j, _ = admin.req("POST", "/api/admin/request", {"id": reqs[0]["id"], "action": "approve"})
check(s == 200, "el admin la acepta")
s, j, _ = anon.req("GET", "/api/forgot/status" + q(token=tok))
check(j.get("state") == "approved" and j.get("password") == "bobpass1" and j.get("user") == "bob",
      "y bob ve su contraseña en su pantalla")
s, j, _ = anon.req("GET", "/api/forgot/status" + q(token=tok))
check(j.get("state") == "unknown", "solo se entrega una vez")
s, j, _ = anon.req("GET", "/api/forgot/status" + q(token="0" * 64))
check(j.get("state") == "unknown" and "password" not in j, "un token inventado no da nada")
s, j, _ = anon.req("POST", "/api/forgot/request", {"user": "eva"})
tok2 = j["token"]
s, j, _ = admin.req("GET", "/api/admin/requests")
rid = [r for r in j["requests"] if r["user"] == "eva"][0]["id"]
admin.req("POST", "/api/admin/request", {"id": rid, "action": "deny"})
s, j, _ = anon.req("GET", "/api/forgot/status" + q(token=tok2))
check(j.get("state") == "denied" and "password" not in j, "solicitud rechazada")
s, j, _ = anon.req("POST", "/api/forgot/request", {"user": "fantasma"})
s2, j2, _ = admin.req("GET", "/api/admin/requests")
check(s == 200 and not any(r["user"] == "fantasma" for r in j2["requests"]),
      "usuario inexistente: misma respuesta y no molesta al admin")

print("== Mi cuenta: correo de recuperación")
eva2 = Web()
eva2.req("POST", "/api/login", {"user": "eva", "pass": "reseteada1"})
s, j, _ = eva2.req("POST", "/api/me/email", {"email": "nuevo@example.com", "pass": "mala"})
check(s == 403, "cambiar el correo exige su contraseña")
s, j, _ = eva2.req("POST", "/api/me/email", {"email": "nuevo@example.com", "pass": "reseteada1"})
s2, me, _ = eva2.req("GET", "/api/me")
check(s == 200 and me["email"] == "nuevo@example.com", "eva cambia su correo de recuperación")
s, j, _ = admin.req("POST", "/api/admin/user", {"name": "zoe", "password": "temporal9", "admin": "0", "enabled": "1",
                                                "can_chpass": "1", "must_chpass": "1", "mounts": ""})
zoe = Web()
zoe.req("POST", "/api/login", {"user": "zoe", "pass": "temporal9"})
s, j, _ = zoe.req("POST", "/api/me/password", {"old": "temporal9", "new": "deZoe123", "email": "zoe@example.com"})
s2, me, _ = zoe.req("GET", "/api/me")
check(s == 200 and me["email"] == "zoe@example.com" and not me["must_chpass"],
      "al cambiar la contraseña la primera vez puede poner su correo")
s, j, _ = admin.req("POST", "/api/admin/user/password", {"name": "zoe"})
check(j.get("password") == "deZoe123", "el admin ve la contraseña que eligió zoe")

print("== Recordar sesión y reinicio del servidor")
import signal, subprocess, socket
def restart():
    pid = int(open(BASE + "/server.pid").read())
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        try:
            os.kill(pid, 0)
            time.sleep(0.1)
        except OSError:
            break
    p = subprocess.Popen(["./ps5share-linux", "-d", BASE + "/conf"], stdout=open(BASE + "/server2.log", "a"),
                         stderr=subprocess.STDOUT)
    open(BASE + "/server.pid", "w").write(str(p.pid))
    for _ in range(100):
        try:
            for port in (8000, 2121, 2222):
                socket.create_connection(("127.0.0.1", port), 1).close()
            return
        except OSError:
            time.sleep(0.1)
evr = Web()
s, j, h = evr.req("POST", "/api/login", {"user": "eva", "pass": "reseteada1", "remember": "1"})
check(s == 200 and "Max-Age=15552000" in h.get("Set-Cookie", ""), "recordar sesión: cookie de 180 días")
s, j, h = eva2.req("POST", "/api/login", {"user": "eva", "pass": "reseteada1"})
check(s == 200 and "Max-Age" not in h.get("Set-Cookie", ""), "sin recordar: cookie de sesión del navegador")
token = [c.value for c in evr.jar if c.name == "ps5s"][0]
sess = open(BASE + "/conf/sessions.conf").read()
check("eva" in sess and token not in sess, "las sesiones recordadas se guardan sin el token")
restart()
s, j, _ = evr.req("GET", "/api/fs/list" + q(path="/Privado"))
check(s == 200 and "log.txt" in [e["name"] for e in j.get("entries", [])],
      "tras reiniciar, la sesión recordada sigue abierta y su carpeta privada también")
s, j, _ = eva2.req("GET", "/api/me")
check(s == 401, "la sesión no recordada se cierra al reiniciar")
admin = Web()
admin.req("POST", "/api/login", {"user": "admin", "pass": "adminpass"})
s, j, _ = admin.req("POST", "/api/admin/mail/test", {"to": "yo@example.com"})
check(s == 200, "la cuenta de correo sigue funcionando tras reiniciar")
evr.req("POST", "/api/logout")
check("eva" not in open(BASE + "/conf/sessions.conf").read(), "cerrar sesión la borra del disco")

print("== Usuarios de versiones anteriores (contraseña aún desconocida)")
conf = open(BASE + "/conf/users.conf").read()
open(BASE + "/conf/users.conf", "w").write("\n".join(l for l in conf.split("\n") if not l.startswith("pw\teva\t")) + "\n")
restart()
admin = Web()
admin.req("POST", "/api/login", {"user": "admin", "pass": "adminpass"})
s, j, _ = admin.req("GET", "/api/admin/users")
check([u for u in j["users"] if u["name"] == "eva"][0]["pw_known"] is False, "eva aparece con contraseña desconocida")
s, j, _ = admin.req("POST", "/api/admin/user/password", {"name": "eva"})
check(s == 404 and "próxima vez" in j["error"], "el admin ve por qué no se puede mostrar")
anon = Web()
s, j, _ = anon.req("POST", "/api/forgot/request", {"user": "eva"})
s, j, _ = admin.req("GET", "/api/admin/requests")
r = [r for r in j["requests"] if r["user"] == "eva"][0]
check(r["pw_known"] is False, "la solicitud avisa de que no se conoce")
s, j, _ = admin.req("POST", "/api/admin/request", {"id": r["id"], "action": "approve"})
check(s == 409, "no se puede aceptar sin conocerla")
t3, sf3 = sftp_connect("eva", "reseteada1")
t3.close()
s, j, _ = admin.req("GET", "/api/admin/users")
check([u for u in j["users"] if u["name"] == "eva"][0]["pw_known"] is True,
      "al entrar por SFTP se guarda su contraseña")
s, j, _ = admin.req("POST", "/api/admin/request", {"id": r["id"], "action": "approve"})
check(s == 200, "y ya se puede aceptar la solicitud")
bob = Web()
bob.req("POST", "/api/login", {"user": "bob", "pass": "bobpass1"})
f = ftplib.FTP()
f.connect(HOST, 2121, timeout=20)
f.login("bob", "bobpass1")
t, sf = sftp_connect("bob", "bobpass1")

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

print("== Apps: accesos directos a otras webs")
evw = Web(); evw.req("POST", "/api/login", {"user": "eva", "pass": "reseteada1"})
zw = Web(); zw.req("POST", "/api/login", {"user": "zoe", "pass": "deZoe123"})
s, j, _ = admin.req("POST", "/api/admin/link", {"name": "Machete IA", "target": "7860", "all": "1", "users": ""})
check(s == 200 and len(j.get("id", "")) == 16, "el admin añade una app para todos")
id_all = j["id"]
s, j, _ = admin.req("POST", "/api/admin/link", {"name": "Tailscale", "target": ":8090/", "all": "0", "users": "eva"})
check(s == 200, "una app solo para eva (se acepta «:puerto»)")
id_eva = j["id"]
s, j, _ = admin.req("POST", "/api/admin/link", {"name": "Router", "target": "http://192.168.1.1/", "all": "0", "users": ""})
check(s == 200, "una app solo para administradores (URL completa)")
id_adm = j["id"]
for bad in ["javascript:alert(1)", "0", "70000", "8080 extra", "8080?x", "ftp://x", ""]:
    s, j, _ = admin.req("POST", "/api/admin/link", {"name": "Mala", "target": bad, "all": "1", "users": ""})
    check(s == 400, f"destino no válido rechazado: {bad!r}")
s, j, _ = admin.req("POST", "/api/admin/link", {"name": "X", "target": "80", "all": "0", "users": "nadie"})
check(s == 400, "usuario inexistente rechazado")
s, j, _ = admin.req("GET", "/api/links")
names = {l["name"]: l for l in j["links"]}
check(set(names) == {"Machete IA", "Tailscale", "Router"} and names["Tailscale"]["target"] == "8090/"
      and names["Tailscale"]["users"] == ["eva"] and names["Machete IA"]["all"] is True,
      "el admin las ve todas, con a quién se muestran")
s, j, _ = evw.req("GET", "/api/links")
check(sorted(l["name"] for l in j["links"]) == ["Machete IA", "Tailscale"] and "users" not in j["links"][0],
      "eva ve la de todos y la suya, sin la lista de usuarios")
s, j, _ = zw.req("GET", "/api/links")
check([l["name"] for l in j["links"]] == ["Machete IA"], "zoe solo ve la de todos")
s, j, _ = Web().req("GET", "/api/links")
check(s == 401, "sin sesión no se ven")
s, j, _ = evw.req("POST", "/api/admin/link", {"name": "Mía", "target": "80", "all": "1", "users": ""})
check(s == 403, "un usuario normal no puede crear apps")
s, j, _ = admin.req("POST", "/api/admin/link", {"id": id_eva, "name": "Tailscale", "target": "8090",
                                                "all": "0", "users": "eva,zoe"})
s2, j2, _ = zw.req("GET", "/api/links")
check(s == 200 and sorted(l["name"] for l in j2["links"]) == ["Machete IA", "Tailscale"], "editar: ahora también zoe")
admin.req("POST", "/api/admin/user", {"name": "temporal", "password": "temporal1", "admin": "0", "enabled": "1",
                                      "can_chpass": "1", "must_chpass": "0", "mounts": ""})
admin.req("POST", "/api/admin/link", {"id": id_adm, "name": "Router", "target": "http://192.168.1.1/",
                                      "all": "0", "users": "temporal"})
admin.req("POST", "/api/admin/user/delete", {"name": "temporal"})
s, j, _ = admin.req("GET", "/api/links")
check([l for l in j["links"] if l["id"] == id_adm][0]["users"] == [], "al borrar un usuario desaparece de sus apps")
conf = open(f"{BASE}/conf/users.conf").read()
check(f"link\t{id_all}\t1\tMachete IA\t7860" in conf and f"linkuser\t{id_eva}\tzoe" in conf,
      "las apps se guardan en users.conf")
s, j, _ = admin.req("POST", "/api/admin/link/delete", {"id": id_adm})
s2, j2, _ = admin.req("GET", "/api/links")
check(s == 200 and len(j2["links"]) == 2, "borrar una app")

print("== Web: ajustes y página")
s, j, _ = admin.req("POST", "/api/admin/settings", {"pasv_address": "100.64.1.2"})
check(s == 200, "guardar IP pasiva")
s, j, _ = admin.req("POST", "/api/admin/settings", {"pasv_address": "1.2.3.4; rm"})
check(s == 400, "IP pasiva inválida rechazada")
s, body, h = admin.req("GET", "/", raw=True)
check(s == 200 and b"PS5NAS" in body, "página web servida")

print()
print("RESULTADO:", "TODO OK" if FAILS == 0 else f"{FAILS} FALLOS")
sys.exit(1 if FAILS else 0)
