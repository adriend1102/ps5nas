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

# el admin le pone otra contraseña: los archivos anteriores quedan ilegibles
s, j, _ = admin.req("POST", "/api/admin/user", mk({"password": "reseteada1",
                                                     "mounts": f"enc|Privado|{PRIV}\nrw|Comun|{BASE}/share/inbox"}))
check(s == 200, "el admin cambia la contraseña de eva")
try:
    sf3.listdir("/Privado")
    t3.close()
except Exception:
    pass
t3, sf3 = sftp_connect("eva", "reseteada1")
check(sf3.listdir("/Privado") == [], "tras el cambio del admin, los archivos antiguos no se pueden abrir")
sf3.open("/Privado/nuevo.txt", "wb").write(b"empiezo de cero")
check(sf3.open("/Privado/nuevo.txt").read() == b"empiezo de cero", "y puede seguir usando la carpeta con su nueva clave")
t3.close()

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
