"""Imitación de las cuentas y la Web API de Spotify (HTTPS) para las pruebas.

Implementa solo lo que usa src/spotify.c, con los endpoints de la Web API
posteriores a febrero de 2026 (/me/playlists, /playlists/{id}/items...).
Lo usa smoke_test.py."""
import base64, hashlib, json, ssl, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeSpotify:
    def __init__(self, port, cert, key):
        self.base = f"https://localhost:{port}"
        self.lock = threading.Lock()
        self.challenge = None          # code_challenge del último authorize
        self.code = "CODE123"
        self.access = None
        self.refresh = None
        self.revoked = False           # el refresco devolverá invalid_grant
        self.liked = []                # [(added_at, uri, name, artists, album, ms)] (cualquier orden)
        self.playlists = {}            # id -> {"name", "public", "uris": []}
        self.calls = []                # (método, ruta)
        self.max_add = 0
        self.throttle_once = True      # un 429 en la primera lectura de me/tracks
        self.next_id = 1
        fake = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def reply(self, code, obj=None, headers=None, chunked=False):
                body = json.dumps(obj if obj is not None else {}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                if chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if chunked:
                    for i in range(0, len(body), 7):
                        part = body[i:i + 7]
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                    self.wfile.write(b"0\r\n\r\n")
                else:
                    self.wfile.write(body)
                self.close_connection = True

            def body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def do_POST(self):
                self.route("POST")

            def do_GET(self):
                self.route("GET")

            def route(self, method):
                u = urllib.parse.urlsplit(self.path)
                qs = dict(urllib.parse.parse_qsl(u.query))
                with fake.lock:
                    fake.calls.append((method, u.path))
                if u.path == "/api/token" and method == "POST":
                    return self.token(dict(urllib.parse.parse_qsl(self.body().decode())))
                auth = self.headers.get("Authorization", "")
                if not fake.access or auth != "Bearer " + fake.access:
                    return self.reply(401, {"error": {"status": 401, "message": "The access token expired"}})
                p = u.path
                if p == "/v1/me" and method == "GET":
                    return self.reply(200, {"id": "adri", "display_name": "Adrián"}, chunked=True)
                if p == "/v1/me/tracks" and method == "GET":
                    with fake.lock:
                        if fake.throttle_once:
                            fake.throttle_once = False
                            return self.reply(429, {"error": {"status": 429}}, {"Retry-After": "1"})
                    return self.page(sorted(fake.liked, reverse=True), qs, 50, p, lambda t: {
                        "added_at": t[0],
                        "track": {"uri": t[1], "name": t[2], "duration_ms": t[5],
                                  "album": {"name": t[4]},
                                  "artists": [{"name": a} for a in t[3]]}})
                if p == "/v1/me/playlists" and method == "GET":
                    items = [{"id": k, "name": v["name"]} for k, v in fake.playlists.items()]
                    return self.page(items, qs, 50, p, lambda x: x)
                if p == "/v1/me/playlists" and method == "POST":
                    d = json.loads(self.body())
                    with fake.lock:
                        pid = "new%d" % fake.next_id
                        fake.next_id += 1
                        fake.playlists[pid] = {"name": d["name"], "public": d.get("public"),
                                               "description": d.get("description"), "uris": []}
                    return self.reply(201, {"id": pid, "name": d["name"]})
                parts = p.split("/")
                if len(parts) == 5 and parts[1] == "v1" and parts[2] == "playlists" and parts[4] == "items":
                    pl = fake.playlists.get(parts[3])
                    if not pl:
                        return self.reply(404, {"error": {"status": 404, "message": "Not found"}})
                    if method == "GET":
                        return self.page(pl["uris"], qs, 100, p, lambda uri: {"item": {"uri": uri}})
                    d = json.loads(self.body())
                    if len(d["uris"]) > 100:
                        return self.reply(400, {"error": {"status": 400, "message": "Too many ids"}})
                    with fake.lock:
                        fake.max_add = max(fake.max_add, len(d["uris"]))
                        pl["uris"].extend(d["uris"])
                    return self.reply(201, {"snapshot_id": "x"})
                if "/tracks" in p and "playlists" in p:
                    return self.reply(403, {"error": {"status": 403, "message": "Forbidden"}})
                return self.reply(404, {"error": {"status": 404, "message": "Service not found"}})

            def page(self, items, qs, maxlim, path, fmt):
                limit = min(int(qs.get("limit", 20)), maxlim)
                off = int(qs.get("offset", 0))
                chunk = items[off:off + limit]
                nxt = None
                if off + limit < len(items):
                    nxt = f"{fake.base}{path}?offset={off + limit}&limit={limit}"
                return self.reply(200, {"items": [fmt(x) for x in chunk], "next": nxt,
                                        "total": len(items), "limit": limit, "offset": off})

            def token(self, f):
                with fake.lock:
                    if f.get("grant_type") == "authorization_code":
                        ver = f.get("code_verifier", "")
                        ch = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
                        if (f.get("code") != fake.code or ch != fake.challenge or
                                f.get("redirect_uri") != "http://127.0.0.1:8888/callback" or
                                f.get("client_id") != "abc123"):
                            return self.reply(400, {"error": "invalid_grant", "error_description": "Invalid authorization code"})
                        fake.access, fake.refresh = "AT1", "RT1-" + "x" * 120
                        return self.reply(200, {"access_token": fake.access, "token_type": "Bearer",
                                                "expires_in": 3600, "refresh_token": fake.refresh})
                    if f.get("grant_type") == "refresh_token":
                        if fake.revoked or f.get("refresh_token") != fake.refresh:
                            return self.reply(400, {"error": "invalid_grant", "error_description": "Refresh token revoked"})
                        fake.access = "AT%d" % (int(fake.access[2:]) + 1 if fake.access else 9)
                        fake.refresh = "RT2-" + "y" * 120     # rotación
                        return self.reply(200, {"access_token": fake.access, "expires_in": 3600,
                                                "refresh_token": fake.refresh})
                return self.reply(400, {"error": "unsupported_grant_type"})

        self.srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
