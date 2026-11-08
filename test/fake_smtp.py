"""Servidor SMTP de pruebas con TLS (directo o STARTTLS) que guarda los
mensajes recibidos.  Lo usa smoke_test.py."""
import base64, email, socket, ssl, threading


class FakeSMTP:
    def __init__(self, port, cert, key, implicit, user, password):
        self.msgs, self.auth_fails = [], 0
        self.user, self.password, self.implicit = user, password, implicit
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(5)
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            c, _ = self.sock.accept()
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        try:
            if self.implicit:
                c = self.ctx.wrap_socket(c, server_side=True)
            f = c.makefile("rwb")
            def say(s):
                f.write(s.encode() + b"\r\n"); f.flush()
            say("220 fake ESMTP")
            authed, rcpt, tls = False, [], self.implicit
            while True:
                line = f.readline()
                if not line:
                    return
                cmd = line.decode().strip()
                up = cmd.upper()
                if up.startswith("EHLO"):
                    say("250-fake"); say("250-AUTH PLAIN")
                    say("250 STARTTLS" if not tls else "250 8BITMIME")
                elif up == "STARTTLS" and not tls:
                    say("220 go")
                    f.close()
                    c = self.ctx.wrap_socket(c, server_side=True)
                    f = c.makefile("rwb")
                    tls = True
                elif up.startswith("AUTH PLAIN "):
                    if not tls:
                        say("530 TLS primero"); continue
                    raw = base64.b64decode(cmd[11:]).split(b"\0")
                    if raw[1].decode() == self.user and raw[2].decode() == self.password:
                        authed = True; say("235 ok")
                    else:
                        self.auth_fails += 1; say("535 5.7.8 Username and Password not accepted")
                elif up.startswith("MAIL FROM:"):
                    say("250 ok" if authed else "530 auth")
                elif up.startswith("RCPT TO:"):
                    rcpt.append(cmd[8:].strip("<> ")); say("250 ok")
                elif up == "DATA":
                    say("354 go")
                    data = b""
                    while True:
                        l = f.readline()
                        if l in (b".\r\n", b""):
                            break
                        data += l
                    m = email.message_from_bytes(data)
                    subj = str(email.header.make_header(email.header.decode_header(m["Subject"])))
                    body = m.get_payload(decode=True).decode()
                    self.msgs.append({"to": rcpt[:], "from": m["From"], "subject": subj, "body": body})
                    say("250 queued")
                elif up == "QUIT":
                    say("221 bye"); return
                else:
                    say("500 ?")
        except Exception as e:
            print("fake smtp:", e)
