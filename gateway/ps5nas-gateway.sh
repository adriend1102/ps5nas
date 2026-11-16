#!/usr/bin/env bash
# PS5NAS - pasarela pública en un servidor (Oracle Cloud «Always Free», u otro
# Ubuntu/Debian).  Copyright (C) 2026  ps5share contributors.  GPLv3.
#
# Deja PS5NAS (y las apps que publiques desde su pestaña «Apps») accesibles
# desde internet con HTTPS de verdad, sin VPN en los móviles:
#
#   https://DOMINIO/              -> PS5NAS (web, SFTP aparte, gestor de contraseñas)
#   https://APP.DOMINIO/          -> cada app publicada, solo tras iniciar sesión en PS5NAS
#   sftp://DOMINIO:2222           -> SFTP de PS5NAS
#
# El servidor entra en tu red de Tailscale y llega a la PS5 por ella; la PS5 no
# abre nada a internet.  Caddy pone los certificados (Let's Encrypt) y
# pregunta a PS5NAS quién puede entrar en cada app.  Cada minuto se sincroniza
# con PS5NAS: si añades o quitas apps en el panel, se aplica solo.
#
# Uso (como root):
#   sudo bash ps5nas-gateway.sh --domain tunas.duckdns.org --duckdns-token TOKEN \
#        --ps5 100.x.y.z --secret CLAVE_DE_PS5NAS
#
# Opciones:
#   --domain D          dominio público (con DuckDNS: NOMBRE.duckdns.org)
#   --duckdns-token T   token de duckdns.org (mantiene la IP al día; opcional
#                       si el dominio no es de DuckDNS)
#   --ps5 IP            IP de Tailscale de la PS5 (100.x.y.z)
#   --secret S          clave de la pasarela (Ajustes de PS5NAS → Acceso desde internet)
#   --http-port N       puerto web de PS5NAS (por defecto 8000)
#   --sftp-port N       puerto público para SFTP (por defecto 2222; 0 = sin SFTP)
#   --email E           correo para Let's Encrypt (opcional)
#   --uninstall         quita la pasarela (Caddy, sincronización y SFTP)
set -euo pipefail

CONF_DIR=/etc/ps5nas-gateway
ENV_FILE=$CONF_DIR/env

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo; echo "==> $*"; }

DOMAIN="" DUCK="" PS5="" SECRET="" HTTP_PORT=8000 SFTP_PUBLIC=2222 EMAIL="" UNINSTALL=0
[ -f "$ENV_FILE" ] && . "$ENV_FILE"     # reinstalar sin repetir todo
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2,,}"; shift 2 ;;
    --duckdns-token) DUCK="$2"; shift 2 ;;
    --ps5) PS5="$2"; shift 2 ;;
    --secret) SECRET="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --sftp-port) SFTP_PUBLIC="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n 2,32p "$0"; exit 0 ;;
    *) die "opción desconocida: $1 (usa --help)" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "ejecútalo con sudo"

if [ "$UNINSTALL" = 1 ]; then
  systemctl disable --now ps5nas-gateway-sync.timer ps5nas-duckdns.timer ps5nas-sftp.service 2>/dev/null || true
  rm -f /etc/systemd/system/ps5nas-* /usr/local/bin/ps5nas-gateway-sync
  systemctl stop caddy 2>/dev/null || true
  systemctl daemon-reload
  echo "Pasarela quitada (Caddy y Tailscale siguen instalados; $CONF_DIR se conserva)."
  exit 0
fi

[[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$ ]] || die "falta --domain (p. ej. tunas.duckdns.org)"
[[ "$PS5" =~ ^100\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "falta --ps5 con la IP de Tailscale de la PS5 (100.x.y.z)"
[[ "$SECRET" =~ ^[0-9a-f]{64}$ ]] || die "falta --secret (64 caracteres, en Ajustes de PS5NAS)"
[[ "$HTTP_PORT" =~ ^[0-9]+$ && "$SFTP_PUBLIC" =~ ^[0-9]+$ ]] || die "puertos no válidos"
if [[ "$DOMAIN" == *.duckdns.org ]] && [ -z "$DUCK" ]; then
  die "con un dominio de DuckDNS hace falta --duckdns-token"
fi

export DEBIAN_FRONTEND=noninteractive

info "Paquetes"
apt-get update -q
apt-get install -y -q curl jq socat gnupg debian-keyring debian-archive-keyring \
  apt-transport-https ca-certificates iptables >/dev/null
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install -y -q iptables-persistent >/dev/null

if ! command -v caddy >/dev/null; then
  info "Caddy (servidor web con HTTPS automático)"
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key |
    gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -q
  apt-get install -y -q caddy >/dev/null
fi

if ! command -v tailscale >/dev/null; then
  info "Tailscale"
  curl -fsSL https://tailscale.com/install.sh | sh
fi
if ! tailscale status >/dev/null 2>&1; then
  info "Conecta este servidor a tu Tailscale: abre el enlace que sale abajo e inicia sesión"
  tailscale up --hostname=ps5nas-gateway --accept-dns=false
fi

info "Comprobando que se llega a la PS5 ($PS5:$HTTP_PORT)"
if ! curl -fsS -m 10 -H "X-PS5NAS-Gateway: $SECRET" "http://$PS5:$HTTP_PORT/api/gate/routes" >/dev/null; then
  echo "AVISO: no se pudo hablar con PS5NAS. Comprueba que la PS5 está encendida, que"
  echo "       el acceso desde internet está activado en Ajustes y que la clave es la misma."
  echo "       La instalación sigue; la sincronización lo reintentará cada minuto."
fi

info "Cortafuegos (80, 443${SFTP_PUBLIC:+ y $SFTP_PUBLIC})"
for p in 80 443 $( [ "$SFTP_PUBLIC" != 0 ] && echo "$SFTP_PUBLIC" ); do
  iptables -C INPUT -p tcp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null ||
    iptables -I INPUT 1 -p tcp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
done
netfilter-persistent save >/dev/null 2>&1 || true

mkdir -p "$CONF_DIR"
umask 077
cat > "$ENV_FILE" <<EOF
DOMAIN=$DOMAIN
DUCK=$DUCK
PS5=$PS5
SECRET=$SECRET
HTTP_PORT=$HTTP_PORT
SFTP_PUBLIC=$SFTP_PUBLIC
EMAIL=$EMAIL
EOF
umask 022

if [ -n "$DUCK" ] && [[ "$DOMAIN" == *.duckdns.org ]]; then
  info "DuckDNS"
  cat > /etc/systemd/system/ps5nas-duckdns.service <<'EOF'
[Unit]
Description=PS5NAS: actualiza la IP en DuckDNS
After=network-online.target
[Service]
Type=oneshot
EnvironmentFile=/etc/ps5nas-gateway/env
ExecStart=/bin/sh -c 'curl -fsS -m 20 "https://www.duckdns.org/update?domains=$${DOMAIN%%.duckdns.org}&token=$${DUCK}&ip=" -o /run/ps5nas-duckdns.txt'
EOF
  cat > /etc/systemd/system/ps5nas-duckdns.timer <<'EOF'
[Unit]
Description=PS5NAS: DuckDNS cada 5 minutos
[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl start ps5nas-duckdns.service
  [ "$(cat /run/ps5nas-duckdns.txt 2>/dev/null)" = OK ] || echo "AVISO: DuckDNS no respondió OK: revisa el dominio y el token"
  systemctl enable --now ps5nas-duckdns.timer >/dev/null
fi

info "Sincronización con PS5NAS"
cat > /usr/local/bin/ps5nas-gateway-sync <<'SYNC'
#!/usr/bin/env bash
# Pregunta a PS5NAS qué publicar y rehace la configuración de Caddy y el SFTP.
set -uo pipefail
. /etc/ps5nas-gateway/env
routes=$(curl -fsS -m 15 -H "X-PS5NAS-Gateway: $SECRET" "http://$PS5:$HTTP_PORT/api/gate/routes?v=2") || exit 0
echo "$routes" | jq -e .domain >/dev/null 2>&1 || exit 0

tmp=$(mktemp)
{
  echo "# Generado por ps5nas-gateway-sync. No editar: se rehace cada minuto."
  echo "{"
  [ -n "${EMAIL:-}" ] && echo "	email $EMAIL"
  echo "}"
  echo
  echo "$DOMAIN {"
  echo "	reverse_proxy $PS5:$HTTP_PORT {"
  echo "		header_up X-PS5NAS-Gateway $SECRET"
  echo "		flush_interval -1"
  echo "	}"
  echo "}"
  echo "$routes" | jq -r '.apps[] | "\(.sub) \(.port) \(.host // "")"' | while read -r sub port host; do
    [[ "$sub" =~ ^[a-z0-9-]+$ && "$port" =~ ^[0-9]+$ ]] || continue
    # Apps de otro equipo de la red de Tailscale (p. ej. un PC); si no, la PS5.
    target=$PS5
    if [ -n "$host" ]; then
      [[ "$host" =~ ^100\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
      target=$host
    fi
    echo
    echo "$sub.$DOMAIN {"
    echo "	forward_auth $PS5:$HTTP_PORT {"
    echo "		uri /api/gate?sub=$sub"
    echo "		header_up X-PS5NAS-Gateway $SECRET"
    echo "	}"
    echo "	reverse_proxy $target:$port {"
    echo "		flush_interval -1"
    echo "	}"
    echo "}"
  done
} > "$tmp"
if ! cmp -s "$tmp" /etc/caddy/Caddyfile; then
  if caddy validate --adapter caddyfile --config "$tmp" >/dev/null 2>&1; then
    install -m 0640 -o root -g caddy "$tmp" /etc/caddy/Caddyfile
    systemctl reload caddy || systemctl restart caddy
    logger -t ps5nas-gateway "configuración actualizada"
  else
    logger -t ps5nas-gateway "configuración no válida; se mantiene la anterior"
  fi
fi
rm -f "$tmp"

# SFTP: reenvía el puerto público al de la PS5.
sftp=$(echo "$routes" | jq -r '.sftp_port // 0')
unit=/etc/systemd/system/ps5nas-sftp.service
if [ "${SFTP_PUBLIC:-0}" != 0 ] && [ "$sftp" != 0 ]; then
  want="ExecStart=/usr/bin/socat TCP-LISTEN:$SFTP_PUBLIC,fork,reuseaddr,keepalive TCP:$PS5:$sftp,keepalive"
  if ! grep -qxF "$want" "$unit" 2>/dev/null; then
    cat > "$unit" <<EOF
[Unit]
Description=PS5NAS: SFTP público -> PS5
After=network-online.target tailscaled.service
[Service]
$want
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ps5nas-sftp.service >/dev/null 2>&1
    systemctl restart ps5nas-sftp.service
  fi
elif [ -f "$unit" ]; then
  systemctl disable --now ps5nas-sftp.service >/dev/null 2>&1
  rm -f "$unit"
  systemctl daemon-reload
fi
SYNC
chmod 755 /usr/local/bin/ps5nas-gateway-sync

cat > /etc/systemd/system/ps5nas-gateway-sync.service <<'EOF'
[Unit]
Description=PS5NAS: sincroniza la pasarela
After=network-online.target tailscaled.service caddy.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ps5nas-gateway-sync
EOF
cat > /etc/systemd/system/ps5nas-gateway-sync.timer <<'EOF'
[Unit]
Description=PS5NAS: sincroniza la pasarela cada minuto
[Timer]
OnBootSec=20s
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now caddy >/dev/null 2>&1
systemctl start ps5nas-gateway-sync.service || true
systemctl enable --now ps5nas-gateway-sync.timer >/dev/null

info "Listo"
echo "  PS5NAS:  https://$DOMAIN/"
[ "$SFTP_PUBLIC" != 0 ] && echo "  SFTP:    $DOMAIN  puerto $SFTP_PUBLIC"
echo "  Apps:    https://NOMBRE.$DOMAIN/  (las que publiques en la pestaña Apps)"
echo
echo "Recuerda abrir en Oracle Cloud (Red → Lista de seguridad) los puertos TCP 80, 443"
[ "$SFTP_PUBLIC" != 0 ] && echo "y $SFTP_PUBLIC para 0.0.0.0/0. El primer acceso tarda unos segundos (certificado)."
exit 0
