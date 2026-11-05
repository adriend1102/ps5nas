<#
  PLAN B: solo si Tailscale no funciona en tu PS5 (firmware no compatible).

  Convierte este Windows en "subnet router" de Tailscale: anuncia la IP de la
  PS5 a tu tailnet, de modo que desde fuera puedas entrar a
  ftp://192.168.100.208:2121 y http://192.168.100.208:8000 como si estuvieras
  en casa.  El servidor (ps5share) sigue corriendo en la PS5; el Windows solo
  hace de puente, así que tiene que estar encendido.

  Ejecutar como administrador, con Tailscale para Windows ya instalado.
#>
param(
  [string]$PS5 = "192.168.100.208",
  [switch]$Quitar
)

$ErrorActionPreference = "Stop"
$ts = "C:\Program Files\Tailscale\tailscale.exe"
if (-not (Test-Path $ts)) { $ts = (Get-Command tailscale -ErrorAction SilentlyContinue).Source }
if (-not $ts) { throw "No encuentro tailscale.exe. Instala Tailscale para Windows primero." }

if ($Quitar) {
  & $ts set --advertise-routes=
  Write-Host "Ruta retirada. Este Windows ya no hace de puente hacia la PS5." -ForegroundColor Green
  exit 0
}

& $ts set --advertise-routes="$PS5/32"
Write-Host ""
Write-Host "Ruta $PS5/32 anunciada." -ForegroundColor Green
Write-Host "Falta un paso: apruébala en https://login.tailscale.com/admin/machines"
Write-Host "  (este equipo > ... > Edit route settings > marca $PS5/32)."
Write-Host ""
Write-Host "Evita que este Windows se suspenda (Configuración > Sistema > Inicio/apagado y suspensión)."
Write-Host "Para deshacerlo:  .\planB-windows-subnet-router.ps1 -Quitar"
