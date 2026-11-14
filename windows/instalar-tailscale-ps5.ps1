<#
  Instala Tailscale para PS5 en la consola, respetando la versión que ya
  tenga en marcha.

  - Si no hay ninguna en marcha, descarga la última versión del repositorio
    indicado (por defecto el oficial, holdmysocks/ps5-tailscale) y la envía.
  - Si ya hay una en marcha y es una compilación propia o de un fork (su
    versión lleva un sufijo, como 0.7.3-adrian1), la deja tal cual: no la
    sustituye por la oficial.
  - Si es una versión oficial más antigua que la última del repositorio, la
    actualiza.  Si ya es la última, no hace nada.

  Uso:
    .\instalar-tailscale-ps5.ps1
    .\instalar-tailscale-ps5.ps1 -PS5 192.168.100.208
    .\instalar-tailscale-ps5.ps1 -Repo adriend1102/ps5-tailscale   # usar un fork
    .\instalar-tailscale-ps5.ps1 -Archivo .\tailscale.elf          # un .elf propio
    .\instalar-tailscale-ps5.ps1 -Forzar                           # instalar aunque haya otra
#>
param(
  [string]$PS5 = "192.168.100.208",
  [int]$Puerto = 9021,
  [string]$Repo = "holdmysocks/ps5-tailscale",
  [string]$Archivo = "",
  [switch]$Forzar
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Versión que tiene en marcha la consola.  /api/ping responde aunque la
# página de estado tenga contraseña: "ps5-tailscale 0.7.3".
function Get-VersionEnMarcha {
  try {
    $r = Invoke-WebRequest "http://${PS5}:8090/api/ping" -UseBasicParsing -TimeoutSec 4
    if ($r.Content -match 'ps5-tailscale\s+(\S+)') { return $Matches[1] }
  } catch { }
  return $null
}

# Una versión oficial es solo números (0.7.3); con sufijo es una compilación
# propia o de un fork.
function Test-Oficial([string]$v) { return $v -match '^\d+(\.\d+)*$' }

$actual = Get-VersionEnMarcha
if ($actual) {
  Write-Host "La PS5 ya tiene en marcha ps5-tailscale $actual."
} else {
  Write-Host "No se encuentra Tailscale en marcha en la PS5."
}

if ($Archivo) {
  if (-not (Test-Path $Archivo)) { throw "No existe $Archivo" }
  if ($actual -and -not $Forzar) {
    Write-Host "Se sustituirá la versión $actual por $Archivo."
  }
  $destino = (Resolve-Path $Archivo).Path
} else {
  if ($actual -and -not (Test-Oficial $actual) -and -not $Forzar) {
    Write-Host "Es una compilación propia o de un fork: se deja como está."
    Write-Host "(Usa -Forzar para sustituirla por la de $Repo.)"
    exit 0
  }

  Write-Host "Buscando la última versión de $Repo..."
  $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" `
    -Headers @{ "User-Agent" = "ps5share-installer" }
  $ultima = $rel.tag_name -replace '^v', ''

  if ($actual -and ($actual -eq $ultima) -and -not $Forzar) {
    Write-Host "Ya tiene la última versión ($ultima). No hay nada que hacer."
    exit 0
  }
  $masNueva = $false
  try { $masNueva = (Test-Oficial $actual) -and (Test-Oficial $ultima) -and ([version]$actual -gt [version]$ultima) } catch { }
  if ($actual -and $masNueva -and -not $Forzar) {
    Write-Host "La versión en marcha ($actual) es más nueva que la de $Repo ($ultima): se deja."
    exit 0
  }

  $asset = $rel.assets | Where-Object { $_.name -match '^tailscale.*\.elf$' } |
    Sort-Object { $_.name -eq "tailscale.elf" } -Descending | Select-Object -First 1
  if (-not $asset) { throw "No se encontró el .elf en la release $($rel.tag_name) de $Repo" }

  $destino = Join-Path $PSScriptRoot "tailscale.elf"
  Write-Host "Descargando $($asset.name) ($($rel.tag_name))..."
  Invoke-WebRequest $asset.browser_download_url -OutFile $destino -UseBasicParsing
}

& (Join-Path $PSScriptRoot "enviar-payload.ps1") -Archivo $destino -PS5 $PS5 -Puerto $Puerto

if ($actual) {
  # Ya estaba configurada: sesión iniciada y ajustes guardados en la consola.
  Start-Sleep -Seconds 5
  $nueva = Get-VersionEnMarcha
  if ($nueva) { Write-Host "En marcha: ps5-tailscale $nueva." }
  else { Write-Host "Aún no responde; espera unos segundos y abre http://${PS5}:8090" }
  exit 0
}

Write-Host ""
Write-Host "Ahora, en la página que se abre (http://${PS5}:8090):"
Write-Host "  1. Inicia sesión en Tailscale (código QR o enlace)."
Write-Host "  2. Pon una contraseña a la página de estado."
Write-Host "  3. En Settings > 'TCP ports never exposed' añade: 2121, 8080, 9021, 2323, 3232"
Write-Host "  4. Copia la IP 100.x.y.z de la PS5 y pégala en ps5share > Ajustes."
Start-Sleep -Seconds 5
Start-Process "http://${PS5}:8090"
