<#
  Descarga la última versión de Tailscale para PS5 (holdmysocks/ps5-tailscale)
  y la envía a la consola.  Después abre su página de estado para iniciar
  sesión en tu cuenta de Tailscale.

  Uso:
    .\instalar-tailscale-ps5.ps1
    .\instalar-tailscale-ps5.ps1 -PS5 192.168.100.208
#>
param(
  [string]$PS5 = "192.168.100.208",
  [int]$Puerto = 9021
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "Buscando la última versión de ps5-tailscale..."
$rel = Invoke-RestMethod "https://api.github.com/repos/holdmysocks/ps5-tailscale/releases/latest" `
  -Headers @{ "User-Agent" = "ps5share-installer" }
$asset = $rel.assets | Where-Object { $_.name -match '^tailscale.*\.elf$' } |
  Sort-Object { $_.name -eq "tailscale.elf" } -Descending | Select-Object -First 1
if (-not $asset) { throw "No se encontró el .elf en la release $($rel.tag_name)" }

$destino = Join-Path $PSScriptRoot "tailscale.elf"
Write-Host "Descargando $($asset.name) ($($rel.tag_name))..."
Invoke-WebRequest $asset.browser_download_url -OutFile $destino -UseBasicParsing

& (Join-Path $PSScriptRoot "enviar-payload.ps1") -Archivo $destino -PS5 $PS5 -Puerto $Puerto

Write-Host ""
Write-Host "Ahora, en la página que se abre (http://${PS5}:8090):"
Write-Host "  1. Inicia sesión en Tailscale (código QR o enlace)."
Write-Host "  2. Pon una contraseña a la página de estado."
Write-Host "  3. En Settings > 'TCP ports never exposed' añade: 8080, 9021, 2323, 3232"
Write-Host "  4. Copia la IP 100.x.y.z de la PS5 y pégala en ps5share > Ajustes."
Start-Sleep -Seconds 5
Start-Process "http://${PS5}:8090"
