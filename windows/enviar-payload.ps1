<#
  Envía un payload ELF al cargador de la PS5 (elfldr, puerto 9021).

  Uso:
    .\enviar-payload.ps1 -Archivo ..\ps5nas.elf
    .\enviar-payload.ps1 -Archivo .\tailscale.elf -PS5 192.168.100.208
#>
param(
  [Parameter(Mandatory = $true)][string]$Archivo,
  [string]$PS5 = "192.168.100.208",
  [int]$Puerto = 9021
)

$ErrorActionPreference = "Stop"
$ruta = Resolve-Path $Archivo
$bytes = [IO.File]::ReadAllBytes($ruta)
Write-Host "Enviando $(Split-Path $ruta -Leaf) ($([math]::Round($bytes.Length/1KB)) KB) a ${PS5}:$Puerto ..."

$cliente = New-Object Net.Sockets.TcpClient
try {
  $cliente.Connect($PS5, $Puerto)
} catch {
  Write-Host "No se pudo conectar a ${PS5}:$Puerto. ¿Está la PS5 encendida y con el jailbreak (elfldr) cargado?" -ForegroundColor Red
  exit 1
}
$flujo = $cliente.GetStream()
$flujo.Write($bytes, 0, $bytes.Length)
$flujo.Flush()
$cliente.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)

# Muestra lo que el payload imprima durante unos segundos.
$flujo.ReadTimeout = 4000
$buf = New-Object byte[] 4096
try {
  while (($n = $flujo.Read($buf, 0, $buf.Length)) -gt 0) {
    Write-Host ([Text.Encoding]::UTF8.GetString($buf, 0, $n)) -NoNewline
  }
} catch { }
$cliente.Close()
Write-Host "`nEnviado." -ForegroundColor Green
