<#
Downloads wintun.dll, which client.exe needs for the TUN adapter. It is
not in the repository: WireGuard LLC ships it under its own license, see
https://www.wintun.net/.

The DLL is taken from the official 0.14.1 archive and checked by SHA-256;
any other file is refused, nothing is written.

Usage:
  .\get-wintun.ps1                                  # next to this script
  .\get-wintun.ps1 -Dir "C:\Program Files\splicertc"  # admin window
#>

param(
    [string]$Dir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

$url = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$entry = "wintun/bin/amd64/wintun.dll"
$want = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE"

# PowerShell 5.1: TLS 1.2 явно
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem

$tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory $tmp | Out-Null
try {
    $zip = Join-Path $tmp "wintun.zip"
    Write-Host "Downloading $url"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip

    $dll = Join-Path $tmp "wintun.dll"
    $z = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        $e = $z.GetEntry($entry)
        if (-not $e) { throw "$entry is not in $url" }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dll)
    } finally {
        $z.Dispose()
    }

    $got = (Get-FileHash $dll -Algorithm SHA256).Hash
    if ($got -ne $want) { throw "wintun.dll SHA-256 is $got, expected $want" }

    Copy-Item $dll (Join-Path $Dir "wintun.dll") -Force
    Write-Host "wintun.dll 0.14.1 (SHA-256 OK) -> $Dir" -ForegroundColor Green
} finally {
    Remove-Item -Recurse -Force $tmp
}
