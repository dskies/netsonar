<#
.SYNOPSIS
    Downloads all packages needed for an offline build of NetSonar.
    Run ON WINDOWS (online) before transferring to the server.
.DESCRIPTION
    1. Downloads Alpine (.apk) packages for nmap and ALL its dependencies
    2. Downloads Python wheels for Alpine/musl Linux x86_64
    3. Creates the packages/ folder ready for the offline build
.USAGE
    .\prepare-offline.ps1
    # then copy/transfer the entire netsonar/ folder to the server
#>

$ErrorActionPreference = "Stop"

# ── Alpine 3.23 (python:3.12-alpine usa questa versione) ──────────────────────
$ALPINE_VER  = "v3.23"
$mirrorMain  = "https://dl-cdn.alpinelinux.org/alpine/$ALPINE_VER/main/x86_64"
$mirrorComm  = "https://dl-cdn.alpinelinux.org/alpine/$ALPINE_VER/community/x86_64"

$pkgDir    = Join-Path $PSScriptRoot "packages"
$apkDir    = Join-Path $pkgDir "apk"
$wheelsDir = Join-Path $pkgDir "wheels"

New-Item -ItemType Directory -Force -Path $apkDir, $wheelsDir | Out-Null

# ─────────────────────────────────────────────────────────────────────────────
#  Function: parse APKINDEX → hashtable name→version
# ─────────────────────────────────────────────────────────────────────────────
function Get-ApkIndex([string]$mirror) {
    $tmpGz  = Join-Path $env:TEMP "APKINDEX_$([System.IO.Path]::GetRandomFileName()).tar.gz"
    $tmpDir = Join-Path $env:TEMP "apkindex_$([System.IO.Path]::GetRandomFileName())"
    try {
        Invoke-WebRequest -Uri "$mirror/APKINDEX.tar.gz" -OutFile $tmpGz -UseBasicParsing
        New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
        tar -xzf $tmpGz -C $tmpDir
        $idx = Join-Path $tmpDir "APKINDEX"
        $map = @{}
        $cur = $null
        foreach ($line in [System.IO.File]::ReadLines($idx)) {
            if     ($line -match '^P:(.+)$') { $cur = $Matches[1] }
            elseif ($line -match '^V:(.+)$' -and $cur) { $map[$cur] = $Matches[1]; $cur = $null }
        }
        return $map
    } finally {
        Remove-Item $tmpGz, $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  1. Load indexes from both repositories
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[1/3] Fetching APKINDEX Alpine $ALPINE_VER (main + community)..." -ForegroundColor Cyan

$idxMain = Get-ApkIndex $mirrorMain
$idxComm = Get-ApkIndex $mirrorComm

# Merge: main takes priority
$idx = @{}
$idxComm.GetEnumerator() | ForEach-Object { $idx[$_.Key] = @{ ver = $_.Value; mirror = $mirrorComm } }
$idxMain.GetEnumerator() | ForEach-Object { $idx[$_.Key] = @{ ver = $_.Value; mirror = $mirrorMain } }

Write-Host "  Indexed packages: $($idx.Count)" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
#  2. Download Alpine packages — FULL LIST with all transitive dependencies
#     (derived from nmap error on Alpine 3.23)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[2/3] Downloading Alpine packages (.apk)..." -ForegroundColor Cyan

$neededPkgs = @(
    "nmap",           # main scanner
    "nmap-nselibs",   # NSE libraries (required by nmap-scripts!)
    "nmap-scripts",   # NSE scripts (nbstat, http-title, smb-*, upnp-info, ssl-cert...)
    "lua5.4",         # Lua interpreter
    "lua5.4-libs",    # shared lib (provides so:liblua-5.4.so.0)
    "libgcc",         # GCC runtime    (provides so:libgcc_s.so.1)
    "libstdc++",      # C++ stdlib     (provides so:libstdc++.so.6)
    "libpcap",        # packet capture
    "libssh2",        # SSH
    "pcre2",          # regex
    "openssl",        # TLS (libssl3 + libcrypto3)
    "ca-certificates",# root certificates
    # ── SNMP ──────────────────────────────────────────────────────────────────
    "net-snmp",           # snmpget/snmpwalk CLI
    "net-snmp-tools",     # client tools: snmpget, snmpwalk, snmpbulkwalk
    "net-snmp-libs",      # shared libs (.so) required by net-snmp
    "net-snmp-agent-libs",# libnetsnmpagent/mibs/trapd .so (required by net-snmp CLI)
    # ── mDNS / Bonjour (avahi-browse) ────────────────────────────────────────────
    "libcap2",             # so:libcap.so.2     (required by avahi + dbus)
    "libevent",           # so:libevent-2.1.so.7 (required by avahi)
    "libexpat",           # so:libexpat.so.1   (required by dbus + avahi)
    "dbus",               # D-Bus daemon (avahi dependency)
    "dbus-libs",          # D-Bus shared lib
    "libdaemon",          # libdaemon.so (avahi dependency)
    "avahi",              # mDNS/Bonjour daemon
    "avahi-libs",         # shared lib (libavahi-*.so)
    "avahi-tools"         # avahi-browse CLI
)

$downloaded = 0; $skipped = 0; $errors = 0

foreach ($pkg in $neededPkgs) {
    if (-not $idx.ContainsKey($pkg)) {
        Write-Warning "  [$pkg] not found in index — skipping"
        $errors++
        continue
    }
    $ver      = $idx[$pkg].ver
    $mirror   = $idx[$pkg].mirror
    $filename = "${pkg}-${ver}.apk"
    $dest     = Join-Path $apkDir $filename
    $url      = "$mirror/$filename"

    if (Test-Path $dest) {
        Write-Host "  [skip] $filename" -ForegroundColor DarkGray
        $skipped++
        continue
    }
    try {
        Write-Host "  $filename" -ForegroundColor Gray
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
        $downloaded++
    } catch {
        Write-Warning "  ERROR downloading $filename`: $($_.Exception.Message)"
        $errors++
    }
}

Write-Host "  Downloaded: $downloaded  |  Already present: $skipped  |  Errors: $errors" -ForegroundColor $(if ($errors -gt 0) { "Yellow" } else { "Green" })

# ─────────────────────────────────────────────────────────────────────────────
#  3. Download Python wheels
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[3/3] Downloading Python wheels (musl/linux x86_64)..." -ForegroundColor Cyan

if (-not (Get-Command pip -ErrorAction SilentlyContinue)) {
    Write-Error "pip not found. Install Python from python.org and retry."
}

$pipPackages = @(
    "fastapi==0.115.6",
    "uvicorn==0.32.1",
    "sqlalchemy==2.0.36",
    "greenlet",           # SQLAlchemy dependency on x86_64 / Python < 3.13
    "apscheduler==3.10.4",
    "apprise==1.9.0",
    "python-multipart==0.0.12",
    "aiofiles==24.1.0"
)

# Try musllinux platforms in order (SQLAlchemy has C extensions — need the right wheel)
# $args is a PowerShell automatic variable — do NOT use it as a variable name!
$muslPlatforms = @("musllinux_1_2_x86_64", "musllinux_1_1_x86_64")

$success = $false
foreach ($plat in $muslPlatforms) {
    Write-Host "  Trying platform: $plat" -ForegroundColor Gray
    $pipArgs = @(
        "download",
        "--platform", $plat,
        "--python-version", "3.12",
        "--abi", "cp312",
        "--only-binary", ":all:",
        "--dest", $wheelsDir
    ) + $pipPackages
    & pip @pipArgs
    if ($LASTEXITCODE -eq 0) { $success = $true; break }
}

if (-not $success) {
    # Fallback: download source distributions (.tar.gz) — compilable in Docker with gcc
    Write-Host "  Binary download failed. Downloading source distributions (.tar.gz)..." -ForegroundColor Yellow
    Write-Host "  NOTE: the Dockerfile will need gcc/musl-dev to compile." -ForegroundColor Yellow
    $pipArgsSrc = @("download", "--no-binary", ":all:", "--dest", $wheelsDir) + $pipPackages
    & pip @pipArgsSrc
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Download failed even for source distributions. Check your internet connection."
    }
}

$wheelCount = (Get-ChildItem $wheelsDir -Filter "*.whl" -ErrorAction SilentlyContinue).Count
$apkCount   = (Get-ChildItem $apkDir   -Filter "*.apk" -ErrorAction SilentlyContinue).Count

# ─────────────────────────────────────────────────────────────────────────────
#  Summary
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n✔ Offline preparation complete!" -ForegroundColor Green
Write-Host "  APK:    $apkCount files in packages\apk\"    -ForegroundColor White
Write-Host "  Wheels: $wheelCount files in packages\wheels\" -ForegroundColor White
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Copy the entire netsonar/ folder to the server:"
Write-Host "     scp -r netsonar/ root@<server-ip>:/opt/" -ForegroundColor Yellow
Write-Host "  2. On the server — RESET DB (required when upgrading from a previous version):"
Write-Host "     rm -f /opt/netsonar/data/netsonar.db" -ForegroundColor Red
Write-Host "     (the DB is recreated automatically on first start — scan history will be lost)"
Write-Host "  3. On the server — rebuild and start:"
Write-Host "     cd /opt/netsonar && docker compose down && docker compose up -d --build" -ForegroundColor Yellow
Write-Host "`nNOTE: to keep history, skip the rm — new columns (model, services)" -ForegroundColor DarkYellow
Write-Host "      will remain NULL for existing records." -ForegroundColor DarkYellow
