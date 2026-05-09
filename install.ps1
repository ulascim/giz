# giz one-line installer (Windows).
#
# Usage (PowerShell):
#   iwr -useb https://raw.githubusercontent.com/ulascim/giz/main/install.ps1 | iex
#
# What this script does:
#   1) Refuses to run as Administrator.
#   2) Verifies the data directory is NOT inside OneDrive / Dropbox /
#      Google Drive (HARD GATE - no override).
#   3) Installs Java 17 and Python 3.12 via winget if missing.
#   4) Downloads the giz source and the briar-headless Windows JAR
#      from this repo's GitHub Release and verifies SHA-256.
#   5) Creates a Python virtualenv at %LOCALAPPDATA%\giz\venv.
#   6) Drops a 'giz.cmd' launcher into a directory on PATH (or asks
#      you to add %LOCALAPPDATA%\giz\bin to PATH yourself).
#   7) Runs first-time setup interactively.

$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

$GIZ_VERSION = 'v0.1.6'
$REPO        = 'ulascim/giz'
$RELEASE_BASE   = "https://github.com/$REPO/releases/download/v0.1.0"
$SOURCE_TARBALL = "https://github.com/$REPO/archive/refs/tags/$GIZ_VERSION.zip"

# SHA-256 of the source zip at the tag. install.ps1 aborts on
# mismatch. Auditors verify with:
#   (Get-FileHash giz-v0.1.1.zip -Algorithm SHA256).Hash
$SOURCE_SHA = 'd728d987318388afe75951ed7003e20339b60a14299606bf7eab014caa6aeff3'

# JAR is shipped with the v0.1.0 release (the binary did not change
# between v0.1.0 and v0.1.1; only the wrapper did). Verified by SHA.
$JAR_NAME = 'briar-headless-windows-x86_64.jar'
$JAR_SHA  = 'ed056e80bdf0e9fe97084ebee7ce619ba49784070afe23532c8d25e16efbe4b2'

$INSTALL_ROOT = Join-Path $env:LOCALAPPDATA 'giz'
$DATA_DIR     = Join-Path $env:LOCALAPPDATA 'giz\data'
$BIN_DIR      = Join-Path $INSTALL_ROOT 'bin'
$LAUNCHER     = Join-Path $BIN_DIR 'giz.cmd'

$TMP_DIR = Join-Path $env:TEMP ("giz-install-" + [guid]::NewGuid().Guid)
New-Item -ItemType Directory -Force -Path $TMP_DIR | Out-Null

function Cleanup { if (Test-Path $TMP_DIR) { Remove-Item -Recurse -Force $TMP_DIR } }
trap { Cleanup; throw }

function Bold($s)    { Write-Host $s -ForegroundColor White -BackgroundColor Black }
function Dim($s)     { Write-Host $s -ForegroundColor DarkGray }
function Yellow($s)  { Write-Host $s -ForegroundColor Yellow }
function Red($s)     { Write-Host $s -ForegroundColor Red }
function Green($s)   { Write-Host $s -ForegroundColor Green }

function Die($msg) { Red "error: $msg"; Cleanup; exit 1 }

Bold "giz installer $GIZ_VERSION"
Write-Host

# ---- preconditions ----------------------------------------------------------

$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "do not run this installer as Administrator. giz installs into your user profile only."
}

# ---- backup-leak gate (HARD) -----------------------------------------------

$resolved = $DATA_DIR
try { $resolved = (Resolve-Path -LiteralPath $DATA_DIR -ErrorAction Stop).Path } catch { }

$leakPatterns = @(
    'OneDrive',
    'Dropbox',
    'Google Drive',
    'GoogleDrive'
)

foreach ($pat in $leakPatterns) {
    if ($resolved -like "*$pat*") {
        Red "REFUSED: data directory '$DATA_DIR' resolves under '$pat'."
        Red "         giz will not store its database in a cloud-synced folder."
        exit 2
    }
}

# OneDrive often relocates Documents. We use %LOCALAPPDATA% explicitly to
# avoid that case but check anyway in case the user customized it.

# ---- Java 17+ ---------------------------------------------------------------

function Test-Java17 {
    $java = (Get-Command java -ErrorAction SilentlyContinue)
    if (-not $java) { return $false }
    $line = & java -version 2>&1 | Select-Object -First 1
    if ($line -match 'version "(\d+)\.') { return [int]$Matches[1] -ge 17 }
    if ($line -match 'version "(\d+)"')  { return [int]$Matches[1] -ge 17 }
    return $false
}

if (-not (Test-Java17)) {
    Yellow "Java 17 not found - installing via winget..."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Die "winget not available. Install Java 17 manually from https://adoptium.net and re-run."
    }
    & winget install --id Microsoft.OpenJDK.17 --silent --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { Die "winget install of OpenJDK 17 failed" }
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
    if (-not (Test-Java17)) { Die "Java 17 still not visible after install. Restart PowerShell and retry." }
}

Dim "java: $((& java -version 2>&1 | Select-Object -First 1))"

# ---- Python 3.9+ ------------------------------------------------------------

function Test-Python39 {
    $py = (Get-Command python -ErrorAction SilentlyContinue)
    if (-not $py) { $py = (Get-Command python3 -ErrorAction SilentlyContinue) }
    if (-not $py) { return $null }
    try {
        $check = & $py.Source -c "import sys; print(sys.version_info >= (3, 9))" 2>$null
        if ($check -eq 'True') { return $py.Source }
    } catch { }
    return $null
}

$PY = Test-Python39
if (-not $PY) {
    Yellow "Python 3.9+ not found - installing via winget..."
    & winget install --id Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { Die "winget install of Python 3.12 failed" }
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
    $PY = Test-Python39
    if (-not $PY) { Die "Python 3.9+ still not visible after install. Restart PowerShell and retry." }
}
Dim "python: $((& $PY --version))"

# ---- download source --------------------------------------------------------

New-Item -ItemType Directory -Force -Path $INSTALL_ROOT, $DATA_DIR, $BIN_DIR | Out-Null

Dim "downloading source $SOURCE_TARBALL"
$zip = Join-Path $TMP_DIR 'giz.zip'
Invoke-WebRequest -UseBasicParsing -Uri $SOURCE_TARBALL -OutFile $zip

$ActualSrcSha = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
if ($ActualSrcSha -ne $SOURCE_SHA) {
    Red "SHA-256 mismatch on source zip"
    Red "  expected: $SOURCE_SHA"
    Red "  actual:   $ActualSrcSha"
    Red "Refusing to install. The source archive at the tag does not"
    Red "match the SHA pinned in this installer."
    Cleanup
    exit 4
}
Green "source verified: $ActualSrcSha"

Expand-Archive -Force -Path $zip -DestinationPath $TMP_DIR

$srcDir = Get-ChildItem -Path $TMP_DIR -Directory | Where-Object { $_.Name -like 'giz-*' } | Select-Object -First 1
if (-not $srcDir) { Die "source archive did not extract as expected" }

# ---- download JAR + verify --------------------------------------------------

$jarPath = Join-Path $TMP_DIR $JAR_NAME
Dim "downloading $JAR_NAME"
Invoke-WebRequest -UseBasicParsing -Uri "$RELEASE_BASE/$JAR_NAME" -OutFile $jarPath

$actualSha = (Get-FileHash -Algorithm SHA256 -Path $jarPath).Hash.ToLower()
if ($actualSha -ne $JAR_SHA) {
    Red "SHA-256 mismatch for $JAR_NAME"
    Red "  expected: $JAR_SHA"
    Red "  actual:   $actualSha"
    exit 3
}
Green "JAR verified: $actualSha"

# ---- atomic install ---------------------------------------------------------

$repoDest = Join-Path $INSTALL_ROOT 'repo'
if (Test-Path $repoDest) { Remove-Item -Recurse -Force $repoDest }
Move-Item -Path $srcDir.FullName -Destination $repoDest

Move-Item -Force -Path $jarPath -Destination (Join-Path $INSTALL_ROOT 'briar-headless.jar')

# ---- venv + deps ------------------------------------------------------------

$venv = Join-Path $INSTALL_ROOT 'venv'
if (Test-Path $venv) { Remove-Item -Recurse -Force $venv }
& $PY -m venv $venv
$venvPy = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path $venvPy)) { Die "venv python not at $venvPy" }
& $venvPy -m pip install --quiet --upgrade pip
# --require-hashes refuses any package (including transitive deps)
# whose tarball / wheel does not match the sha256 listed in the
# lockfile. This is the supply-chain gate for everything pip installs.
& $venvPy -m pip install --quiet --require-hashes `
    -r (Join-Path $repoDest 'requirements.lock.txt')
& $venvPy -m pip install --quiet -e $repoDest

$venvGiz = Join-Path $venv 'Scripts\giz.exe'
if (-not (Test-Path $venvGiz)) {
    # Fallback for older pip versions that produce .py instead of .exe shims
    $venvGiz = Join-Path $venv 'Scripts\giz-script.py'
}

# ---- launcher ---------------------------------------------------------------

@"
@echo off
"$venvGiz" --data-dir "$DATA_DIR" --jar "$INSTALL_ROOT\briar-headless.jar" %*
"@ | Set-Content -Path $LAUNCHER -Encoding ASCII

# ---- PATH hint --------------------------------------------------------------

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$BIN_DIR*") {
    Yellow "note: $BIN_DIR is not in your User PATH."
    Yellow "      adding it now..."
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$BIN_DIR", 'User')
    $env:Path = $env:Path + ";$BIN_DIR"
    Yellow "      PATH updated. New PowerShell windows will have 'giz' available."
}

# ---- run setup (only on a fresh install) -----------------------------------

# An existing .gizhashes means an account already lives at DATA_DIR. Re-running
# the installer is then an upgrade, not a first run. We must NOT call
# 'giz --setup' in that case: giz will refuse with exit 4, but more
# importantly, asking for nickname/passwords here would imply we are about
# to clobber the account. We never touch DATA_DIR contents in either path.
if (Test-Path (Join-Path $DATA_DIR '.gizhashes')) {
    Green "upgrade complete. existing account at $DATA_DIR preserved."
    Dim   "run 'giz' to log in with your existing password."
    exit 0
}

Green "install complete. starting first-run setup..."
Write-Host

& $LAUNCHER --setup
