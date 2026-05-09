#!/usr/bin/env bash
# giz one-line installer (macOS / Linux).
#
# Usage:   curl -fsSL https://raw.githubusercontent.com/ulascim/giz/main/install.sh | bash
#
# What this script does:
#   1) Detects your OS and architecture and refuses unsupported combos.
#   2) Refuses to run as root.
#   3) Verifies your data directory is NOT inside iCloud / OneDrive /
#      Dropbox / Google Drive (HARD GATE - no override flag).
#   4) Installs Java 17+ and Python 3.9+ if missing.
#   5) Downloads the giz source and the briar-headless JAR from this
#      repo's GitHub Release and verifies SHA-256 hashes.
#   6) Creates a Python virtualenv and installs three pinned dependencies.
#   7) Drops a 'giz' launcher into ~/.local/bin/.
#   8) Runs first-time setup interactively (nickname + real password +
#      duress password). The duress password silently wipes all real
#      data when typed - this is intentional and irreversible.
#
# After this finishes, run `giz` in any terminal to log in.

set -euo pipefail

GIZ_VERSION="v0.1.12"
REPO="ulascim/giz"
RELEASE_BASE="https://github.com/${REPO}/releases/download/v0.1.0"
SOURCE_TARBALL="https://github.com/${REPO}/archive/refs/tags/${GIZ_VERSION}.tar.gz"

# SHA-256 of the source tarball at the tag. Computed once when the tag
# is cut and recorded here. install.sh aborts on mismatch; this is the
# binding artifact integrity check for everything inside the source
# archive (giz/*.py, requirements.lock.txt, pyproject.toml, etc.).
# Auditors verify by:
#   curl -fsSL https://github.com/ulascim/giz/archive/refs/tags/v0.1.1.tar.gz \
#     | shasum -a 256
SOURCE_SHA="857a9c9f32374ea16845ed1cbbfa957b4cd3181be8760fb1c4bf759caa6b39ad"

# JAR is shipped with the v0.1.0 release (the binary did not change
# between v0.1.0 and v0.1.1; only the wrapper did). Verified by SHA.
JAR_SHA_MACOS_AARCH64="12d8efc1d65fc78cfa2c365cd2bc47632d56841f4f20d7dd411f5d95e8d1fa57"

INSTALL_ROOT="${HOME}/.local/share/giz"
DATA_DIR="${HOME}/.giz"
LAUNCHER="${HOME}/.local/bin/giz"
TMP_DIR="$(mktemp -d -t giz-install.XXXXXX)"

cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

die() { red "error: $*"; exit 1; }

bold "giz installer ${GIZ_VERSION}"
echo

# ---- preconditions ----------------------------------------------------------

if [[ "${EUID}" -eq 0 ]]; then
    die "do not run as root. giz installs into your home directory only."
fi

OS_KIND="$(uname -s)"
ARCH="$(uname -m)"

case "${OS_KIND}" in
    Darwin)
        if [[ "${ARCH}" != "arm64" ]]; then
            die "this version of giz ships only an Apple Silicon (arm64) Mac JAR. Intel Mac support is on the Phase 2 list."
        fi
        JAR_NAME="briar-headless-macos-aarch64.jar"
        JAR_SHA="${JAR_SHA_MACOS_AARCH64}"
        ;;
    Linux)
        die "linux JAR is not yet shipped (Phase 2). Run on macOS for now."
        ;;
    *)
        die "unsupported OS: ${OS_KIND}"
        ;;
esac

dim "OS: ${OS_KIND} ${ARCH}"
dim "JAR: ${JAR_NAME}"

# ---- backup-leak gate (HARD) -----------------------------------------------

# Resolve symlinks so /Users/me/Documents -> iCloud is detected.
if command -v greadlink >/dev/null 2>&1; then
    RESOLVED="$(greadlink -f "${DATA_DIR}" 2>/dev/null || echo "${DATA_DIR}")"
else
    RESOLVED="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${DATA_DIR}" 2>/dev/null || echo "${DATA_DIR}")"
fi

LEAK_PATTERNS=(
    "Library/Mobile Documents"
    "iCloud Drive"
    "com~apple~CloudDocs"
    "OneDrive"
    "Dropbox"
    "Google Drive"
    "GoogleDrive"
)

for pat in "${LEAK_PATTERNS[@]}"; do
    if [[ "${RESOLVED}" == *"${pat}"* ]]; then
        red "REFUSED: data directory '${DATA_DIR}' resolves to '${RESOLVED}'"
        red "         which contains the cloud-sync marker: ${pat}"
        red "         giz will not store its database in a cloud-synced folder."
        exit 2
    fi
done

# ---- Java 17+ ---------------------------------------------------------------

have_java_17() {
    if ! command -v java >/dev/null 2>&1; then return 1; fi
    local v
    v="$(java -version 2>&1 | head -n1 | awk -F'"' '{print $2}' | awk -F'.' '{print $1}')"
    [[ -n "${v}" ]] && [[ "${v}" -ge 17 ]]
}

if ! have_java_17; then
    yellow "Java 17+ not found - installing via Homebrew (will require your password if Homebrew is not yet installed)."
    if ! command -v brew >/dev/null 2>&1; then
        die "Homebrew is required for Java install. Install Homebrew from https://brew.sh and rerun."
    fi
    brew install --quiet openjdk@17 || die "Java install failed"
    JAVA_BIN="$(brew --prefix)/opt/openjdk@17/bin/java"
    if [[ ! -x "${JAVA_BIN}" ]]; then
        die "openjdk@17 installed but ${JAVA_BIN} not found"
    fi
    export PATH="$(brew --prefix)/opt/openjdk@17/bin:${PATH}"
    have_java_17 || die "Java 17 still not visible after install. Add $(brew --prefix)/opt/openjdk@17/bin to PATH manually."
fi

dim "java: $(java -version 2>&1 | head -n1)"

# ---- Python 3.9+ ------------------------------------------------------------

have_python_39() {
    if ! command -v python3 >/dev/null 2>&1; then return 1; fi
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'
}

if ! have_python_39; then
    yellow "Python 3.9+ not found - installing via Homebrew."
    command -v brew >/dev/null 2>&1 || die "Homebrew required to install Python."
    brew install --quiet python@3.12
fi

dim "python: $(python3 --version)"

# ---- download source --------------------------------------------------------

mkdir -p "${INSTALL_ROOT}" "${DATA_DIR}" "$(dirname "${LAUNCHER}")"

dim "downloading source ${SOURCE_TARBALL}"
curl -fsSL "${SOURCE_TARBALL}" -o "${TMP_DIR}/giz.tar.gz"

ACTUAL_SRC_SHA="$(shasum -a 256 "${TMP_DIR}/giz.tar.gz" | awk '{print $1}')"
if [[ "${ACTUAL_SRC_SHA}" != "${SOURCE_SHA}" ]]; then
    red "SHA-256 mismatch on source tarball"
    red "  expected: ${SOURCE_SHA}"
    red "  actual:   ${ACTUAL_SRC_SHA}"
    red "Refusing to install. The source archive at the tag does not"
    red "match the SHA pinned in this installer. Either the install"
    red "script is out of date or someone replaced the source archive."
    exit 4
fi
green "source verified: ${ACTUAL_SRC_SHA}"

tar -xzf "${TMP_DIR}/giz.tar.gz" -C "${TMP_DIR}"
SRC_DIR="$(echo "${TMP_DIR}"/giz-*)"
[[ -d "${SRC_DIR}" ]] || die "source tarball did not extract as expected"

# ---- download JAR + verify --------------------------------------------------

dim "downloading ${JAR_NAME}"
curl -fsSL "${RELEASE_BASE}/${JAR_NAME}" -o "${TMP_DIR}/${JAR_NAME}"

ACTUAL_SHA="$(shasum -a 256 "${TMP_DIR}/${JAR_NAME}" | awk '{print $1}')"
if [[ "${ACTUAL_SHA}" != "${JAR_SHA}" ]]; then
    red "SHA-256 mismatch for ${JAR_NAME}"
    red "  expected: ${JAR_SHA}"
    red "  actual:   ${ACTUAL_SHA}"
    exit 3
fi
green "JAR verified: ${ACTUAL_SHA}"

# ---- atomic install ---------------------------------------------------------

rm -rf "${INSTALL_ROOT}/repo"
mv "${SRC_DIR}" "${INSTALL_ROOT}/repo"
mv "${TMP_DIR}/${JAR_NAME}" "${INSTALL_ROOT}/briar-headless.jar"

# ---- venv + deps ------------------------------------------------------------

VENV="${INSTALL_ROOT}/venv"
rm -rf "${VENV}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet --upgrade pip

# --require-hashes refuses any package (including transitive deps)
# whose tarball / wheel does not match the sha256 listed in the
# lockfile. This is the supply-chain gate for everything pip installs.
"${VENV}/bin/pip" install --quiet --require-hashes \
    -r "${INSTALL_ROOT}/repo/requirements.lock.txt"

# ---- launcher ---------------------------------------------------------------

"${VENV}/bin/pip" install --quiet -e "${INSTALL_ROOT}/repo"

cat > "${LAUNCHER}" <<EOF
#!/usr/bin/env bash
set -e
# Use the venv's giz entry point (NOT python -m giz) so the launcher
# does not pick up a sibling giz/ package from whatever cwd the user
# happens to be in.
exec "${VENV}/bin/giz" \\
    --data-dir "${DATA_DIR}" \\
    --jar "${INSTALL_ROOT}/briar-headless.jar" \\
    "\$@"
EOF
chmod +x "${LAUNCHER}"

# ---- Time Machine exclusion (best-effort) -----------------------------------

if [[ "${OS_KIND}" == "Darwin" ]] && command -v tmutil >/dev/null 2>&1; then
    tmutil addexclusion "${DATA_DIR}" >/dev/null 2>&1 || true
fi

# ---- PATH (auto, idempotent) ------------------------------------------------

LAUNCHER_DIR="$(dirname "${LAUNCHER}")"
PATH_LINE='export PATH="${HOME}/.local/bin:${PATH}"  # added by giz installer'

ensure_path_in_rc() {
    local rc="$1"
    [[ -f "${rc}" ]] || touch "${rc}"
    if ! grep -q '# added by giz installer' "${rc}" 2>/dev/null; then
        printf '\n%s\n' "${PATH_LINE}" >> "${rc}"
        dim "added ${LAUNCHER_DIR} to PATH in ${rc}"
    fi
}

case ":${PATH}:" in
    *":${LAUNCHER_DIR}:"*) ;;
    *)
        # Append to the user's actual login shell rc, falling back sanely
        # if the conventional file does not exist yet.
        case "$(basename "${SHELL:-/bin/zsh}")" in
            zsh)  ensure_path_in_rc "${HOME}/.zshrc" ;;
            bash) ensure_path_in_rc "${HOME}/.bash_profile" ;;
            fish) yellow "fish detected; add ~/.local/bin to fish_user_paths manually." ;;
            *)    ensure_path_in_rc "${HOME}/.profile" ;;
        esac
        yellow "open a new terminal or run 'source ~/.zshrc' to pick up PATH changes."
        ;;
esac

# ---- run setup (only on a fresh install) -----------------------------------

# An existing .gizhashes means an account already lives at DATA_DIR. Re-running
# the installer is then an upgrade, not a first run. We must NOT call
# 'giz --setup' in that case: giz will refuse with exit 4, but more
# importantly, asking for nickname/passwords here would imply we are about
# to clobber the account. We never touch DATA_DIR contents in either path.
if [[ -f "${DATA_DIR}/.gizhashes" ]]; then
    green "upgrade complete. existing account at ${DATA_DIR} preserved."
    dim   "run 'giz' to log in with your existing password."
    exit 0
fi

green "install complete. starting first-run setup..."
echo

# Redirect stdin from the controlling terminal explicitly so that
# 'curl ... | bash' still allows interactive input during setup.
# Without this, getpass and input() see EOF immediately and abort.
if [[ -r /dev/tty ]]; then
    exec "${LAUNCHER}" --setup </dev/tty
else
    yellow "warning: /dev/tty unavailable. Run \"giz --setup\" from a terminal to finish."
    exit 0
fi
