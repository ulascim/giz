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

GIZ_VERSION="v0.2.6"
REPO="ulascim/giz"
RELEASE_BASE="https://github.com/${REPO}/releases/download/v0.1.0"
SOURCE_TARBALL="https://github.com/${REPO}/archive/refs/tags/${GIZ_VERSION}.tar.gz"

# SHA-256 of the source tarball at the tag. Computed once when the tag
# is cut and recorded here. install.sh aborts on mismatch; this is the
# binding artifact integrity check for everything inside the source
# archive (giz/*.py, requirements.lock.txt, pyproject.toml, etc.).
# Auditors verify by:
#   curl -fsSL https://github.com/ulascim/giz/archive/refs/tags/v0.2.0.tar.gz \
#     | shasum -a 256
SOURCE_SHA="1b699bf0725621fc5178bc851e1fc75d3647421ddd3329c973c72e4fe753756c"

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

# Find an existing Homebrew install even if `brew` is not yet on PATH.
# A fresh macOS Terminal can have brew installed but the shell rc not
# yet sourced; we should not declare 'brew missing' in that case.
find_brew() {
    if command -v brew >/dev/null 2>&1; then
        command -v brew
        return 0
    fi
    for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
        if [[ -x "${candidate}" ]]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    return 1
}

if ! have_java_17; then
    yellow "Java 17+ not found - installing it now."
    BREW_BIN="$(find_brew || true)"
    if [[ -z "${BREW_BIN}" ]]; then
        red "Homebrew is required to install Java but was not found."
        red ""
        red "Install Homebrew first by running this single line in Terminal:"
        red ""
        red "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        red ""
        red "Homebrew will ask for your Mac password (this is normal; it's"
        red "needed to write to /opt/homebrew on Apple Silicon or to"
        red "/usr/local on Intel). After Homebrew finishes, re-run the"
        red "giz one-liner:"
        red ""
        red "  curl -fsSL https://raw.githubusercontent.com/ulascim/giz/main/install.sh | bash"
        die "exiting; install Homebrew first"
    fi
    dim "using Homebrew at ${BREW_BIN}"

    # Capture stderr so we can show what actually went wrong if the
    # install fails. brew install does NOT need sudo for a normal user
    # install; if it asks for a password something is unusual.
    BREW_LOG="${TMP_DIR:-/tmp}/giz-brew-openjdk17.log"
    if ! "${BREW_BIN}" install openjdk@17 >"${BREW_LOG}" 2>&1; then
        red "brew install openjdk@17 failed. last 20 lines of output:"
        red "--------------------------------------------------------"
        tail -n 20 "${BREW_LOG}" | sed 's/^/  /'
        red "--------------------------------------------------------"
        red "full log: ${BREW_LOG}"
        die "Java install failed"
    fi

    BREW_PREFIX="$("${BREW_BIN}" --prefix 2>/dev/null || true)"
    JAVA_BIN="${BREW_PREFIX}/opt/openjdk@17/bin/java"
    if [[ ! -x "${JAVA_BIN}" ]]; then
        red "openjdk@17 installed but ${JAVA_BIN} not found."
        red "Try running:  ${BREW_BIN} reinstall openjdk@17"
        die "Java not at the expected path after install"
    fi
    export PATH="${BREW_PREFIX}/opt/openjdk@17/bin:${PATH}"

    # Final ground-truth check: actually run java -version. If this
    # fails we abort here, NOT later when the user tries to log in.
    if ! "${JAVA_BIN}" -version >/dev/null 2>&1; then
        red "${JAVA_BIN} exists but cannot be executed."
        red "Try:  xattr -dr com.apple.quarantine \"$(dirname "${JAVA_BIN}")\""
        die "Java binary present but unrunnable"
    fi
    have_java_17 || die "Java 17 still not visible after install. Add ${BREW_PREFIX}/opt/openjdk@17/bin to PATH manually."
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

# Read the top-level directory name from the tarball itself so we never
# rely on a shell glob (which silently expands to its literal pattern
# when no file matches, and produced 'source tarball did not extract as
# expected' on at least one user's macOS Tahoe install). 'tar -tzf'
# lists archive contents without extracting; the first entry is always
# the top-level dir for a GitHub tag tarball.
TOP_LEVEL="$(tar -tzf "${TMP_DIR}/giz.tar.gz" 2>/dev/null | head -n1 | cut -d/ -f1)"
if [[ -z "${TOP_LEVEL}" ]]; then
    red "could not list contents of ${TMP_DIR}/giz.tar.gz"
    red "this means the source tarball is corrupted or 'tar' is broken."
    red "tar -tzf output:"
    tar -tzf "${TMP_DIR}/giz.tar.gz" 2>&1 | sed 's/^/  /' | head -n 5
    die "tar listing failed"
fi

if ! tar -xzf "${TMP_DIR}/giz.tar.gz" -C "${TMP_DIR}" 2>"${TMP_DIR}/tar.err"; then
    red "tar extract failed. last 20 lines of stderr:"
    tail -n 20 "${TMP_DIR}/tar.err" | sed 's/^/  /'
    die "tar extract failed"
fi

SRC_DIR="${TMP_DIR}/${TOP_LEVEL}"
if [[ ! -d "${SRC_DIR}" ]]; then
    red "expected ${SRC_DIR} after extraction but it is missing."
    red "TMP_DIR contents:"
    ls -la "${TMP_DIR}" | sed 's/^/  /'
    die "source tarball did not extract as expected"
fi

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

# ---- second launcher on the Homebrew bin --------------------------------
#
# Why: ${LAUNCHER} lives in ~/.local/bin which we have to add to PATH via
# rc files. Appending to .zshrc does NOT update an already-running
# shell, so users who type 'giz' in the SAME terminal that ran
# 'curl ... | bash' get 'command not found' even after a successful
# install. /opt/homebrew/bin (Apple Silicon) and /usr/local/bin (Intel)
# are on PATH for every macOS shell out of the box, AND after Homebrew
# is set up they are user-writable without sudo, so we can drop a
# symlink there without prompting for a password. This is the same
# trick npm install -g and pip --user use, but explicit.
#
# We write a thin shim instead of a raw symlink so that 'realpath' and
# 'readlink -f' on the second copy still resolve to a real file the
# user can audit, and so deleting ~/.local/bin/giz never breaks the
# shim.

BREW_BIN_DIR=""
case "${OS_KIND}" in
    Darwin)
        if BREW_BIN_PATH="$(find_brew 2>/dev/null)"; then
            BREW_BIN_DIR="$(dirname "${BREW_BIN_PATH}")"
        fi
        ;;
    Linux)
        # Linuxbrew is rare; if a user has it we honor it but most
        # distros put ~/.local/bin on PATH already so we do not need
        # this step there.
        if BREW_BIN_PATH="$(find_brew 2>/dev/null)"; then
            BREW_BIN_DIR="$(dirname "${BREW_BIN_PATH}")"
        fi
        ;;
esac

GIZ_ON_PATH=0
if [[ -n "${BREW_BIN_DIR}" ]] && [[ -w "${BREW_BIN_DIR}" ]]; then
    BREW_LAUNCHER="${BREW_BIN_DIR}/giz"
    cat > "${BREW_LAUNCHER}" <<EOF
#!/usr/bin/env bash
# giz shim (mirrors ${LAUNCHER}). Edit the real launcher, not this.
exec "${LAUNCHER}" "\$@"
EOF
    chmod +x "${BREW_LAUNCHER}"
    dim "installed ${BREW_LAUNCHER} (already on PATH)"
    GIZ_ON_PATH=1
fi

# ---- Time Machine exclusion (best-effort) -----------------------------------

if [[ "${OS_KIND}" == "Darwin" ]] && command -v tmutil >/dev/null 2>&1; then
    tmutil addexclusion "${DATA_DIR}" >/dev/null 2>&1 || true
fi

# ---- PATH (auto, idempotent, defensive) -------------------------------------
#
# We write the PATH export to MULTIPLE rc files because it is impossible to
# know in advance which one the user's interactive shell will read on next
# launch. macOS Terminal opens login shells -> zsh reads .zprofile then
# .zshrc; bash reads .bash_profile (or .profile). Linux non-login shells
# read .bashrc. We append to all of them, guarded by an idempotent marker
# so re-installs never duplicate the line.

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

PATH_NEEDED=0
case ":${PATH}:" in
    *":${LAUNCHER_DIR}:"*) ;;
    *) PATH_NEEDED=1 ;;
esac

if [[ "${PATH_NEEDED}" == "1" ]]; then
    case "$(basename "${SHELL:-/bin/zsh}")" in
        zsh)
            # zsh: login shell reads .zprofile, interactive reads .zshrc.
            # Write to both - cheap and immune to user shell config quirks.
            ensure_path_in_rc "${HOME}/.zshrc"
            ensure_path_in_rc "${HOME}/.zprofile"
            ;;
        bash)
            # bash: macOS login shell reads .bash_profile; many Linux setups
            # source .bashrc from there. Write to all three to be safe.
            ensure_path_in_rc "${HOME}/.bash_profile"
            ensure_path_in_rc "${HOME}/.bashrc"
            ensure_path_in_rc "${HOME}/.profile"
            ;;
        fish)
            yellow "fish detected. add ~/.local/bin to fish_user_paths manually:"
            yellow "    fish_add_path \"\$HOME/.local/bin\""
            ;;
        *)
            ensure_path_in_rc "${HOME}/.profile"
            ;;
    esac
fi

# ---- run setup (only on a fresh install) -----------------------------------

# An existing .gizhashes means an account already lives at DATA_DIR. Re-running
# the installer is then an upgrade, not a first run. We must NOT call
# 'giz --setup' in that case: giz will refuse with exit 4, but more
# importantly, asking for nickname/passwords here would imply we are about
# to clobber the account. We never touch DATA_DIR contents in either path.
SETUP_NEEDED=0
if [[ -f "${DATA_DIR}/.gizhashes" ]]; then
    green "upgrade complete. existing account at ${DATA_DIR} preserved."
else
    SETUP_NEEDED=1
    green "install complete. starting first-run setup..."
    echo
    # Redirect stdin from the controlling terminal explicitly so that
    # 'curl ... | bash' still allows interactive input during setup.
    # Without this, getpass and input() see EOF immediately and abort.
    # We deliberately do NOT exec here so we can print the post-install
    # banner with launch instructions after setup finishes.
    if [[ -r /dev/tty ]]; then
        if ! "${LAUNCHER}" --setup </dev/tty; then
            red "first-run setup failed. you can re-run it later with:"
            red "    ${LAUNCHER} --setup"
            exit 1
        fi
    else
        yellow "warning: /dev/tty unavailable. Run \"${LAUNCHER} --setup\" from a terminal to finish."
        exit 0
    fi
fi

# ---- final banner: how to actually start giz --------------------------------
#
# This is the bit users miss. Appending to .zshrc does NOT update the PATH of
# the shell that ran 'curl ... | bash' - that shell already loaded its rc.
# The user types 'giz', gets command-not-found, and thinks the install broke.
# Spell out every fallback so this stops happening.

echo
bold "────────────────────────────────────────────────────────────"
bold "  giz is installed."
echo
if [[ "${GIZ_ON_PATH}" == "1" ]]; then
    # We dropped a shim into a directory that is already on every
    # macOS shell's PATH. The user can literally just type 'giz'.
    green "  to start it, type:"
    green "          giz"
    echo
    dim   "  (the launcher also lives at ${LAUNCHER} for direct use.)"
else
    # Fallback path: PATH-via-rc only. The absolute path is the
    # most-foolproof option, so it goes FIRST.
    green "  to start it, the most reliable way is to run by"
    green "  absolute path (works in every shell, no PATH edits needed):"
    green "          ${LAUNCHER}"
    echo
    green "  or open a NEW terminal window and type:"
    green "          giz"
    echo
    green "  or, in THIS terminal, refresh PATH and start giz:"
    case "$(basename "${SHELL:-/bin/zsh}")" in
        zsh)  green "          source ~/.zshrc && giz" ;;
        bash) green "          source ~/.bash_profile && giz" ;;
        fish) green "          fish_add_path \"\$HOME/.local/bin\" && giz" ;;
        *)    green "          source ~/.profile && giz" ;;
    esac
fi
bold "────────────────────────────────────────────────────────────"
echo
