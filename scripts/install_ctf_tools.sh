#!/usr/bin/env bash
# shellcheck disable=SC2024  # redirects target user-owned log file, not sudo
# Bootstrap common tooling for the solve-challenge skill.
#
# Usage:
#   bash scripts/install_ctf_tools.sh [OPTIONS] MODE
#
# Modes:
#   python, apt, brew, gems, go, pat, manual, all, --verify
#
# Options (flags must come BEFORE MODE):
#   --dry-run         Show what would be installed without installing
#   --force           Reinstall packages even if already present
#   --only LIST       Install only these tool groups (comma-separated)
#   --skip LIST       Exclude tool groups or backends (comma-separated)
#   --list-groups     Print the tool-group table and exit 0
#
# Tool groups (skill categories): crypto, web, pwn, reverse, forensics,
# misc, malware, osint. Backends skippable via --skip:
# python, apt, brew, gems, go, pat, manual.
#
# Examples:
#   bash scripts/install_ctf_tools.sh all
#   bash scripts/install_ctf_tools.sh --dry-run all
#   bash scripts/install_ctf_tools.sh --force python
#   bash scripts/install_ctf_tools.sh --verify
#   bash scripts/install_ctf_tools.sh --only crypto,web --dry-run all
#   bash scripts/install_ctf_tools.sh --only crypto --skip gems,go python
#   bash scripts/install_ctf_tools.sh --list-groups

set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

DRY_RUN=false
FORCE=false
MODE=""
FAILED=()
SUCCEEDED=()
SKIPPED=()
LOG_DIR="${HOME}/.ctf-tools"
LOG_FILE=""
CTF_VENV="${HOME}/.ctf-tools/venv"
PAT_DIR="${HOME}/.ctf-tools/PayloadsAllTheThings"
WEB_PAT_DIR="ctf-web/payloads/PayloadsAllTheThings"
ONLY_GROUPS=""
SKIP_GROUPS=""
LIST_GROUPS=false
ONLY_NORM=""
SKIP_NORM=""
SKIP_GROUPS_ONLY=""
SKIP_BACKENDS=""
ACTIVE_GROUPS=""
SELECT_PIPS=""
SELECT_APTS=""
SELECT_BREWS=""
SELECT_GEMS=""
SELECT_GOS=""
SELECT_PATS=""
SELECT_MANUALS=""
SELECTION_ACTIVE=false
VALID_GROUPS="crypto web pwn reverse forensics misc malware osint"
VALID_BACKENDS="python apt brew gems go pat manual"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --force) FORCE=true; shift ;;
    --only=*) ONLY_GROUPS="${1#--only=}"; shift ;;
    --only)
      if [ $# -lt 2 ]; then echo "Option --only requires a value" >&2; exit 2; fi
      ONLY_GROUPS="$2"; shift 2 ;;
    --skip=*) SKIP_GROUPS="${1#--skip=}"; shift ;;
    --skip)
      if [ $# -lt 2 ]; then echo "Option --skip requires a value" >&2; exit 2; fi
      SKIP_GROUPS="$2"; shift 2 ;;
    --list-groups) LIST_GROUPS=true; shift ;;
    -*) if [ -z "$MODE" ]; then MODE="$1"; shift; else echo "Unknown option: $1" >&2; exit 2; fi ;;
    *) MODE="$1"; shift ;;
  esac
done
MODE="${MODE:-all}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

setup_logging() {
  mkdir -p "$LOG_DIR"
  LOG_FILE="${LOG_DIR}/install-$(date +%Y-%m-%d_%H%M%S).log"
  log_info "Logging to $LOG_FILE"
}

log_info() { echo "==> $*" | tee -a "${LOG_FILE:-/dev/null}"; }
log_warn() { echo "WARNING: $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_error() { echo "ERROR: $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_detail() { echo "    $*" >> "${LOG_FILE:-/dev/null}"; }

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "'$cmd' is required but not found in PATH"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Skip-if-installed checks
# ---------------------------------------------------------------------------

# Check if a Python module is importable.
py_module_installed() {
  python3 -c "import $1" 2>/dev/null
}

# Check if an apt package is installed.
apt_pkg_installed() {
  dpkg -s "$1" >/dev/null 2>&1
}

# Check if a Homebrew formula is installed.
brew_pkg_installed() {
  brew list --formula "$1" >/dev/null 2>&1
}

# Check if a Ruby gem is installed.
gem_installed() {
  gem list -i "^${1}$" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Pip package list — name=version:import_module
#
# Format: "pip_name==version:import_name"
# The import_name is used for skip-if-installed checks.
# uv alternative: uv venv && uv pip install "pwntools==4.15.0" "ROPgadget==7.7" "ropper==1.13.13"
# Optional cross-arch (ARM/MIPS): apt install qemu-user qemu-user-static qemu-user-binfmt gdb-multiarch binutils-multiarch libc6-armhf-cross libc6-arm64-cross libc6-mips-cross
# ---------------------------------------------------------------------------

PIP_PACKAGES=(
  "pwntools==4.15.0:pwn"
  "pycryptodome==4.0.0:Crypto"
  "z3-solver==5.1.0.0:z3"
  "sympy==1.14.0:sympy"
  "gmpy2==2.3.2:gmpy2"
  "hashpumpy==1.2:hashpumpy"
  "fpylll==0.6.4:fpylll"
  "py_ecc==8.0.0:py_ecc"
  "ecdsa==0.19.2:ecdsa"
  # Coppersmith — no reliable PyPI package as of 2026-09 (pip install coppersmith not found);
  # use manual clone: git clone https://github.com/jvdsn/crypto-attacks ~/.ctf-tools/crypto-attacks
  # (fpylll + sympy already enable pure-Python Coppersmith via lattice construction)
  "angr==10.0.4.post1:angr"
  "frida-tools==14.11.0:frida"
  "qiling==1.4.6:qiling"
  "requests==2.34.2:requests"
  "httpx==0.28.1:httpx"
  "flask-unsign==1.2.1:flask_unsign"
  "sqlmap==1.10.10:sqlmap"
  "ropper==1.13.13:ropper"
  "ROPgadget==7.7:ropgadget"
  "volatility3==2.28.2:volatility3"
  "yara-python==4.5.4:yara"
  "pefile==2024.8.26:pefile"
  "capstone==5.0.9:capstone"
  "r2pipe==1.9.8:r2pipe"
  "keystone-engine==0.9.2:keystone"
  "oletools==0.60.2:oletools"
  "unicorn==2.1.4:unicorn"
  "pyelftools==0.33:elftools"
  "scapy==2.8.0:scapy"
  "Pillow==12.3.0:PIL"
  "numpy==2.5.4:numpy"
  "matplotlib==3.11.2:matplotlib"
  "shodan==1.31.0:shodan"
  "uncompyle6==3.9.3:uncompyle6"
  "lief==1.0.0:lief"
  "dnspython==2.9.0:dns"
  "dnslib==0.9.26:dnslib"
  "segno==1.6.6:segno"
  "dissect.cobaltstrike==1.3.0:dissect.cobaltstrike"
  "python-evtx==0.8.1:Evtx"
  "scipy==1.18.1:scipy"
  "librosa==1.0.0:librosa"
  "scikit-learn==1.9.1:sklearn"
  "opencv-python-headless==5.0.0.93:cv2"
  "pymongo==4.19.0:bson"
  "impacket==0.13.1:impacket"
  "brotli==1.2.0:brotli"
  "exrex==0.12.0:exrex"
  "stegano==3.0.0:stegano"
  "heatshrink2==0.14.0:heatshrink2"
)
# ---------------------------------------------------------------------------
# Tool groups — skill-category selections over the backend package lists.
#
# Derived from each category's SKILL.md Prerequisites plus `grep import`
# evidence in that category's snippets (see mapping comments). Selection is
# opt-in only: when --only/--skip are absent the installers use the full
# backend lists byte-identically to before. A group that selects nothing
# errors clearly via validate_selection (never silently succeeds).
# ---------------------------------------------------------------------------

# Selected pip names per group (pip_name only; version pin comes from PIP_PACKAGES).
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_PIPS_crypto="pwntools pycryptodome z3-solver sympy gmpy2 hashpumpy fpylll py_ecc ecdsa Pillow numpy requests"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_PIPS_web="sqlmap flask-unsign requests httpx hashpumpy py_ecc pwntools"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_PIPS_forensics="volatility3 Pillow numpy matplotlib scipy librosa scikit-learn opencv-python-headless pymongo impacket brotli exrex stegano heatshrink2 scapy pycryptodome dnspython uncompyle6 python-evtx"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_PIPS_reverse="frida-tools angr qiling uncompyle6 capstone keystone-engine lief z3-solver pwntools pycryptodome Pillow unicorn pyelftools r2pipe numpy"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_PIPS_pwn="pwntools ROPgadget ropper sympy numpy"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_PIPS_misc="pwntools segno z3-solver Pillow numpy requests dnslib dnspython pycryptodome"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_PIPS_malware="yara-python pefile capstone oletools unicorn pycryptodome volatility3 dissect.cobaltstrike scapy requests"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_PIPS_osint="shodan Pillow opencv-python-headless numpy"

# Selected OS packages per group (subset of the install_apt/install_brew lists).
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_APTS_crypto="hashcat sagemath"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_APTS_web="hashcat jq curl"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_APTS_pwn="gdb binutils strace ltrace qemu-system-x86"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_APTS_reverse="gdb radare2 binutils strace ltrace apktool upx"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_APTS_forensics="gdb binutils binwalk foremost libimage-exiftool-perl tshark sleuthkit ffmpeg steghide testdisk john pcapfix strace ltrace nmap whois dnsutils hashcat imagemagick curl apktool upx qemu-system-x86 qrencode"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_APTS_misc="ffmpeg qrencode libzbar0 sagemath"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_APTS_malware="strace ltrace tshark binwalk binutils"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_APTS_osint="whois dnsutils nmap libimage-exiftool-perl imagemagick curl"

# shellcheck disable=SC2034 # read via group_var indirection
GROUP_BREWS_crypto="hashcat"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_BREWS_web="hashcat jq curl"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_BREWS_pwn="gdb binutils qemu"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_BREWS_reverse="gdb radare2 binutils apktool upx ghidra"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_BREWS_forensics="gdb radare2 binutils binwalk exiftool wireshark sleuthkit ffmpeg testdisk john-jumbo nmap whois bind hashcat ghidra imagemagick curl jq apktool upx qemu qrencode"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_BREWS_misc="ffmpeg qrencode"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_BREWS_malware="wireshark binwalk binutils ghidra"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_BREWS_osint="whois bind nmap exiftool imagemagick curl"

# Non-pip backends owned per group (gems/go/pat/manual are backend-granular).
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_GEMS_pwn="one_gadget seccomp-tools"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_GEMS_forensics="zsteg"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_GOS_web="ffuf"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_PATS_web="PayloadsAllTheThings"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_MANUALS_crypto="RsaCtfTool SageMath crypto-attacks"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_MANUALS_reverse="pwndbg pycdc"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_MANUALS_forensics="steghide"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_MANUALS_malware="dnSpy"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_MANUALS_pwn="pwndbg"
# shellcheck disable=SC2034 # read via group_var indirection
GROUP_MANUALS_web="PAT ysoserial"

print_groups() {
  cat <<'EOF'
Tool groups (skill categories) — pip / apt+brew / backend selections:
  crypto    pip: pwntools pycryptodome z3-solver sympy gmpy2 hashpumpy fpylll py_ecc ecdsa Pillow numpy requests | os: hashcat sagemath | manual: RsaCtfTool SageMath crypto-attacks
  web       pip: sqlmap flask-unsign requests httpx hashpumpy py_ecc pwntools | os: hashcat jq curl | go: ffuf | pat: PayloadsAllTheThings
  pwn       pip: pwntools ROPgadget ropper sympy numpy | os: gdb binutils strace ltrace qemu-system-x86 | gems: one_gadget seccomp-tools | manual: pwndbg
  reverse   pip: frida-tools angr qiling uncompyle6 capstone keystone-engine lief z3-solver pwntools pycryptodome Pillow unicorn pyelftools r2pipe numpy | os: gdb radare2 binutils strace ltrace apktool upx (+brew ghidra) | manual: pwndbg pycdc
  forensics pip: volatility3 Pillow numpy matplotlib scipy librosa scikit-learn opencv-python-headless pymongo impacket brotli exrex stegano heatshrink2 scapy pycryptodome dnspython uncompyle6 | os: binwalk foremost libimage-exiftool-perl tshark sleuthkit ffmpeg steghide testdisk john pcapfix + shared | gems: zsteg
  misc      pip: pwntools segno z3-solver Pillow numpy requests dnslib dnspython pycryptodome | os: ffmpeg qrencode libzbar0 sagemath
  malware   pip: yara-python pefile capstone oletools unicorn pycryptodome volatility3 dissect.cobaltstrike scapy requests | os: strace ltrace tshark binwalk binutils (+brew ghidra) | manual: dnSpy
  osint     pip: shodan Pillow opencv-python-headless numpy | os: whois dnsutils nmap libimage-exiftool-perl imagemagick curl
Backends skippable via --skip: python apt brew gems go pat manual
EOF
}

# Normalize a comma/space-separated list: lowercase, one per line, deduped.
norm_list() {
  tr ', ' '\n' <<<"$1" | tr '[:upper:]' '[:lower:]' | grep -v '^$' | awk '!seen[$0]++'
}

# Look up a GROUP_*_<group> variable by backend prefix and group name.
group_var() {
  local prefix="$1"
  local group="$2"
  local var="${prefix}_${group}"
  printf '%s' "${!var:-}"
}

# Validate + resolve --only/--skip into Active selection strings.
validate_selection() {
  ONLY_NORM="$(norm_list "$ONLY_GROUPS")"
  SKIP_NORM="$(norm_list "$SKIP_GROUPS")"
  SKIP_GROUPS_ONLY=""
  SKIP_BACKENDS=""
  local bad=()
  local tok
  for tok in $SKIP_NORM; do
    case " $VALID_BACKENDS " in
      *" $tok "*) SKIP_BACKENDS="$SKIP_BACKENDS $tok" ;;
      *)
        case " $VALID_GROUPS " in
          *" $tok "*) SKIP_GROUPS_ONLY="$SKIP_GROUPS_ONLY $tok" ;;
          *) bad+=("$tok") ;;
        esac
        ;;
    esac
  done
  if [ -n "$ONLY_GROUPS" ]; then
    for tok in $ONLY_NORM; do
      case " $VALID_GROUPS " in
        *" $tok "*) ;;
        *) bad+=("$tok") ;;
      esac
    done
  fi
  if [ ${#bad[@]} -gt 0 ]; then
    log_error "Unknown group(s): ${bad[*]} (valid groups: $VALID_GROUPS; skippable backends: $VALID_BACKENDS)"
    echo "Valid groups: $VALID_GROUPS" >&2
    return 2
  fi

  if [ -z "$ONLY_GROUPS" ] && [ -z "$SKIP_GROUPS" ]; then
    SELECTION_ACTIVE=false
    ACTIVE_GROUPS="$VALID_GROUPS"
    return 0
  fi
  SELECTION_ACTIVE=true

  # Start from --only (or everything), then subtract --skip groups.
  local active
  if [ -n "$ONLY_GROUPS" ]; then
    active="$ONLY_NORM"
  else
    active="$VALID_GROUPS"
  fi
  local keep=""
  for tok in $active; do
    local drop=false
    for s in $SKIP_GROUPS_ONLY; do
      if [ "$tok" = "$s" ]; then drop=true; break; fi
    done
    if [ "$drop" = false ]; then keep="$keep $tok"; fi
  done
  active="$(norm_list "$keep" | tr '\n' ' ' | sed 's/ *$//')"
  ACTIVE_GROUPS="$active"

  # Union each backend's needs across the surviving groups.
  local pips="" apts="" brews="" gems="" gos="" pats="" manuals=""
  local g
  for g in $active; do
    pips="$pips $(group_var GROUP_PIPS "$g")"
    apts="$apts $(group_var GROUP_APTS "$g")"
    brews="$brews $(group_var GROUP_BREWS "$g")"
    gems="$gems $(group_var GROUP_GEMS "$g")"
    gos="$gos $(group_var GROUP_GOS "$g")"
    pats="$pats $(group_var GROUP_PATS "$g")"
    manuals="$manuals $(group_var GROUP_MANUALS "$g")"
  done
  SELECT_PIPS="$(norm_list "$pips")"
  SELECT_APTS="$(norm_list "$apts")"
  SELECT_BREWS="$(norm_list "$brews")"
  SELECT_GEMS="$(norm_list "$gems")"
  SELECT_GOS="$(norm_list "$gos")"
  SELECT_PATS="$(norm_list "$pats")"
  SELECT_MANUALS="$(norm_list "$manuals")"

  if [ -z "$active" ]; then
    log_error "Selection is empty: nothing left after --only/--skip (groups: only='${ONLY_GROUPS:-all}' skip='${SKIP_GROUPS:-none}')"
    return 2
  fi
  if [ -z "$ONLY_GROUPS" ] && [ -z "$SKIP_GROUPS_ONLY" ]; then
    # Backend-only --skip: no group filtering, keep full package lists.
    SELECTION_ACTIVE=false
    ACTIVE_GROUPS="$VALID_GROUPS"
    return 0
  fi
  return 0
}

# True if group filtering is active and this backend is skipped outright.
backend_skipped() {
  case " $SKIP_BACKENDS " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

# Filter a backend's full package list down to the group selection (by name).
filter_pips() {
  local entry spec name
  for entry in "${PIP_PACKAGES[@]}"; do
    spec="${entry%%:*}"
    name="${spec%%==*}"
    for tok in $SELECT_PIPS; do
      if [ "$(tr '[:upper:]' '[:lower:]' <<<"$name")" = "$tok" ]; then
        printf '%s\n' "$entry"
        break
      fi
    done
  done
}

filter_list() {
  local want="$1"; shift
  local pkg key
  for pkg in "$@"; do
    key="$(tr '[:upper:]' '[:lower:]' <<<"$pkg")"
    for tok in $want; do
      if [ "$key" = "$tok" ]; then
        printf '%s\n' "$pkg"
        break
      fi
    done
  done
}

# ---------------------------------------------------------------------------
# Installers
# ---------------------------------------------------------------------------

install_python() {
  require_cmd python3 || return 1

  local pip_flags=()

  # PEP 668: prefer creating a dedicated venv over --user
  if python3 -c "import sysconfig; marker = sysconfig.get_path('stdlib') + '/EXTERNALLY-MANAGED'; open(marker)" 2>/dev/null; then
    if [ -z "${VIRTUAL_ENV:-}" ]; then
      if [ "$DRY_RUN" = true ]; then
        log_info "PEP 668 detected — would create virtualenv at $CTF_VENV"
      else
        log_info "PEP 668 detected — creating virtualenv at $CTF_VENV"
        python3 -m venv "$CTF_VENV" 2>>"${LOG_FILE:-/dev/null}" || {
          log_warn "venv creation failed — falling back to --user"
          pip_flags+=(--user)
        }
        if [ -d "$CTF_VENV" ] && [ -z "${pip_flags[*]:-}" ]; then
          # shellcheck disable=SC1091
          source "$CTF_VENV/bin/activate"
          log_info "Activated virtualenv: $CTF_VENV"
          log_info "To reuse: source $CTF_VENV/bin/activate"
        fi
      fi
    fi
  fi

  # Install libgmp-dev first if on apt-based systems — required by gmpy2
  if command -v apt-get >/dev/null 2>&1; then
    if ! dpkg -s libgmp-dev >/dev/null 2>&1; then
      if [ "$DRY_RUN" = true ]; then
        log_info "Would install libgmp-dev (required by gmpy2)"
      else
        log_info "Installing libgmp-dev (required by gmpy2)"
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q libgmp-dev >>"${LOG_FILE:-/dev/null}" 2>&1 || log_warn "Could not install libgmp-dev"
      fi
    fi
  fi

  # First pass: collect packages that need installing
  local to_install=()
  local to_install_display=()
  local pip_list=("${PIP_PACKAGES[@]}")
  local pip_total="${#PIP_PACKAGES[@]}"
  if [ "$SELECTION_ACTIVE" = true ]; then
    mapfile -t pip_list < <(filter_pips)
    pip_total="${#pip_list[@]}"
    if [ "$pip_total" -eq 0 ]; then
      log_error "Selection matched no pip packages (groups: $ACTIVE_GROUPS)"
      return 2
    fi
    log_info "Groups: $ACTIVE_GROUPS"
  fi
  for entry in "${pip_list[@]}"; do
    local spec="${entry%%:*}"
    local mod="${entry##*:}"
    local name="${spec%%==*}"

    if [ "$FORCE" = false ] && py_module_installed "$mod"; then
      SKIPPED+=("pip:$name")
      continue
    fi
    to_install+=("$spec")
    to_install_display+=("$name")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "Python: all ${pip_total} packages already installed"
    return 0
  fi

  log_info "Python: ${#to_install[@]}/${pip_total} packages to install (${#SKIPPED[@]} skipped)"
  if [ "$DRY_RUN" = true ]; then
    log_info "Would install: ${to_install_display[*]}"
    return 0
  fi

  # Try batch install first (pip handles parallelism internally)
  log_info "Attempting batch install of ${#to_install[@]} packages"
  if python3 -m pip install "${pip_flags[@]}" "${to_install[@]}" >>"$LOG_FILE" 2>&1; then
    for entry in "${to_install_display[@]}"; do
      SUCCEEDED+=("pip:$entry")
    done
    log_info "Batch install succeeded"
    return 0
  fi

  # Batch failed — fall back to one-by-one
  log_warn "Batch install failed — falling back to individual installs"
  for entry in "${pip_list[@]}"; do
    local spec="${entry%%:*}"
    local mod="${entry##*:}"
    local name="${spec%%==*}"

    if [ "$FORCE" = false ] && py_module_installed "$mod"; then
      continue
    fi

    if python3 -m pip install "${pip_flags[@]}" "$spec" >>"$LOG_FILE" 2>&1; then
      SUCCEEDED+=("pip:$name")
    else
      log_warn "pip install failed: $name"
      log_detail "Failed command: python3 -m pip install ${pip_flags[*]} $spec"
      FAILED+=("pip:$name")
    fi
  done
}

install_apt() {
  require_cmd apt-get || return 1

  # Optional cross-arch (ARM/MIPS) — not auto-installed; run manually if needed:
  #   apt install qemu-user qemu-user-static qemu-user-binfmt gdb-multiarch binutils-multiarch libc6-armhf-cross libc6-arm64-cross libc6-mips-cross
  local packages=(
    gdb radare2 binutils binwalk foremost libimage-exiftool-perl
    tshark sleuthkit ffmpeg steghide testdisk john pcapfix
    nmap whois dnsutils hashcat strace ltrace imagemagick curl jq
    apktool upx qemu-system-x86 sagemath qrencode libzbar0
  )
  local apt_total="${#packages[@]}"
  if [ "$SELECTION_ACTIVE" = true ]; then
    mapfile -t packages < <(filter_list "$SELECT_APTS" "${packages[@]}")
    apt_total="${#packages[@]}"
    if [ "$apt_total" -eq 0 ]; then
      log_info "apt: no packages for groups: $ACTIVE_GROUPS (skipped)"
      return 0
    fi
    log_info "Groups: $ACTIVE_GROUPS"
  fi

  # Collect packages that need installing
  local to_install=()
  for pkg in "${packages[@]}"; do
    if [ "$FORCE" = false ] && apt_pkg_installed "$pkg"; then
      SKIPPED+=("apt:$pkg")
      continue
    fi
    to_install+=("$pkg")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "apt: all ${apt_total} packages already installed"
    return 0
  fi

  log_info "apt: ${#to_install[@]}/${apt_total} packages to install (${#SKIPPED[@]} skipped)"

  if [ "$DRY_RUN" = true ]; then
    log_info "Would install: ${to_install[*]}"
    return 0
  fi

  log_info "Updating apt package lists"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -q >>"$LOG_FILE" 2>&1 || log_warn "apt-get update failed"

  for pkg in "${to_install[@]}"; do
    if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$pkg" >>"$LOG_FILE" 2>&1; then
      SUCCEEDED+=("apt:$pkg")
    else
      log_warn "apt install failed: $pkg"
      FAILED+=("apt:$pkg")
    fi
  done
}

install_brew() {
  require_cmd brew || return 1

  local packages=(
    gdb radare2 binutils binwalk exiftool wireshark sleuthkit
    ffmpeg testdisk john-jumbo nmap whois bind hashcat ghidra
    imagemagick curl jq apktool upx qemu qrencode
  )
  local brew_total="${#packages[@]}"
  if [ "$SELECTION_ACTIVE" = true ]; then
    mapfile -t packages < <(filter_list "$SELECT_BREWS" "${packages[@]}")
    brew_total="${#packages[@]}"
    if [ "$brew_total" -eq 0 ]; then
      log_info "brew: no packages for groups: $ACTIVE_GROUPS (skipped)"
      return 0
    fi
    log_info "Groups: $ACTIVE_GROUPS"
  fi

  # Collect packages that need installing
  local to_install=()
  for pkg in "${packages[@]}"; do
    if [ "$FORCE" = false ] && brew_pkg_installed "$pkg"; then
      SKIPPED+=("brew:$pkg")
      continue
    fi
    to_install+=("$pkg")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "brew: all ${brew_total} packages already installed"
    return 0
  fi

  log_info "brew: ${#to_install[@]}/${brew_total} packages to install (${#SKIPPED[@]} skipped)"

  if [ "$DRY_RUN" = true ]; then
    log_info "Would install: ${to_install[*]}"
    return 0
  fi

  for pkg in "${to_install[@]}"; do
    if brew install "$pkg" >>"$LOG_FILE" 2>&1; then
      SUCCEEDED+=("brew:$pkg")
    else
      log_warn "brew install failed: $pkg"
      FAILED+=("brew:$pkg")
    fi
  done
}

install_gems() {
  if ! command -v gem >/dev/null 2>&1; then
    log_warn "gem not found — skipping Ruby gem installs (install Ruby to enable)"
    SKIPPED+=(gem:one_gadget gem:seccomp-tools gem:zsteg)
    return 0
  fi

  local packages=(one_gadget seccomp-tools zsteg)
  local gem_total=3
  if [ "$SELECTION_ACTIVE" = true ]; then
    mapfile -t packages < <(filter_list "$SELECT_GEMS" "${packages[@]}")
    gem_total="${#packages[@]}"
    if [ "$gem_total" -eq 0 ]; then
      log_info "gems: no gems for groups: $ACTIVE_GROUPS (skipped)"
      return 0
    fi
    log_info "Groups: $ACTIVE_GROUPS"
  fi

  local to_install=()
  for pkg in "${packages[@]}"; do
    if [ "$FORCE" = false ] && gem_installed "$pkg"; then
      SKIPPED+=("gem:$pkg")
      continue
    fi
    to_install+=("$pkg")
  done

  if [ ${#to_install[@]} -eq 0 ]; then
    log_info "gems: all ${gem_total} gems already installed"
    return 0
  fi

  log_info "gems: ${#to_install[@]}/${gem_total} to install"

  if [ "$DRY_RUN" = true ]; then
    log_info "Would install: ${to_install[*]}"
    return 0
  fi

  for pkg in "${to_install[@]}"; do
    if gem install "$pkg" >>"$LOG_FILE" 2>&1; then
      SUCCEEDED+=("gem:$pkg")
    else
      log_warn "gem install failed: $pkg"
      FAILED+=("gem:$pkg")
    fi
  done
}

install_go() {
  if [ "$SELECTION_ACTIVE" = true ] && ! grep -qw "ffuf" <<<"$SELECT_GOS"; then
    log_info "go: no Go tools for groups: $ACTIVE_GROUPS (skipped)"
    return 0
  fi
  if [ "$SELECTION_ACTIVE" = true ]; then
    log_info "Groups: $ACTIVE_GROUPS"
  fi
  if ! command -v go >/dev/null 2>&1; then
    log_warn "go not found — skipping Go tool installs (install Go to enable)"
    SKIPPED+=(go:ffuf)
    return 0
  fi

  if [ "$FORCE" = false ] && command -v ffuf >/dev/null 2>&1; then
    log_info "go: ffuf already installed"
    SKIPPED+=(go:ffuf)
    return 0
  fi

  if [ "$DRY_RUN" = true ]; then
    log_info "Would install: ffuf"
    return 0
  fi

  log_info "Installing Go tools"
  if go install github.com/ffuf/ffuf/v2@latest >>"$LOG_FILE" 2>&1; then
    SUCCEEDED+=(go:ffuf)
  else
    log_warn "go install failed: ffuf"
    FAILED+=(go:ffuf)
  fi
}

install_pat() {
  local pat_url="https://github.com/swisskyrepo/PayloadsAllTheThings.git"
  if [ "$SELECTION_ACTIVE" = true ] && ! grep -qw "payloadsallthethings" <<<"$(tr '[:upper:]' '[:lower:]' <<<"$SELECT_PATS")"; then
    log_info "pat: PayloadsAllTheThings not needed for groups: $ACTIVE_GROUPS (skipped)"
    return 0
  fi
  if [ "$SELECTION_ACTIVE" = true ]; then
    log_info "Groups: $ACTIVE_GROUPS"
  fi
  # --force: remove existing clone first
  local pat_force_removed=false
  if [ "$FORCE" = true ] && [ -d "$PAT_DIR" ]; then
    if [ "$DRY_RUN" = true ]; then
      log_info "Would remove $PAT_DIR (--force)"
      pat_force_removed=true
    else
      log_info "Removing $PAT_DIR (--force)"
      rm -rf "$PAT_DIR"
    fi
  fi

  if [ "$pat_force_removed" = false ] && [ -d "$PAT_DIR/.git" ]; then
    if [ "$DRY_RUN" = true ]; then
      log_info "Would update PayloadsAllTheThings at $PAT_DIR (git -C \"$PAT_DIR\" pull --ff-only)"
    else
      log_info "Updating PayloadsAllTheThings at $PAT_DIR"
      if git -C "$PAT_DIR" pull --ff-only >>"${LOG_FILE:-/dev/null}" 2>&1; then
        SUCCEEDED+=("pat:PayloadsAllTheThings")
      else
        log_warn "git pull failed for PayloadsAllTheThings at $PAT_DIR"
        FAILED+=("pat:PayloadsAllTheThings")
      fi
    fi
  else
    if [ "$DRY_RUN" = true ]; then
      log_info "Would clone PayloadsAllTheThings: git clone --depth 1 $pat_url \"$PAT_DIR\""
    else
      log_info "Cloning PayloadsAllTheThings to $PAT_DIR"
      require_cmd git || return 1
      if git clone --depth 1 "$pat_url" "$PAT_DIR" >>"${LOG_FILE:-/dev/null}" 2>&1; then
        SUCCEEDED+=("pat:PayloadsAllTheThings")
      else
        log_warn "git clone failed for PayloadsAllTheThings"
        FAILED+=("pat:PayloadsAllTheThings")
        return 1
      fi
    fi
  fi

  # Symlink into ctf-web/payloads for on-demand use by the agent
  if [ "$DRY_RUN" = true ]; then
    log_info "Would link $PAT_DIR -> $WEB_PAT_DIR (mkdir -p \"\$(dirname \"$WEB_PAT_DIR\")\" && ln -sfn \"$PAT_DIR\" \"$WEB_PAT_DIR\")"
    return 0
  fi

  mkdir -p "$(dirname "$WEB_PAT_DIR")"
  if ln -sfn "$PAT_DIR" "$WEB_PAT_DIR" 2>>"${LOG_FILE:-/dev/null}"; then
    log_info "Linked $WEB_PAT_DIR -> $PAT_DIR"
  else
    log_warn "Symlink failed (Windows/read-only?) — falling back to direct clone into $WEB_PAT_DIR"
    if [ -d "$WEB_PAT_DIR/.git" ]; then
      git -C "$WEB_PAT_DIR" pull --ff-only >>"${LOG_FILE:-/dev/null}" 2>&1 || true
    else
      rm -rf "$WEB_PAT_DIR"
      if git clone --depth 1 "$pat_url" "$WEB_PAT_DIR" >>"${LOG_FILE:-/dev/null}" 2>&1; then
        SUCCEEDED+=("pat:PayloadsAllTheThings-fallback")
      else
        log_warn "Fallback clone failed for $WEB_PAT_DIR"
        FAILED+=("pat:PayloadsAllTheThings-fallback")
      fi
    fi
  fi
}

print_manual() {
  if [ "$SELECTION_ACTIVE" = true ]; then
    log_info "Groups: $ACTIVE_GROUPS"
    echo "Manual installs (cannot be automated reliably):"
    local manuals_lc
    manuals_lc="$(tr '[:upper:]' '[:lower:]' <<<"$SELECT_MANUALS")"
    if grep -qw "pwndbg" <<<"$manuals_lc"; then
      echo "  pwndbg     — Linux: https://github.com/pwndbg/pwndbg"
      echo "               macOS: brew install pwndbg/tap/pwndbg-gdb"
    fi
    if grep -qw "rsactftool" <<<"$manuals_lc"; then
      echo "  RsaCtfTool — git clone https://github.com/RsaCtfTool/RsaCtfTool"
    fi
    if grep -qw "sagemath" <<<"$manuals_lc"; then
      echo "  SageMath   — Linux: apt install sagemath (optional — only for legacy Sage fallback snippets)"
      echo "               macOS: brew install --cask sage (optional)"
    fi
    if grep -qw "crypto-attacks" <<<"$manuals_lc"; then
      echo "  crypto-attacks (Coppersmith) — git clone https://github.com/jvdsn/crypto-attacks ~/.ctf-tools/crypto-attacks"
      echo "               && pip install -r ~/.ctf-tools/crypto-attacks/requirements.txt"
      echo "               Alternative (flaky): pip install coppersmith  # no reliable PyPI package as of 2026-09"
      echo "               Pure-Python Coppersmith lattice via fpylll + sympy works without Sage"
    fi
    if grep -qw "steghide" <<<"$manuals_lc"; then
      echo "  steghide   — Linux: apt install steghide"
      echo "               Homebrew not available"
    fi
    if grep -qw "pycdc" <<<"$manuals_lc"; then
      echo "  pycdc      — git clone https://github.com/zrax/pycdc && cmake . && make"
      echo "               (Python 3.9+ bytecode decompiler; uncompyle6 only supports <=3.8)"
    fi
    if grep -qw "dnspy" <<<"$manuals_lc"; then
      echo "  dnSpy      — https://github.com/dnSpy/dnSpy (Windows/.NET only)"
    fi
    if grep -qw "pat" <<<"$manuals_lc" || grep -qw "ysoserial" <<<"$manuals_lc"; then
      echo "  PayloadsAllTheThings (PAT) — git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ~/.ctf-tools/PayloadsAllTheThings"
      echo "               && ln -sfn ~/.ctf-tools/PayloadsAllTheThings ctf-web/payloads/PayloadsAllTheThings"
      echo "               or: bash scripts/install_ctf_tools.sh pat  # installs + links (MIT licensed upstream)"
      echo "               Offline fallback: manual clone to ctf-web/payloads/PayloadsAllTheThings if symlink fails (Windows/read-only)"
    fi
    return 0
  fi
  cat <<'EOF'
Manual installs (cannot be automated reliably):
  pwndbg     — Linux: https://github.com/pwndbg/pwndbg
               macOS: brew install pwndbg/tap/pwndbg-gdb
  RsaCtfTool — git clone https://github.com/RsaCtfTool/RsaCtfTool
  SageMath   — Linux: apt install sagemath (optional — only for legacy Sage fallback snippets)
               macOS: brew install --cask sage (optional)
  crypto-attacks (Coppersmith) — git clone https://github.com/jvdsn/crypto-attacks ~/.ctf-tools/crypto-attacks
               && pip install -r ~/.ctf-tools/crypto-attacks/requirements.txt
               Alternative (flaky): pip install coppersmith  # no reliable PyPI package as of 2026-09
               Pure-Python Coppersmith lattice via fpylll + sympy works without Sage
  steghide   — Linux: apt install steghide
               Homebrew not available
  pycdc      — git clone https://github.com/zrax/pycdc && cmake . && make
               (Python 3.9+ bytecode decompiler; uncompyle6 only supports <=3.8)
  dnSpy      — https://github.com/dnSpy/dnSpy (Windows/.NET only)
  PayloadsAllTheThings (PAT) — git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ~/.ctf-tools/PayloadsAllTheThings
               && ln -sfn ~/.ctf-tools/PayloadsAllTheThings ctf-web/payloads/PayloadsAllTheThings
               or: bash scripts/install_ctf_tools.sh pat  # installs + links (MIT licensed upstream)
               Offline fallback: manual clone to ctf-web/payloads/PayloadsAllTheThings if symlink fails (Windows/read-only)
MCP servers (optional — agent-driven RE/web, configured in your MCP client):
  IDA Pro MCP    — https://github.com/mrexodia/ida-pro-mcp
                   pip install ida-pro-mcp && ida-pro-mcp --install
  Ghidra MCP     — https://github.com/bethington/ghidra-mcp
                   prebuilt release (extension jar + bridge wheel); headless
                   GhidraMCPHeadlessServer, no GUI needed
  JADX MCP       — https://github.com/zinja-coder/jadx-ai-mcp
                   JADX-GUI plugin + jadx-mcp-server (uvx jadx-mcp-server)
  WinDbg MCP     — https://github.com/svnscha/mcp-windbg
                   uv tool install mcp-server-windbg (needs Windows SDK
                   Debugging Tools: cdb.exe for user mode, kd.exe for kernel)
  Playwright MCP — https://github.com/microsoft/playwright-mcp
                   npx @playwright/mcp@latest
  Burp Suite MCP — https://github.com/PortSwigger/mcp-server
                   build burp-mcp-all.jar (./gradlew embedProxyJar), load in Burp,
                   then: claude mcp add --transport sse burp http://127.0.0.1:9876
EOF
}
# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

verify() {
  local missing=()
  local found=()

  # Activate ctf-tools venv if it exists (packages were installed there)
  if [ -d "$CTF_VENV/bin" ] && [ -z "${VIRTUAL_ENV:-}" ]; then
    # shellcheck disable=SC1091
    source "$CTF_VENV/bin/activate" 2>/dev/null && log_info "Using virtualenv: $CTF_VENV"
  fi

  local -a checks=(
    python3 gdb r2 objdump binwalk exiftool tshark fls ffmpeg
    testdisk john nmap whois hashcat strace ltrace convert curl jq
    apktool upx qemu-system-x86_64 qrencode ffuf gem go
  )

  log_info "Verifying tool availability"
  for cmd in "${checks[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      found+=("$cmd")
    else
      missing+=("$cmd")
    fi
  done

  # Python modules — use the same map from PIP_PACKAGES
  for entry in "${PIP_PACKAGES[@]}"; do
    local mod="${entry##*:}"
    local spec="${entry%%:*}"
    local name="${spec%%==*}"
    if python3 -c "import $mod" 2>/dev/null; then
      found+=("py:$name")
    else
      missing+=("py:$name")
    fi
  done

  # Coppersmith lattice helper — manual clone (no reliable PyPI package)
  local crypto_attacks_dir="${HOME}/.ctf-tools/crypto-attacks"
  if [ -d "$crypto_attacks_dir/.git" ] || [ -d "$crypto_attacks_dir" ] && [ -f "$crypto_attacks_dir/requirements.txt" ]; then
    found+=("crypto-attacks")
  else
    missing+=("crypto-attacks (git clone https://github.com/jvdsn/crypto-attacks ~/.ctf-tools/crypto-attacks)")
  fi
  # Also hint pure-Python alternative via pip coppersmith (flaky)
  if python3 -c "import coppersmith" 2>/dev/null; then
    found+=("py:coppersmith")
  else
    missing+=("py:coppersmith (optional — no reliable PyPI package, use crypto-attacks clone)")
  fi

  # PayloadsAllTheThings (PAT) — on-demand clone
  if [ -d "$PAT_DIR/.git" ]; then
    local pat_sha
    pat_sha=$(git -C "$PAT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    echo "PAT $pat_sha at $PAT_DIR"
    log_info "PAT $pat_sha at $PAT_DIR"
    found+=("PAT $pat_sha at $PAT_DIR")
    # Also check symlink / fallback
    if [ -L "$WEB_PAT_DIR" ] || [ -d "$WEB_PAT_DIR/.git" ] || [ -d "$WEB_PAT_DIR" ]; then
      found+=("PAT link $WEB_PAT_DIR")
    else
      missing+=("PAT link $WEB_PAT_DIR (run: bash scripts/install_ctf_tools.sh pat)")
    fi
  else
    echo "PAT missing (not cloned to $PAT_DIR)"
    log_info "PAT missing (not cloned to $PAT_DIR)"
    missing+=("PAT missing (clone with: bash scripts/install_ctf_tools.sh pat or git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git $PAT_DIR)")
  fi

  echo ""
  echo "Found: ${#found[@]} tools/modules"
  echo "Missing: ${#missing[@]} tools/modules"
  if [ ${#missing[@]} -gt 0 ]; then
    echo ""
    echo "Missing:"
    for m in "${missing[@]}"; do
      echo "  - $m"
    done
  fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
  echo ""
  echo "========================================"
  echo " Install Summary"
  echo "========================================"
  echo " Installed: ${#SUCCEEDED[@]}"
  echo " Skipped:   ${#SKIPPED[@]} (already present)"
  echo " Failed:    ${#FAILED[@]}"
  if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo " Failed packages:"
    for f in "${FAILED[@]}"; do
      echo "   - $f"
    done
  fi
  echo "========================================"
  if [ -n "${LOG_FILE:-}" ]; then
    echo " Full log: $LOG_FILE"
    echo "========================================"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Validate group/backend selection before doing anything else.
if ! validate_selection; then
  exit 2
fi

# --list-groups prints the group table and exits 0 (works with any MODE).
if [ "$LIST_GROUPS" = true ]; then
  print_groups
  exit 0
fi

# Backend-level skips: a direct MODE call for a skipped backend is a no-op
# that reports the skip (exit 0); inside `all`, skipped backends are omitted.
maybe_skip_backend() {
  if backend_skipped "$1"; then
    log_info "$1: skipped via --skip ($SKIP_BACKENDS)"
    return 0
  fi
  return 1
}

# Set up logging for install modes (not verify/manual/dry-run)
if [ "$DRY_RUN" = false ] && [ "$MODE" != "--verify" ] && [ "$MODE" != "manual" ]; then
  setup_logging
fi

case "$MODE" in
  python) maybe_skip_backend python || { install_python; print_summary; } ;;
  apt) maybe_skip_backend apt || { install_apt; print_summary; } ;;
  brew) maybe_skip_backend brew || { install_brew; print_summary; } ;;
  gems) maybe_skip_backend gems || { install_gems; print_summary; } ;;
  go) maybe_skip_backend go || { install_go; print_summary; } ;;
  pat) maybe_skip_backend pat || { install_pat; print_summary; } ;;
  manual) maybe_skip_backend manual || print_manual ;;
  --verify) verify ;;
  all)
    maybe_skip_backend python || install_python
    if backend_skipped apt && backend_skipped brew; then
      log_info "OS packages: skipped via --skip ($SKIP_BACKENDS)"
    elif command -v apt-get >/dev/null 2>&1; then
      maybe_skip_backend apt || install_apt
    elif command -v brew >/dev/null 2>&1; then
      maybe_skip_backend brew || install_brew
    else
      log_warn "Skip OS package install: neither apt nor brew was found."
    fi
    maybe_skip_backend gems || install_gems
    maybe_skip_backend go || install_go
    maybe_skip_backend pat || install_pat
    maybe_skip_backend manual || print_manual
    print_summary
    ;;
  *)
    log_error "Unknown mode: $MODE"
    echo "Usage: $0 [--dry-run] [--force] [--only LIST] [--skip LIST] [--list-groups] {python|apt|brew|gems|go|pat|manual|all|--verify}" >&2
    echo "Tool groups: $VALID_GROUPS; skippable backends: $VALID_BACKENDS (flags before MODE)" >&2
    exit 2
    ;;
esac

# Exit with failure if any packages failed to install
if [ ${#FAILED[@]} -gt 0 ]; then
  exit 1
fi
