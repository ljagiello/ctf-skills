#!/usr/bin/env bash
# Bootstrap common tooling for the solve-challenge skill.
#
# Usage examples:
#   bash scripts/install_ctf_tools.sh python
#   bash scripts/install_ctf_tools.sh apt
#   bash scripts/install_ctf_tools.sh brew
#   bash scripts/install_ctf_tools.sh gems
#   bash scripts/install_ctf_tools.sh go
#   bash scripts/install_ctf_tools.sh all

set -euo pipefail

MODE="${1:-all}"

install_python() {
  PIP_FLAGS=()
  # Detect PEP 668 externally-managed environments (Debian 12+, Ubuntu 23.04+)
  if python3 -c "import sysconfig; marker = sysconfig.get_path('stdlib') + '/EXTERNALLY-MANAGED'; open(marker)" 2>/dev/null; then
    if [ -z "${VIRTUAL_ENV:-}" ]; then
      echo "PEP 668 detected and no virtualenv active — installing with --user" >&2
      PIP_FLAGS+=(--user)
    fi
  fi

  python3 -m pip install "${PIP_FLAGS[@]}" \
    pwntools pycryptodome z3-solver sympy gmpy2 hashpumpy fpylll py_ecc \
    angr frida-tools qiling requests flask-unsign sqlmap \
    ropper ROPgadget volatility3 yara-python pefile capstone \
    oletools unicorn scapy Pillow numpy matplotlib shodan \
    uncompyle6 lief dnspython dnslib dissect.cobaltstrike
}

install_apt() {
  sudo apt install -y \
    gdb radare2 binutils binwalk foremost libimage-exiftool-perl \
    tshark sleuthkit ffmpeg steghide testdisk john pcapfix \
    nmap whois dnsutils hashcat strace ltrace imagemagick curl jq \
    apktool upx qemu-system-x86 sagemath qrencode
}

install_brew() {
  brew install \
    gdb radare2 binutils binwalk exiftool wireshark sleuthkit \
    ffmpeg testdisk john-jumbo nmap whois bind hashcat ghidra \
    imagemagick curl jq apktool upx qemu qrencode
}

install_gems() {
  gem install one_gadget seccomp-tools zsteg
}

install_go() {
  go install github.com/ffuf/ffuf/v2@latest
}

print_manual() {
  cat <<'EOF'
Manual installs:
- pwndbg: Linux -> https://github.com/pwndbg/pwndbg ; macOS -> brew install pwndbg/tap/pwndbg-gdb
- RsaCtfTool: git clone https://github.com/RsaCtfTool/RsaCtfTool
- SageMath: Linux -> apt install sagemath ; macOS -> brew install --cask sage
- steghide: Linux -> apt install steghide ; Homebrew not available
- dnSpy: https://github.com/dnSpy/dnSpy
EOF
}

case "$MODE" in
  python) install_python ;;
  apt) install_apt ;;
  brew) install_brew ;;
  gems) install_gems ;;
  go) install_go ;;
  manual) print_manual ;;
  all)
    install_python
    if command -v apt >/dev/null 2>&1; then
      install_apt
    elif command -v brew >/dev/null 2>&1; then
      install_brew
    else
      echo "Skip OS package install: neither apt nor brew was found." >&2
    fi
    install_gems
    install_go
    print_manual
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    echo "Expected one of: python, apt, brew, gems, go, manual, all" >&2
    exit 2
    ;;
esac
