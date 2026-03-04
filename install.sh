#!/usr/bin/env bash
# Ixoryn v1.0 Installer — 
# Supports: Kali Linux, Ubuntu, Debian, Fedora, Arch, macOS, Windows WSL

set -e
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; RESET='\033[0m'; BOLD='\033[1m'

echo -e "${CYAN}${BOLD}"
cat << 'ART'
  ██╗██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗
  ██║╚██╗██╔╝██╔═══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║
  ██║ ╚███╔╝ ██║   ██║██████╔╝ ╚████╔╝ ██╔██╗ ██║
  ██║ ██╔██╗ ██║   ██║██╔══██╗  ╚██╔╝  ██║╚██╗██║
  ██║██╔╝ ██╗╚██████╔╝██║  ██║   ██║   ██║ ╚████║
  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝
ART
echo -e "${RESET}${BOLD}  Ixoryn v1.0 — ${RESET}"
echo -e "  Cross-Platform Security & Intelligence Platform\n"

OS=$(uname -s 2>/dev/null || echo "Windows")
DISTRO=""
if [ -f /etc/os-release ]; then
    DISTRO=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
fi
echo -e "${CYAN}[*] Platform: $OS ${DISTRO:+($DISTRO)}${RESET}"

# Python check
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] Python 3 not found.${RESET}"
    if [ "$OS" = "Darwin" ]; then
        echo "    brew install python3"
    else
        echo "    sudo apt install python3 python3-pip"
    fi
    exit 1
fi
PY=$(python3 --version)
echo -e "${GREEN}[✓] $PY${RESET}"

# Install pip packages
echo -e "\n${CYAN}[*] Installing Python packages...${RESET}"
PKGS="cryptography argon2-cffi PyNaCl bcrypt Pillow numpy scipy opencv-python stegano requests dnspython python-whois tld beautifulsoup4 sslyze hashid passlib zxcvbn scikit-learn weasyprint pdfkit colorama rich prompt_toolkit tabulate tqdm pyfiglet chardet python-magic filelock pytest"

for pkg in $PKGS; do
    echo -ne "  ${pkg}... "
    if pip3 install "$pkg" --break-system-packages -q 2>/dev/null || pip3 install "$pkg" -q 2>/dev/null || pip install "$pkg" -q 2>/dev/null; then
        echo -e "${GREEN}OK${RESET}"
    else
        echo -e "${YELLOW}FAILED${RESET}"
    fi
done

# pydub optional
echo -ne "  pydub (optional)... "
if pip3 install pydub --break-system-packages -q 2>/dev/null || pip3 install pydub -q 2>/dev/null; then
    echo -e "${GREEN}OK${RESET}"
else
    echo -e "${YELLOW}SKIPPED${RESET}"
fi

# System tools
echo -e "\n${CYAN}[*] Checking system tools...${RESET}"

# hashcat
if command -v hashcat &>/dev/null; then
    echo -e "  ${GREEN}[✓] hashcat${RESET}"
else
    echo -e "  ${YELLOW}[!] hashcat not found (needed for hash cracking)${RESET}"
    if [ "$DISTRO" = "kali" ] || [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        echo -e "      Install: ${CYAN}sudo apt install hashcat${RESET}"
    elif [ "$OS" = "Darwin" ]; then
        echo -e "      Install: ${CYAN}brew install hashcat${RESET}"
    else
        echo -e "      Download: ${CYAN}https://hashcat.net/hashcat/${RESET}"
    fi
fi

# ffmpeg
if command -v ffmpeg &>/dev/null; then
    echo -e "  ${GREEN}[✓] ffmpeg${RESET}"
else
    echo -e "  ${YELLOW}[!] ffmpeg not found (optional, for audio files)${RESET}"
    if [ "$OS" = "Darwin" ]; then
        echo -e "      Install: ${CYAN}brew install ffmpeg${RESET}"
    else
        echo -e "      Install: ${CYAN}sudo apt install ffmpeg${RESET}"
    fi
fi

# wkhtmltopdf
if command -v wkhtmltopdf &>/dev/null; then
    echo -e "  ${GREEN}[✓] wkhtmltopdf${RESET}"
else
    echo -e "  ${YELLOW}[!] wkhtmltopdf not found (optional, for PDF reports)${RESET}"
fi

# Wordlist check (Kali)
if [ -f "/usr/share/wordlists/rockyou.txt" ]; then
    echo -e "  ${GREEN}[✓] rockyou.txt found${RESET}"
elif [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
    echo -e "  ${CYAN}[*] Decompressing rockyou.txt.gz...${RESET}"
    sudo gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
    echo -e "  ${GREEN}[✓] rockyou.txt ready${RESET}"
else
    echo -e "  ${YELLOW}[!] rockyou.txt not found${RESET}"
    if [ "$DISTRO" = "kali" ] || [ "$DISTRO" = "ubuntu" ]; then
        echo -e "      Install: ${CYAN}sudo apt install wordlists${RESET}"
    fi
fi

echo -e "\n${BOLD}${GREEN}  ════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  Ixoryn v1.0 is ready!${RESET}"
echo -e "${BOLD}${GREEN}  ════════════════════════════════════════════════${RESET}"
echo -e "\n  Launch: ${CYAN}python3 ixoryn.py${RESET}\n"
