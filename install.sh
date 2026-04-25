#!/usr/bin/env bash
# ReconX Tool Installer — v2.0
# Run with: bash install.sh
# Tested on: Kali Linux 2024+, Ubuntu 22.04+, Parrot OS, Debian 12
#
# Fixes applied from real-world testing:
#   - Go tools symlinked to /usr/local/bin (survives shell changes, works immediately)
#   - apt versions of httpx/amass removed before installing correct versions
#   - amass installed from prebuilt release binary (avoids libpostal crash)
#   - paramspider installed from GitHub source (not on PyPI)
#   - gauplus installed via go install (not pip)
#   - waymore installed via pip3 --break-system-packages
#   - jsecret installed via pip3 --break-system-packages
#   - Python packages restored after any accidental downgrades

# NO set -e — handle each failure individually
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; }
step()    { echo -e "\n${BOLD}${CYAN}━━ $1${NC}"; }

echo ""
echo -e "${GREEN}${BOLD}  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗██╗  ██╗${NC}"
echo -e "${GREEN}${BOLD}  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║╚██╗██╔╝${NC}"
echo -e "${GREEN}${BOLD}  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║ ╚███╔╝ ${NC}"
echo -e "${GREEN}${BOLD}  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║ ██╔██╗ ${NC}"
echo -e "${GREEN}${BOLD}  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║██╔╝╚██╗${NC}"
echo -e "${GREEN}${BOLD}  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝╚═╝  ╚═╝${NC}"
echo -e "  ${CYAN}ReconX Tool Installer v2.0${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 0 — Detect Go binary
# ─────────────────────────────────────────────────────────────────────────────
step "Resolving Go environment"

GO_BIN=""
for candidate in \
    "$(which go 2>/dev/null)" \
    /usr/local/go/bin/go \
    /usr/bin/go \
    "$HOME/go/bin/go" \
    /snap/bin/go; do
    if [ -x "$candidate" ]; then
        GO_BIN="$candidate"
        break
    fi
done

if [ -z "$GO_BIN" ]; then
    error "Go not found — installing Go 1.22..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        *)       GO_ARCH="amd64" ;;
    esac
    wget -q "https://go.dev/dl/go1.22.4.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    GO_BIN=/usr/local/go/bin/go
    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/golang.sh > /dev/null
    export PATH="$PATH:/usr/local/go/bin"
    success "Go installed"
fi

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:$(dirname $GO_BIN)"

success "Go: $($GO_BIN version 2>/dev/null | awk '{print $3}')"
success "GOPATH: $GOPATH"
info "All tools will be symlinked to /usr/local/bin"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Write permanent PATH to shell profiles
# ─────────────────────────────────────────────────────────────────────────────
step "Writing permanent PATH configuration"

PATH_LINE='export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"'
for profile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$profile" ] && ! grep -q "go/bin" "$profile" 2>/dev/null; then
        echo "" >> "$profile"
        echo "# ReconX — Go tools PATH" >> "$profile"
        echo "$PATH_LINE" >> "$profile"
        success "Updated $profile"
    fi
done
echo "export PATH=\"\$PATH:\$HOME/go/bin:/usr/local/go/bin\"" \
    | sudo tee /etc/profile.d/go-tools.sh > /dev/null
sudo chmod +x /etc/profile.d/go-tools.sh
success "Wrote /etc/profile.d/go-tools.sh (system-wide)"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Remove conflicting apt versions BEFORE installing correct ones
# FIX: apt httpx is old/incompatible, apt amass has libpostal crash
# ─────────────────────────────────────────────────────────────────────────────
step "Removing conflicting apt versions (httpx, amass)"

# Remove apt httpx if present — it's a different tool / incompatible flags
if dpkg -l httpx 2>/dev/null | grep -q "^ii"; then
    info "Removing apt httpx (incompatible with reconx — will install ProjectDiscovery version)..."
    sudo apt-get remove -y httpx 2>/dev/null || true
    sudo rm -f /usr/bin/httpx
    success "Removed apt httpx"
fi

# Remove apt amass if present — it has libpostal dependency that crashes
if dpkg -l amass 2>/dev/null | grep -q "^ii"; then
    info "Removing apt amass (has libpostal crash bug — will install prebuilt binary)..."
    sudo apt-get remove -y amass 2>/dev/null || true
    sudo rm -f /usr/bin/amass
    success "Removed apt amass"
fi

# Also remove any broken version already in /usr/local/bin
# Detect libpostal crash signature
if [ -x /usr/local/bin/amass ]; then
    if /usr/local/bin/amass -version 2>&1 | grep -qi "libpostal"; then
        warn "Found broken amass with libpostal at /usr/local/bin/amass — replacing..."
        sudo rm -f /usr/local/bin/amass
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — System dependencies
# ─────────────────────────────────────────────────────────────────────────────
step "Installing system dependencies"

sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y -qq \
    git curl wget jq unzip pipx \
    build-essential libpcap-dev \
    python3 python3-pip \
    nmap dnsutils whois \
    2>/dev/null || true
success "System deps OK"

# ─────────────────────────────────────────────────────────────────────────────
# Core helper — install Go tool and symlink to /usr/local/bin
# The symlink is the key: /usr/local/bin is in PATH in every shell on every distro
# ─────────────────────────────────────────────────────────────────────────────
install_go_tool() {
    local pkg="$1"
    local name="$2"
    local dest="/usr/local/bin/$name"

    # Already working at /usr/local/bin — done
    if [ -x "$dest" ] && [ ! -L "$dest" -o -x "$(readlink -f $dest 2>/dev/null)" ]; then
        success "$name already installed"
        return 0
    fi

    # Already in GOPATH — just needs symlinking
    if [ -x "$GOPATH/bin/$name" ]; then
        sudo ln -sf "$GOPATH/bin/$name" "$dest"
        success "$name symlinked → /usr/local/bin/$name"
        return 0
    fi

    info "Installing $name..."
    if $GO_BIN install "${pkg}@latest" 2>/dev/null; then
        if [ -x "$GOPATH/bin/$name" ]; then
            sudo ln -sf "$GOPATH/bin/$name" "$dest"
            success "$name installed → /usr/local/bin/$name"
        else
            # Binary may have different name in GOPATH
            local found
            found=$(find "$GOPATH/bin" -name "$name" -type f 2>/dev/null | head -1)
            if [ -n "$found" ]; then
                sudo ln -sf "$found" "$dest"
                success "$name found at $found → symlinked"
            else
                warn "$name: installed but binary not found — check: ls $GOPATH/bin/"
            fi
        fi
    else
        warn "$name: go install failed — manual: $GO_BIN install ${pkg}@latest && sudo ln -sf ~/go/bin/$name /usr/local/bin/$name"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Go-based tools
# ─────────────────────────────────────────────────────────────────────────────
step "Installing Go-based recon tools"

# ProjectDiscovery suite
install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"       "subfinder"
install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx"                  "httpx"
install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"             "nuclei"
install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu"               "naabu"
install_go_tool "github.com/projectdiscovery/dnsx/cmd/dnsx"                    "dnsx"
install_go_tool "github.com/projectdiscovery/katana/cmd/katana"                "katana"
install_go_tool "github.com/projectdiscovery/chaos-client/cmd/chaos"           "chaos"
install_go_tool "github.com/projectdiscovery/asnmap/cmd/asnmap"                "asnmap"
install_go_tool "github.com/projectdiscovery/interactsh/cmd/interactsh-client" "interactsh-client"

# URL discovery
install_go_tool "github.com/tomnomnom/waybackurls"   "waybackurls"
install_go_tool "github.com/lc/gau/v2/cmd/gau"       "gau"
install_go_tool "github.com/bp0lr/gauplus"            "gauplus"
install_go_tool "github.com/hakluke/hakrawler"        "hakrawler"
install_go_tool "github.com/jaeles-project/gospider"  "gospider"

# Subdomain tools
install_go_tool "github.com/tomnomnom/assetfinder"    "assetfinder"
install_go_tool "github.com/d3mondev/puredns/v2"      "puredns"
install_go_tool "github.com/hakluke/hakrevdns"        "hakrevdns"

# JS analysis
install_go_tool "github.com/lc/subjs"                 "subjs"
install_go_tool "github.com/003random/getJS"           "getJS"
install_go_tool "github.com/MrEmpy/mantra"             "mantra"

# github-subdomains
install_go_tool "github.com/gwen001/github-subdomains" "github-subdomains"

# Utility
install_go_tool "github.com/tomnomnom/anew"            "anew"
install_go_tool "github.com/tomnomnom/qsreplace"       "qsreplace"
install_go_tool "github.com/ffuf/ffuf/v2"              "ffuf"
install_go_tool "github.com/s0md3v/smap/cmd/smap"      "smap"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Symlink sweep: catch anything already in GOPATH but not /usr/local/bin
# ─────────────────────────────────────────────────────────────────────────────
step "Symlinking all GOPATH tools to /usr/local/bin"

SYMLINKED=0
for bin in "$GOPATH/bin"/*; do
    [ -x "$bin" ] || continue
    name=$(basename "$bin")
    dest="/usr/local/bin/$name"
    if [ ! -e "$dest" ]; then
        sudo ln -sf "$bin" "$dest" && SYMLINKED=$((SYMLINKED + 1))
    fi
done
success "Symlinked $SYMLINKED new tools"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — findomain (prebuilt binary, not on Go module proxy)
# ─────────────────────────────────────────────────────────────────────────────
step "Installing findomain"

if command -v findomain &>/dev/null; then
    success "findomain already installed ($(findomain --version 2>/dev/null | head -1))"
else
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  FD_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux" ;;
        aarch64) FD_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-aarch64-unknown-linux-gnu" ;;
        *)       FD_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux" ;;
    esac
    info "Downloading findomain ($ARCH)..."
    wget -q "$FD_URL" -O /tmp/findomain && \
        sudo mv /tmp/findomain /usr/local/bin/findomain && \
        sudo chmod +x /usr/local/bin/findomain && \
        success "findomain installed" || \
        warn "findomain download failed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — amass prebuilt release binary
# FIX: NEVER use go install or apt for amass — both produce libpostal-linked
# binaries that crash with "Error loading transliteration module, dir=(null)"
# The official release zip contains a statically linked binary with no deps.
# ─────────────────────────────────────────────────────────────────────────────
step "Installing amass (prebuilt release binary — no libpostal)"

AMASS_OK=false
if command -v amass &>/dev/null; then
    # Test for the libpostal crash — if clean, keep it
    AMASS_TEST=$(amass -version 2>&1)
    if echo "$AMASS_TEST" | grep -qi "libpostal\|transliteration\|No such file"; then
        warn "Existing amass has libpostal crash bug — replacing..."
        sudo rm -f "$(which amass)"
    else
        success "amass already installed ($AMASS_TEST)"
        AMASS_OK=true
    fi
fi

if [ "$AMASS_OK" = false ]; then
    AMASS_VER="v4.2.0"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  AMASS_ARCH="amd64" ;;
        aarch64) AMASS_ARCH="arm64" ;;
        *)       AMASS_ARCH="amd64" ;;
    esac
    # NOTE: amass release zip folder is "amass_Linux_amd64" (capital L) — not linux
    AMASS_URL="https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_Linux_${AMASS_ARCH}.zip"
    info "Downloading amass ${AMASS_VER} (${AMASS_ARCH})..."
    wget -q "$AMASS_URL" -O /tmp/amass.zip 2>/dev/null
    if [ -f /tmp/amass.zip ]; then
        unzip -q /tmp/amass.zip -d /tmp/amass_extract 2>/dev/null || true
        # Find the binary — folder name has capital Linux
        AMASS_BIN=$(find /tmp/amass_extract -name "amass" -type f 2>/dev/null | head -1)
        if [ -n "$AMASS_BIN" ]; then
            sudo cp "$AMASS_BIN" /usr/local/bin/amass
            sudo chmod +x /usr/local/bin/amass
            rm -rf /tmp/amass_extract /tmp/amass.zip
            # Verify no libpostal
            AMASS_VER_OUT=$(amass -version 2>&1)
            if echo "$AMASS_VER_OUT" | grep -qi "libpostal\|transliteration"; then
                error "amass still has libpostal issue after reinstall — check manually"
            else
                success "amass installed cleanly: $AMASS_VER_OUT"
            fi
        else
            warn "amass binary not found in zip — contents: $(ls /tmp/amass_extract/ 2>/dev/null)"
            rm -rf /tmp/amass_extract /tmp/amass.zip
        fi
    else
        warn "amass download failed — check internet connection"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — trufflehog (official install script)
# ─────────────────────────────────────────────────────────────────────────────
step "Installing trufflehog"

if command -v trufflehog &>/dev/null; then
    success "trufflehog already installed ($(trufflehog --version 2>/dev/null | head -1))"
else
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sudo sh -s -- -b /usr/local/bin 2>/dev/null && \
        success "trufflehog installed" || \
        warn "trufflehog install failed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 9 — Python tools
# FIX: Use --break-system-packages on Kali/Debian (externally-managed-environment)
#      paramspider is NOT on PyPI — must install from GitHub source
#      gauplus is NOT on PyPI — use go install (done above in Step 4)
#      waymore and jsecret ARE on PyPI
# ─────────────────────────────────────────────────────────────────────────────
step "Installing Python-based tools"

pip_install() {
    local pkg="$1"
    local name="${2:-$1}"
    if command -v "$name" &>/dev/null; then
        success "$name already installed"
        return 0
    fi
    info "Installing $pkg via pip3..."
    pip3 install "$pkg" --break-system-packages --quiet 2>/dev/null && \
        success "$pkg installed" || \
        warn "$pkg pip install failed — try: pip3 install $pkg --break-system-packages"
}

pip_install "waymore"
pip_install "jsecret"

# paramspider — must install from GitHub (not on PyPI)
step "Installing paramspider (from GitHub source)"
if command -v paramspider &>/dev/null; then
    success "paramspider already installed"
else
    info "Cloning and installing paramspider..."
    TMP_PS=$(mktemp -d)
    git clone -q https://github.com/devanshbatham/ParamSpider "$TMP_PS/ParamSpider" 2>/dev/null && \
        pip3 install "$TMP_PS/ParamSpider" --break-system-packages --quiet 2>/dev/null && \
        success "paramspider installed" || \
        warn "paramspider install failed"
    rm -rf "$TMP_PS"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 10 — Nuclei templates + DNS resolvers
# ─────────────────────────────────────────────────────────────────────────────
step "Updating nuclei templates"
if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent 2>/dev/null && \
        success "Nuclei templates updated" || \
        warn "Nuclei template update failed — run: nuclei -update-templates"
else
    warn "nuclei not found — skipping"
fi

step "Downloading DNS resolvers"
mkdir -p "$HOME/.config/reconx"
wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
    -O "$HOME/.config/reconx/resolvers.txt" && \
    success "Resolvers → $HOME/.config/reconx/resolvers.txt" || \
    warn "Resolver download failed"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 11 — Build and install reconx binary
# ─────────────────────────────────────────────────────────────────────────────
step "Building ReconX"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if $GO_BIN build -o /tmp/reconx_new ./cmd/reconx/ 2>&1; then
    sudo mv /tmp/reconx_new /usr/local/bin/reconx
    sudo chmod +x /usr/local/bin/reconx
    success "reconx built and installed → /usr/local/bin/reconx"
else
    error "reconx build failed"
    warn "Manual fix: cd $SCRIPT_DIR && go build -o reconx ./cmd/reconx/"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 12 — Final symlink sweep (catch anything missed above)
# ─────────────────────────────────────────────────────────────────────────────
step "Final symlink sweep"
for bin in "$GOPATH/bin"/*; do
    [ -x "$bin" ] || continue
    name=$(basename "$bin")
    dest="/usr/local/bin/$name"
    if [ ! -e "$dest" ]; then
        sudo ln -sf "$bin" "$dest"
    fi
done
success "All GOPATH tools symlinked to /usr/local/bin"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 13 — Verification report
# ─────────────────────────────────────────────────────────────────────────────
step "Verification"

ALL_TOOLS=(
    subfinder assetfinder amass findomain chaos puredns dnsx github-subdomains
    httpx curl naabu
    waybackurls waymore gau gauplus katana hakrawler gospider paramspider
    mantra jsecret subjs trufflehog
    nuclei
    reconx
)

INSTALLED=()
MISSING=()
for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        INSTALLED+=("$tool")
    else
        MISSING+=("$tool")
    fi
done

echo ""
echo -e "  ${GREEN}${BOLD}Installed (${#INSTALLED[@]}/${#ALL_TOOLS[@]}):${NC}"
for t in "${INSTALLED[@]}"; do
    printf "    ${GREEN}✓${NC} %-22s %s\n" "$t" "$(command -v $t)"
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${YELLOW}${BOLD}Missing (${#MISSING[@]}):${NC}"
    for t in "${MISSING[@]}"; do
        echo -e "    ${YELLOW}○${NC} $t"
    done
fi

echo ""
echo -e "${GREEN}${BOLD}  ════════════════════════════════════════════════════${NC}"
if [ ${#MISSING[@]} -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  All ${#ALL_TOOLS[@]}/${#ALL_TOOLS[@]} tools installed — ready to scan!${NC}"
else
    echo -e "${YELLOW}${BOLD}  ${#INSTALLED[@]}/${#ALL_TOOLS[@]} tools installed (${#MISSING[@]} missing above)${NC}"
fi
echo -e "${GREEN}${BOLD}  ════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Verify tools:${NC}  reconx -d test.com --skip-subs --skip-alive --skip-ports --skip-urls --skip-js --skip-vuln"
echo -e "  ${CYAN}Run a scan:${NC}    reconx -d target.com --scope scope.txt --header \"X-Bug-Bounty: True\""
echo ""
