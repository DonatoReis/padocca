#!/bin/bash

# Padocca Installation Script
# Universal installer for Linux, macOS, and Windows (WSL)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║      🥖 PADOCCA INSTALLER v2.0 🥖                    ║"
    echo "║        Elite Pentesting Framework                     ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# OS Detection
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS="windows"
    else
        OS="unknown"
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Prompt helpers ------------------------------------------------------------
prompt_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local answer

    if [ -t 0 ]; then
        read -p "$prompt" -n 1 -r
        echo
        answer="${REPLY:-$default}"
    else
        answer="$default"
        echo "${prompt}${default}"
    fi

    [[ "$answer" =~ ^[Yy]$ ]]
}

prompt_select() {
    local prompt="$1"
    local default="${2:-1}"
    local choice

    if [ -t 0 ]; then
        read -p "$prompt" -n 1 -r
        echo
        choice="${REPLY:-$default}"
    else
        choice="$default"
        echo "${prompt}${default}"
    fi

    echo "$choice"
}

# Install Go
install_go() {
    echo -e "${YELLOW}[*] Installing Go...${NC}"
    
    if command_exists go; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        echo -e "${GREEN}[✓] Go is already installed (version $GO_VERSION)${NC}"
        return 0
    fi
    
    GO_VERSION="1.25.0"
    
    if [[ "$OS" == "linux" ]]; then
        ARCH=$(uname -m)
        if [[ "$ARCH" == "x86_64" ]]; then
            GO_ARCH="amd64"
        elif [[ "$ARCH" == "aarch64" ]]; then
            GO_ARCH="arm64"
        else
            GO_ARCH="386"
        fi
        
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        rm "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
        
    elif [[ "$OS" == "macos" ]]; then
        if command_exists brew; then
            brew install go
        else
            echo -e "${RED}[!] Homebrew not found. Please install Homebrew first.${NC}"
            echo "Visit: https://brew.sh"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}[✓] Go installed successfully${NC}"
}

# Install Rust
install_rust() {
    echo -e "${YELLOW}[*] Installing Rust...${NC}"
    
    if command_exists rustc; then
        RUST_VERSION=$(rustc --version | awk '{print $2}')
        echo -e "${GREEN}[✓] Rust is already installed (version $RUST_VERSION)${NC}"
        return 0
    fi
    
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    
    # Update to latest stable (1.85.0)
    rustup update stable
    rustup default stable
    
    echo -e "${GREEN}[✓] Rust installed successfully${NC}"
}

# Install Python dependencies
install_python_deps() {
    echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
    
    if ! command_exists python3; then
        if [[ "$OS" == "linux" ]]; then
            sudo apt-get update && sudo apt-get install -y python3 python3-pip
        elif [[ "$OS" == "macos" ]]; then
            brew install python3
        fi
    fi
    
    # No additional Python packages needed for base installation
    echo -e "${GREEN}[✓] Python ready${NC}"
}

# Install system dependencies
install_system_deps() {
    echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
    
    if [[ "$OS" == "linux" ]]; then
        if [[ "$DISTRO" == "Ubuntu" ]] || [[ "$DISTRO" == "Debian" ]]; then
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                libssl-dev \
                libpcap-dev \
                git \
                wget \
                curl \
                dnsutils \
                net-tools
        elif [[ "$DISTRO" == "Fedora" ]] || [[ "$DISTRO" == "CentOS" ]] || [[ "$DISTRO" == "RedHat" ]]; then
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                openssl-devel \
                libpcap-devel \
                git \
                wget \
                curl \
                bind-utils \
                net-tools
        elif [[ "$DISTRO" == "Arch" ]] || [[ "$DISTRO" == "Manjaro" ]]; then
            sudo pacman -Sy --noconfirm \
                base-devel \
                openssl \
                libpcap \
                git \
                wget \
                curl \
                bind-tools \
                net-tools
        fi
    elif [[ "$OS" == "macos" ]]; then
        # Install Xcode Command Line Tools if not present
        xcode-select --install 2>/dev/null || true
        
        if ! command_exists brew; then
            echo -e "${RED}[!] Homebrew not found. Installing...${NC}"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        brew install libpcap openssl@3 bind
    fi
    
    echo -e "${GREEN}[✓] System dependencies installed${NC}"
}

# Build Padocca
build_padocca() {
    echo -e "${YELLOW}[*] Building Padocca...${NC}"
    
    # Create bin directory
    mkdir -p bin
    
    # Build Go tools
    echo -e "${CYAN}[*] Building Go tools...${NC}"
    cd tools-go

    go mod tidy >/dev/null 2>&1 || echo -e "${YELLOW}  Warning: go mod tidy encountered issues${NC}"

    local go_tools=(bruteforce crawler dirfuzz dnsenum proxychain emailsec pipeline subdiscovery wayback xss_sqli_scanner)

    for tool in "${go_tools[@]}"; do
        echo -e "  Building $tool..."
        go build -o ../bin/$tool ./cmd/$tool/ 2>/dev/null || {
            echo -e "${YELLOW}  Warning: Failed to build $tool${NC}"
        }
    done
    cd ..
    
    # Build Rust core
    echo -e "${CYAN}[*] Building Rust core...${NC}"
    cd core-rust
    cargo build --release
    cp target/release/padocca-core ../bin/
    cd ..
    
    # Make padocca.sh executable
    chmod +x padocca.sh
    
    echo -e "${GREEN}[✓] Build complete${NC}"
}

# Create desktop launcher (optional)
create_launcher() {
    if [[ "$OS" == "linux" ]]; then
        cat > ~/.local/share/applications/padocca.desktop <<EOF
[Desktop Entry]
Name=Padocca
Comment=Elite Pentesting Framework
Exec=$PWD/padocca
Icon=$PWD/assets/icon.png
Terminal=true
Type=Application
Categories=Security;Network;
EOF
        echo -e "${GREEN}[✓] Desktop launcher created${NC}"
    fi
}

# Add to PATH
add_to_path() {
    echo -e "${YELLOW}[*] Configurando Padocca no sistema...${NC}"
    
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    PADOCCA_PATH="export PATH=\$PATH:$SCRIPT_DIR/bin"
    PADOCCA_ALIAS="alias padocca='$SCRIPT_DIR/padocca.sh'"

    local method="$1"

    echo -e "${CYAN}[?] Escolha o método de instalação:${NC}"
    echo "  1) Link simbólico em /usr/local/bin (requer sudo)"
    echo "  2) Alias no shell (não requer sudo)"

    if [[ -z "$method" ]]; then
        method=$(prompt_select "Escolha [1-2]: " "1")
    fi

    if [[ "$method" == "1" ]]; then
        echo -e "${YELLOW}[*] Instalando wrapper em /usr/local/bin...${NC}"
        local wrapper_path="/usr/local/bin/padocca"
        if sudo tee "$wrapper_path" >/dev/null <<EOF
#!/bin/sh
cd "$SCRIPT_DIR" || exit 1
exec "$SCRIPT_DIR/padocca.sh" "\$@"
EOF
        then
            sudo chmod +x "$wrapper_path"
            echo -e "${GREEN}[✓] Wrapper criado em /usr/local/bin/padocca${NC}"
            echo -e "${GREEN}    Você pode usar 'padocca' de qualquer lugar!${NC}"
        else
            echo -e "${RED}[!] Falha ao criar link simbólico${NC}"
            echo -e "${YELLOW}    Configurando alias como fallback...${NC}"
            method="2"
        fi
    fi

    if [[ "$method" == "2" ]]; then
        # Adicionar alias ao shell
        echo -e "${YELLOW}[*] Adicionando alias ao shell...${NC}"
        
        # Detectar shell ativo
        CURRENT_SHELL=$(basename "$SHELL")
        
        if [[ "$OS" == "linux" ]]; then
            # Adicionar ao .bashrc
            if [[ -f ~/.bashrc ]]; then
                if ! grep -q "alias padocca=" ~/.bashrc; then
                    echo "" >> ~/.bashrc
                    echo "# Padocca Security Framework" >> ~/.bashrc
                    echo "$PADOCCA_PATH" >> ~/.bashrc
                    echo "$PADOCCA_ALIAS" >> ~/.bashrc
                    echo -e "${GREEN}[✓] Alias adicionado ao ~/.bashrc${NC}"
                fi
            fi
            
            # Adicionar ao .zshrc se existir
            if [[ -f ~/.zshrc ]]; then
                if ! grep -q "alias padocca=" ~/.zshrc; then
                    echo "" >> ~/.zshrc
                    echo "# Padocca Security Framework" >> ~/.zshrc
                    echo "$PADOCCA_PATH" >> ~/.zshrc
                    echo "$PADOCCA_ALIAS" >> ~/.zshrc
                    echo -e "${GREEN}[✓] Alias adicionado ao ~/.zshrc${NC}"
                fi
            fi
            
        elif [[ "$OS" == "macos" ]]; then
            # macOS usa principalmente zsh agora
            if [[ -f ~/.zshrc ]]; then
                if ! grep -q "alias padocca=" ~/.zshrc; then
                    echo "" >> ~/.zshrc
                    echo "# Padocca Security Framework" >> ~/.zshrc
                    echo "$PADOCCA_PATH" >> ~/.zshrc
                    echo "$PADOCCA_ALIAS" >> ~/.zshrc
                    echo -e "${GREEN}[✓] Alias adicionado ao ~/.zshrc${NC}"
                fi
            fi
            
            # Adicionar ao .bash_profile para compatibilidade
            if [[ -f ~/.bash_profile ]]; then
                if ! grep -q "alias padocca=" ~/.bash_profile; then
                    echo "" >> ~/.bash_profile
                    echo "# Padocca Security Framework" >> ~/.bash_profile
                    echo "$PADOCCA_PATH" >> ~/.bash_profile
                    echo "$PADOCCA_ALIAS" >> ~/.bash_profile
                    echo -e "${GREEN}[✓] Alias adicionado ao ~/.bash_profile${NC}"
                fi
            fi
        fi
        
        echo -e "${YELLOW}[!] Para usar o alias, execute:${NC}"
        if [[ "$CURRENT_SHELL" == "zsh" ]]; then
            echo -e "    ${CYAN}source ~/.zshrc${NC}"
        else
            echo -e "    ${CYAN}source ~/.bashrc${NC}"
        fi
    fi
}

# Verify installation
verify_installation() {
    echo -e "${YELLOW}[*] Verifying installation...${NC}"
    
    ERRORS=0
    
    # Check binaries
    local required_bins=(bruteforce crawler dirfuzz dnsenum proxychain emailsec pipeline subdiscovery techfinger wayback xss_sqli_scanner padocca-core)

    for binary in "${required_bins[@]}"; do
        if [[ -f "bin/$binary" ]]; then
            echo -e "${GREEN}  ✓ $binary${NC}"
        else
            echo -e "${RED}  ✗ $binary${NC}"
            ((ERRORS++))
        fi
    done
    
    # Check main script
    if [[ -f "padocca.sh" ]] && [[ -x "padocca.sh" ]]; then
        echo -e "${GREEN}  ✓ padocca.sh (main)${NC}"
    else
        echo -e "${RED}  ✗ padocca.sh (main)${NC}"
        ((ERRORS++))
    fi
    
    if [[ $ERRORS -eq 0 ]]; then
        echo -e "${GREEN}[✓] Installation successful!${NC}"
        return 0
    else
        echo -e "${RED}[!] Installation completed with $ERRORS errors${NC}"
        return 1
    fi
}

# Main installation
main() {
    print_banner
    
    echo -e "${CYAN}[*] Starting Padocca installation...${NC}"
    echo
    
    # Detect OS
    detect_os
    echo -e "${GREEN}[✓] Detected OS: $OS${NC}"
    
    # Check for Windows
    if [[ "$OS" == "windows" ]]; then
        echo -e "${YELLOW}[!] Windows detected. Please use WSL2 for installation.${NC}"
        echo "    Visit: https://docs.microsoft.com/en-us/windows/wsl/install"
        exit 1
    fi
    
    # Install dependencies
    install_system_deps
    install_go
    install_rust
    install_python_deps
    
    # Build Padocca
    build_padocca
    
    # Optional features
    if prompt_yes_no "Add Padocca to PATH? (y/n) " "y"; then
        local install_method=""
        if [ ! -t 0 ]; then
            install_method="1"
        fi
        add_to_path "$install_method"
    fi
    
    if [[ "$OS" == "linux" ]]; then
        if prompt_yes_no "Create desktop launcher? (y/n) " "n"; then
            create_launcher
        fi
    fi
    
    # Verify
    verify_installation
    
    echo
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Installation Complete!${NC}"
    echo
    echo -e "Para começar:"
    echo -e "  ${YELLOW}padocca --help${NC}                # Mostrar ajuda"
    echo -e "  ${YELLOW}padocca --scan domain.com${NC}     # Scan completo"
    echo -e "  ${YELLOW}padocca --quick domain.com${NC}    # Scan rápido"
    echo
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
}

# Run main
main
