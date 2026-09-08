#!/bin/bash

# ====================================================================
# 🛡️  Automated Vulnerability Management Pipeline - Setup Script
# Target OS: Ubuntu 22.04/24.04/26.04 or Ubuntu-compatible
# ====================================================================

# Prevent running the script directly as root
if [ "$EUID" -eq 0 ]; then
  echo -e "\033[0;31m❌ Please run this script as a normal user (NOT with sudo directly).\033[0m"
  echo -e "The script will ask for sudo password when necessary."
  exit 1
fi

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}🚀 Starting Project Setup & Tool Installation...${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. Update System & Install OS prerequisites
echo -e "\n${GREEN}[1/7] Updating system packages and installing OS prerequisites...${NC}"
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl python3 python3-pip python3-venv \
    nmap git unzip \
    libxml2-dev libxslt1-dev python3-dev \
    build-essential libcurl4-openssl-dev zlib1g-dev

# Install Docker Engine from Docker's official apt repository
echo -e "   Installing Docker Engine from Docker's official apt repository..."
CONFLICTING_DOCKER_PACKAGES=$(dpkg --get-selections docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc 2>/dev/null | cut -f1 || true)
if [ -n "$CONFLICTING_DOCKER_PACKAGES" ]; then
    echo -e "   Removing conflicting Docker packages: $CONFLICTING_DOCKER_PACKAGES"
    sudo apt remove -y $CONFLICTING_DOCKER_PACKAGES
fi

sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
if command -v systemctl &> /dev/null; then
    sudo systemctl start docker
fi

# Ensure user is in docker group
if ! getent group docker > /dev/null; then
    sudo groupadd docker
fi
if ! groups "$USER" | grep -q "\bdocker\b"; then
    echo -e "   ℹ️  Adding user to docker group. The script will run newgrp docker at the end."
    sudo usermod -aG docker "$USER"
fi

# 2. Setup Python Virtual Environment
echo -e "\n${GREEN}[2/7] Setting up Python Virtual Environment (venv)...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "   ✅ Created venv."
else
    echo -e "   ℹ️  venv already exists, skipping creation."
fi

echo -e "   Installing Python requirements..."
./venv/bin/pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt
    echo -e "   ✅ requirements.txt installed."
else
    echo -e "   ⚠️  requirements.txt NOT found, installing core packages manually..."
    ./venv/bin/pip install pandas openpyxl requests pyyaml xlsxwriter defusedxml python-dotenv lxml
fi

# 3. Install Nuclei (Binary)
echo -e "\n${GREEN}[3/7] Installing Nuclei (Latest Binary)...${NC}"
if ! command -v nuclei &> /dev/null; then
    ARCH=$(uname -m)
    if [ "$ARCH" == "x86_64" ]; then ARCH="amd64"; elif [ "$ARCH" == "aarch64" ]; then ARCH="arm64"; fi
    
    LATEST_TAG=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/v//')
    if [ -z "$LATEST_TAG" ]; then LATEST_TAG="3.2.9"; fi
    
    DOWNLOAD_URL="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${LATEST_TAG}_linux_${ARCH}.zip"
    echo -e "   Downloading Nuclei ${LATEST_TAG} (linux_${ARCH})..."
    curl -L "$DOWNLOAD_URL" -o nuclei.zip
    
    FILE_SIZE=$(stat -c%s nuclei.zip)
    if [ "$FILE_SIZE" -lt 1000 ]; then
        echo -e "   ${RED}❌ Download failed. Trying fallback URL...${NC}"
        DOWNLOAD_URL="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${ARCH}.zip"
        curl -L "$DOWNLOAD_URL" -o nuclei.zip
    fi

    unzip -o nuclei.zip
    if [ -f "nuclei" ]; then
        sudo mv nuclei /usr/local/bin/
        rm nuclei.zip LICENSE.md README.md 2>/dev/null
        echo -e "   ✅ Nuclei installed."
    else
        echo -e "   ${RED}❌ Nuclei binary NOT found after unzipping.${NC}"
    fi
else
    echo -e "   ℹ️  Nuclei is already installed."
fi

if [ -d "$HOME/nuclei-templates" ] || [ -d "/usr/share/nuclei-templates" ]; then
    echo -e "   ℹ️  Nuclei templates already present. (Run 'nuclei -ut' manually to refresh)"
elif command -v nuclei &> /dev/null; then
    echo -e "   Downloading Nuclei templates..."
    nuclei -ut
fi

# 4. Optional: Install SearchSploit (Exploit-DB from GitLab)
echo -e "\n${GREEN}[4/7] Installing SearchSploit (Latest from GitLab)...${NC}"
if ! command -v searchsploit &> /dev/null; then
    sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
    # Fix ownership so normal user can run searchsploit -u
    sudo chown -R $USER:$USER /opt/exploitdb
    sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
    echo -e "   ✅ SearchSploit installed."
else
    echo -e "   ℹ️  SearchSploit is already installed. Ensuring correct permissions..."
    sudo chown -R $USER:$USER /opt/exploitdb 2>/dev/null
fi

if [ -f "/opt/exploitdb/files_exploits.csv" ]; then
    echo -e "   ℹ️  SearchSploit database already present. (Run 'searchsploit -u' manually to refresh)"
else
    echo -e "   Updating SearchSploit database..."
    git config --global --add safe.directory /opt/exploitdb
    searchsploit -u
fi

# 5. Install Metasploit Framework (Official Script)
echo -e "\n${GREEN}[5/7] Installing Metasploit Framework...${NC}"
if ! command -v msfconsole &> /dev/null; then
    echo -e "   Downloading and running Metasploit installer..."
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
    chmod 755 msfinstall
    sudo ./msfinstall
    rm msfinstall
    echo -e "   ✅ Metasploit installed."
else
    echo -e "   ℹ️  Metasploit is already installed."
fi

# 6. Setup Directory Structure & Dynamic Run Layout
echo -e "\n${GREEN}[6/7] Creating project directory structure & dynamic run layout...${NC}"
mkdir -p runs data/raw data/normalized data/output data/reports/internal data/reports/customer_safe mapping scripts config
chmod +x scripts/*.py greenbone_report_formats/generate greenbone_report_formats/*.py 2>/dev/null || true
echo -e "   ✅ Project directories initialized: runs/ (dynamic outputs), data/ (fallback), scripts/, mapping/, config/"

# 7. Final Configuration & Warm-up
echo -e "\n${GREEN}[7/7] Finalizing & Initializing tools...${NC}"

# Detect whether docker can run without sudo
DOCKER_CMD="docker"
if ! docker info &>/dev/null; then
    DOCKER_CMD="sudo docker"
fi

if [ -f "/usr/share/nmap/scripts/script.db" ]; then
    echo -e "   ℹ️  Nmap script database already present."
else
    echo -e "   Updating Nmap NSE script database..."
    sudo nmap --script-updatedb
fi

ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
if $DOCKER_CMD image inspect "$ZAP_IMAGE" &>/dev/null; then
    echo -e "   ℹ️  OWASP ZAP Docker image already exists ($ZAP_IMAGE), skipping pull."
else
    echo -e "   Pre-pulling OWASP ZAP Docker image ($ZAP_IMAGE)..."
    $DOCKER_CMD pull "$ZAP_IMAGE"
fi

if [ -f "compose.yml" ]; then
    COMPOSE_IMAGES=$($DOCKER_CMD compose -f compose.yml config --images 2>/dev/null | sort -u)
    MISSING_COMPOSE=0
    for img in $COMPOSE_IMAGES; do
        if ! $DOCKER_CMD image inspect "$img" &>/dev/null; then
            MISSING_COMPOSE=1
            break
        fi
    done

    if [ "$MISSING_COMPOSE" -eq 0 ] && [ -n "$COMPOSE_IMAGES" ]; then
        echo -e "   ℹ️  OpenVAS Docker images already downloaded, skipping compose pull."
        echo -e "      (Run '$DOCKER_CMD compose -f compose.yml pull' manually whenever you wish to refresh feeds)"
    else
        echo -e "   Pre-pulling missing OpenVAS (Greenbone) Docker images from compose.yml..."
        $DOCKER_CMD compose -f compose.yml pull
        echo -e "   ✅ OpenVAS images downloaded."
    fi
else
    echo -e "   ⚠️  compose.yml NOT found, skipping OpenVAS pull."
fi

echo -e "   ✅ All tools initialized successfully."

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}✨ SETUP COMPLETE! ✨${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "\nTo start the pipeline, run:"
echo -e "   ${YELLOW}source venv/bin/activate${NC}"
echo -e "   ${YELLOW}python3 scripts/run_pipeline.py${NC}"
echo -e "\nArtifacts and output directories are dynamically created per run under:"
echo -e "   ${CYAN}runs/run_YYYYMMDD_HHMMSS/${NC} (or via ${CYAN}VA_RUN_DIR${NC} / ${CYAN}VA_RUN_ID${NC})"
echo -e "\nTo start OpenVAS (Greenbone) in the background, run:"
echo -e "   ${CYAN}sudo docker compose -f compose.yml up -d${NC}"
echo -e "${BLUE}====================================================${NC}\n"

# Reload group dynamically so the user doesn't have to logout
echo -e "🔄 Nạp lại quyền Docker cho Terminal hiện tại..."
exec newgrp docker
