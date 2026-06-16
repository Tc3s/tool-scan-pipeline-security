#!/bin/bash

# ====================================================================
# 🛡️  Automated Vulnerability Management Pipeline - Setup Script
# Target OS: Ubuntu 24.04 / Debian-based
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
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}🚀 Starting Project Setup & Tool Installation...${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. Update System & Install Docker
echo -e "\n${GREEN}[1/8] Updating system packages and installing Docker...${NC}"
sudo apt update && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose-v2 python3 python3-pip python3-venv \
    nmap sqlmap nikto curl git unzip ruby-full \
    libxml2-dev libxslt1-dev python3-dev

# Ensure user is in docker group (optional but helpful)
if ! groups $USER | grep -q "\bdocker\b"; then
    echo -e "   ℹ️  Adding user to docker group (requires logout/login to take effect fully for manual docker runs)..."
    sudo usermod -aG docker $USER
fi

# 2. Install Essential Tools via APT & Ruby
echo -e "\n${GREEN}[2/8] Installing WPScan via RubyGems...${NC}"
if ! command -v wpscan &> /dev/null; then
    sudo gem install wpscan
    echo -e "   ✅ WPScan installed."
else
    echo -e "   ℹ️  WPScan is already installed."
fi

# 3. Setup Python Virtual Environment
echo -e "\n${GREEN}[3/8] Setting up Python Virtual Environment (venv)...${NC}"
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

# 4. Install Nuclei (Binary)
echo -e "\n${GREEN}[4/8] Installing Nuclei (Latest Binary)...${NC}"
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

if command -v nuclei &> /dev/null; then
    echo -e "   Updating Nuclei templates..."
    nuclei -ut
fi

# 5. Optional: Install SearchSploit (Exploit-DB from GitLab)
echo -e "\n${GREEN}[5/8] Installing SearchSploit (Latest from GitLab)...${NC}"
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

echo -e "   Updating SearchSploit database..."
# Fix for git dubious ownership inside script
git config --global --add safe.directory /opt/exploitdb
searchsploit -u

# 6. Install Metasploit Framework (Official Script)
echo -e "\n${GREEN}[6/8] Installing Metasploit Framework...${NC}"
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

# 7. Setup Directory Structure
echo -e "\n${GREEN}[7/8] Creating project directory structure...${NC}"
mkdir -p data/raw data/normalized data/output mapping scripts
chmod +x scripts/*.py 2>/dev/null
echo -e "   ✅ data/ scripts/ mapping/ directories ensured."

# 8. Final Configuration & Warm-up
echo -e "\n${GREEN}[8/8] Finalizing & Initializing tools...${NC}"

if command -v wpscan &> /dev/null; then
    echo -e "   Updating WPScan database..."
    # Ensure local user directory exists to prevent permission errors
    mkdir -p ~/.wpscan
    wpscan --update
fi

echo -e "   Updating Nmap NSE script database..."
sudo nmap --script-updatedb

echo -e "   Pre-pulling OWASP ZAP Docker image (Stable)..."
# Pull via sudo or user if in docker group
sudo docker pull ghcr.io/zaproxy/zaproxy:stable

echo -e "   Pre-pulling OpenVAS (Greenbone) Docker images from compose.yml..."
if [ -f "compose.yml" ]; then
    sudo docker compose -f compose.yml pull
    echo -e "   ✅ OpenVAS images downloaded."
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
echo -e "\nTo start OpenVAS (Greenbone) in the background, run:"
echo -e "   ${CYAN}sudo docker compose -f compose.yml up -d${NC}"
echo -e "${BLUE}====================================================${NC}\n"
