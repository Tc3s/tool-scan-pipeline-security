#!/bin/bash

# ====================================================================
# 🛡️  Automated Vulnerability Management Pipeline - Setup Script
# Target OS: Ubuntu 24.04 / Debian-based
# ====================================================================

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}🚀 Starting Project Setup & Tool Installation...${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. Update System
echo -e "\n${GREEN}[1/7] Updating system packages...${NC}"
sudo apt update && sudo apt upgrade -y

# 2. Install Essential Tools via APT
echo -e "\n${GREEN}[2/7] Installing CLI tools via APT...${NC}"
sudo apt install -y python3 python3-pip python3-venv \
    nmap sqlmap nikto wpscan curl git \
    libxml2-dev libxslt-dev python3-dev

# 3. Setup Python Virtual Environment
echo -e "\n${GREEN}[3/7] Setting up Python Virtual Environment (venv)...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "   ✅ Created venv."
else
    echo -e "   ℹ️  venv already exists, skipping creation."
fi

echo -e "   Installing Python requirements..."
source venv/bin/activate
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo -e "   ✅ requirements.txt installed."
else
    echo -e "   ⚠️  requirements.txt NOT found, installing core packages manually..."
    pip install pandas openpyxl requests pyyaml xlsxwriter defusedxml python-dotenv
fi

# 4. Install Nuclei (Binary)
echo -e "\n${GREEN}[4/7] Installing Nuclei (Latest Binary)...${NC}"
if ! command -v nuclei &> /dev/null; then
    ARCH=$(uname -m)
    if [ "$ARCH" == "x86_64" ]; then ARCH="amd64"; elif [ "$ARCH" == "aarch64" ]; then ARCH="arm64"; fi
    
    DOWNLOAD_URL="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${ARCH}.zip"
    echo -e "   Downloading Nuclei Latest (linux_${ARCH})..."
    curl -L "$DOWNLOAD_URL" -o nuclei.zip
    unzip nuclei.zip
    sudo mv nuclei /usr/local/bin/
    rm nuclei.zip LICENSE.md README.md 2>/dev/null
    echo -e "   ✅ Nuclei installed."
else
    echo -e "   ℹ️  Nuclei is already installed."
fi

echo -e "   Updating Nuclei templates..."
nuclei -ut

# 5. Optional: Install SearchSploit (Exploit-DB from GitLab)
echo -e "\n${GREEN}[5/7] Installing SearchSploit (Latest from GitLab)...${NC}"
if ! command -v searchsploit &> /dev/null; then
    sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
    sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
    echo -e "   ✅ SearchSploit installed."
else
    echo -e "   ℹ️  SearchSploit is already installed."
fi
echo -e "   Updating SearchSploit database..."
searchsploit -u

# 6. Setup Directory Structure
echo -e "\n${GREEN}[6/7] Creating project directory structure...${NC}"
mkdir -p data/raw data/normalized data/output mapping scripts
chmod +x scripts/*.py 2>/dev/null
echo -e "   ✅ data/ scripts/ mapping/ directories ensured."

# 7. Final Configuration & Warm-up
echo -e "\n${GREEN}[7/7] Finalizing & Initializing tools...${NC}"
echo -e "   Updating WPScan database..."
wpscan --update

echo -e "   Updating Nmap NSE script database..."
sudo nmap --script-updatedb

echo -e "   Pre-pulling OWASP ZAP Docker image (Stable)..."
sudo docker pull ghcr.io/zaproxy/zaproxy:stable

echo -e "   ✅ All tools initialized successfully."

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}✨ SETUP COMPLETE! ✨${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "\nTo start the pipeline, run:"
echo -e "   ${YELLOW}source venv/bin/activate${NC}"
echo -e "   ${YELLOW}python3 scripts/run_pipeline.py${NC}"
echo -e "\nOptional tools like Metasploit can be installed with:"
echo -e "   ${CYAN}sudo apt install metasploit-framework${NC} (via Kali repo or official script)"
echo -e "${BLUE}====================================================${NC}\n"
