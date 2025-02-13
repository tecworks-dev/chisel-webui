#!/bin/bash

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    rm -f chisel.gz
    rm -f chisel
    rm -f nssm.zip
    rm -rf nssm-2.24
}
trap cleanup EXIT

# Error handling function
handle_error() {
    echo -e "${RED}Error: $1${NC}"
    exit 1
}

# Check for required dependencies
check_dependencies() {
    local deps=("curl" "gunzip")
    if [ "$OS" != "windows" ]; then
        deps+=("sudo")
    fi
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            handle_error "Required dependency '$dep' is not installed."
        fi
    done
}

echo -e "${GREEN}Chisel Server Installation Script${NC}"
echo "=============================="

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    apt install curl gunzip python3 python3-pip python3-venv -y
    apt install sudo -y
    python3 -m pip install --upgrade pip
    python3 -m venv venv
    source venv/bin/activate
    python3 -m pip install -r requirements.txt
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="darwin"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    OS="windows"
else
    handle_error "Unsupported operating system"
fi

# Check dependencies
check_dependencies

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64)
        ARCH="arm64"
        ;;
    armv7l)
        ARCH="arm"
        ;;
    *)
        handle_error "Unsupported architecture: $ARCH"
        ;;
esac

# Set installation directory
if [ "$OS" == "windows" ]; then
    INSTALL_DIR="C:\\Program Files\\Chisel"
    CHISEL_EXE="chisel.exe"
else
    INSTALL_DIR="/usr/local/bin"
    CHISEL_EXE="chisel"
fi

# Create installation directory if it doesn't exist
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Creating installation directory...${NC}"
    if [ "$OS" == "windows" ]; then
        mkdir -p "$INSTALL_DIR" || handle_error "Failed to create installation directory"
    else
        sudo mkdir -p "$INSTALL_DIR" || handle_error "Failed to create installation directory"
    fi
fi

# Download latest chisel release
echo -e "${YELLOW}Downloading Chisel...${NC}"
LATEST_VERSION=$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') || handle_error "Failed to get latest version"
DOWNLOAD_URL="https://github.com/jpillora/chisel/releases/download/${LATEST_VERSION}/chisel_${LATEST_VERSION}_${OS}_${ARCH}.gz"

if [ "$OS" == "windows" ]; then
    DOWNLOAD_URL="https://github.com/jpillora/chisel/releases/download/${LATEST_VERSION}/chisel_${LATEST_VERSION}_windows_${ARCH}.gz"
fi

# Download and extract
echo -e "${YELLOW}Downloading from: $DOWNLOAD_URL${NC}"
if ! curl -L "$DOWNLOAD_URL" -o chisel.gz; then
    handle_error "Failed to download Chisel"
fi

if ! gunzip chisel.gz; then
    handle_error "Failed to extract Chisel"
fi

# Make executable and move to installation directory
echo -e "${YELLOW}Installing Chisel...${NC}"
if [ "$OS" == "windows" ]; then
    mv chisel "$INSTALL_DIR\\$CHISEL_EXE" || handle_error "Failed to install Chisel"
else
    chmod +x chisel || handle_error "Failed to make Chisel executable"
    sudo mv chisel "$INSTALL_DIR/$CHISEL_EXE" || handle_error "Failed to install Chisel"
fi

# Verify environment variables
if [ -z "$SERVER_PORT" ]; then
    SERVER_PORT="8081"  # Default port if not specified
fi

if [ -z "$AUTH_FILE" ]; then
    AUTH_FILE="users.json"  # Default auth file if not specified
fi
WORKING_DIR=$(pwd)
# Create service file for Linux systems
if [ "$OS" == "linux" ]; then
    echo -e "${YELLOW}Creating systemd service...${NC}"
    if ! sudo tee /etc/systemd/system/chisel-server.service > /dev/null << EOL
[Unit]
Description=Chisel Server Service
After=network.target

[Service]
Type=simple
Environment=SERVER_PORT=${SERVER_PORT}
Environment=AUTH_FILE=${AUTH_FILE}
Environment=WORKING_DIR=${WORKING_DIR}
ExecStart=source ${WORKING_DIR}/venv/bin/activate && python3 ${WORKING_DIR}/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL
    then
        handle_error "Failed to create service file"
    fi

    # Enable and start the service
    sudo systemctl daemon-reload || handle_error "Failed to reload systemd"
    sudo systemctl enable chisel-server || handle_error "Failed to enable service"
    sudo systemctl start chisel-server || handle_error "Failed to start service"

    echo -e "${GREEN}Service installed and started!${NC}"

# Create service for Windows systems
elif [ "$OS" == "windows" ]; then
    echo -e "${YELLOW}Creating Windows service...${NC}"

    # Create batch script for the service
    if ! tee "$INSTALL_DIR\\run-chisel-server.bat" > /dev/null << EOL
@echo off
set SERVER_PORT=${SERVER_PORT}
set AUTH_FILE=${AUTH_FILE}
"$INSTALL_DIR\\chisel.exe" server --authfile %AUTH_FILE% --port %SERVER_PORT%
EOL
    then
        handle_error "Failed to create batch script"
    fi

    # Download and install NSSM if not present
    if [ ! -f "$INSTALL_DIR\\nssm.exe" ]; then
        echo -e "${YELLOW}Downloading NSSM...${NC}"
        if ! curl -L "https://nssm.cc/release/nssm-2.24.zip" -o nssm.zip; then
            handle_error "Failed to download NSSM"
        fi
        if ! unzip nssm.zip; then
            handle_error "Failed to extract NSSM"
        fi
        if ! mv nssm-2.24/win64/nssm.exe "$INSTALL_DIR\\nssm.exe"; then
            handle_error "Failed to install NSSM"
        fi
        rm -rf nssm.zip nssm-2.24
    fi

    # Install and configure the service
    "$INSTALL_DIR\\nssm.exe" install ChiselServer "$INSTALL_DIR\\run-chisel-server.bat" || handle_error "Failed to install service"
    "$INSTALL_DIR\\nssm.exe" set ChiselServer DisplayName "Chisel Server Service" || handle_error "Failed to set service display name"
    "$INSTALL_DIR\\nssm.exe" set ChiselServer Description "Chisel Server for secure tunneling" || handle_error "Failed to set service description"
    "$INSTALL_DIR\\nssm.exe" set ChiselServer Start SERVICE_AUTO_START || handle_error "Failed to set service auto-start"

    # Start the service
    net start ChiselServer || handle_error "Failed to start service"

    echo -e "${GREEN}Service installed and started!${NC}"
fi

# Verify installation
if [ "$OS" == "windows" ]; then
    if [ ! -f "$INSTALL_DIR\\$CHISEL_EXE" ]; then
        handle_error "Installation verification failed"
    fi
else
    if [ ! -f "$INSTALL_DIR/$CHISEL_EXE" ]; then
        handle_error "Installation verification failed"
    fi
fi

echo -e "${GREEN}Chisel server installation completed successfully!${NC}"
echo -e "${YELLOW}Service Status:${NC}"
if [ "$OS" == "linux" ]; then
    sudo systemctl status chisel-server
elif [ "$OS" == "windows" ]; then
    sc query ChiselServer
fi 