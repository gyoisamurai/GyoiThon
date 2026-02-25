#!/bin/bash

# Exit on error
set -e

echo "[*] Setting up GyoiThon for Termux..."

# Update packages
echo "[*] Updating packages..."
pkg update -y && pkg upgrade -y

# Install system dependencies
# python, build tools, libraries for lxml, pillow, cryptography
echo "[*] Installing system dependencies..."
pkg install -y python clang make libxml2 libxslt libjpeg-turbo libcrypt openssl pkg-config \
    freetype libpng libzmq

# Install pre-compiled heavy python libraries to save build time and errors
# Note: Package names might vary slightly in Termux, but these are common.
echo "[*] Installing heavy python libraries via pkg..."
pkg install -y python-numpy python-pandas || echo "[!] Could not install python-numpy or python-pandas via pkg. Will attempt via pip."

# Install python dependencies
echo "[*] Installing python dependencies via pip..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Setup complete! You can now run:"
echo "    python gyoithon.py --help"
echo "    streamlit run dashboard.py"
