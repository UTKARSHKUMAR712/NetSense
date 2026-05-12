#!/bin/bash

echo "[*] Compiling NetSense+ executable..."
bash build.sh
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed! Aborting packaging."
    exit 1
fi
echo ""

echo "[*] Creating NetSense+ Release Bundle..."

# Create release directory
mkdir -p release/proxy
mkdir -p release/recordings

# Copy the core executable
if [ -f "NetSense.exe" ]; then
    cp NetSense.exe release/
    echo "[+] Copied NetSense.exe"
else
    echo "[-] NetSense.exe not found! Run build.sh first."
    exit 1
fi

# Download and bundle standalone mitmproxy (Includes Python inside!)
echo "[*] Downloading standalone mitmproxy (Python bundled)..."
curl -L -o release/mitmproxy.zip "https://downloads.mitmproxy.org/9.0.1/mitmproxy-9.0.1-windows.zip"

if [ -f "release/mitmproxy.zip" ]; then
    echo "[+] Extracting mitmdump.exe using PowerShell..."
    powershell -Command "Expand-Archive -Force 'release/mitmproxy.zip' 'release/'"
    rm release/mitmproxy.zip
    
    # Delete unused UI tools to save space! NetSense only needs mitmdump.exe
    echo "[*] Cleaning up unused proxy tools..."
    rm -f release/mitmproxy.exe release/mitmweb.exe
    
    echo "[+] Successfully bundled standalone mitmdump.exe!"
else
    echo "[-] Failed to download mitmproxy!"
fi

# Note about dependencies
echo ""
echo "[*] Packaging Complete! The 'release' folder contains your standalone app."
echo "[!] Note: To run on a machine without MSYS2, you may need to copy the following DLLs into the release folder:"
echo "    - glfw3.dll"
echo "    - libstdc++-6.dll"
echo "    - libgcc_s_seh-1.dll"
echo "    - libwinpthread-1.dll"
