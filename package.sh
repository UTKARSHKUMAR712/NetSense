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
if [ -f "release/NetSense.exe" ]; then
    echo "[+] NetSense.exe compiled successfully in release folder."
elif [ -f "NetSense.exe" ]; then
    cp NetSense.exe release/
    echo "[+] Copied NetSense.exe to release folder."
else
    echo "[-] NetSense.exe not found! Run build.sh first."
    exit 1
fi

echo "[*] Compiling Certificate Uninstaller..."
g++ uninstall_certificate.cpp -o release/uninstall_certificate.exe -O3 -mwindows -static -static-libgcc -static-libstdc++
if [ $? -eq 0 ]; then
    echo "[+] uninstall_certificate.exe created in release folder."
else
    echo "[-] Failed to compile uninstaller!"
fi


# Download and bundle standalone mitmproxy (Includes Python inside!)
if [ ! -f "release/mitmdump.exe" ]; then
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
else
    echo "[+] mitmdump.exe is already bundled in the release folder."
fi

# Bundle mitmproxy root CA certificates so they can be auto-installed
echo "[*] Bundling pre-generated CA certificates..."
cp -u C:/Users/utkarsh_kumar/.mitmproxy/mitmproxy-ca-cert.cer release/ 2>/dev/null || cp -u ~/.mitmproxy/mitmproxy-ca-cert.cer release/ || true
cp -u C:/Users/utkarsh_kumar/.mitmproxy/mitmproxy-ca-cert.p12 release/ 2>/dev/null || cp -u ~/.mitmproxy/mitmproxy-ca-cert.p12 release/ || true
cp -u C:/Users/utkarsh_kumar/.mitmproxy/mitmproxy-ca-cert.pem release/ 2>/dev/null || cp -u ~/.mitmproxy/mitmproxy-ca-cert.pem release/ || true
cp -u C:/Users/utkarsh_kumar/.mitmproxy/mitmproxy-ca.p12 release/ 2>/dev/null || cp -u ~/.mitmproxy/mitmproxy-ca.p12 release/ || true
cp -u C:/Users/utkarsh_kumar/.mitmproxy/mitmproxy-ca.pem release/ 2>/dev/null || cp -u ~/.mitmproxy/mitmproxy-ca.pem release/ || true
cp -u C:/Users/utkarsh_kumar/.mitmproxy/mitmproxy-dhparam.pem release/ 2>/dev/null || cp -u ~/.mitmproxy/mitmproxy-dhparam.pem release/ || true

# Copy to root project too so they are checked in / saved
cp -u release/mitmproxy-ca-cert.* . 2>/dev/null || true
cp -u release/mitmproxy-ca.* . 2>/dev/null || true
cp -u release/mitmproxy-dhparam.pem . 2>/dev/null || true

# Clean up unused/bloated files to save zip space
echo "[*] Cleaning up development artifacts, logs, and settings..."
rm -f release/mitmproxy.exe release/mitmweb.exe
rm -f release/imgui.ini
rm -f release/netsense.db
rm -f release/netsense_settings.json
rm -f release/settings.json
rm -f release/settings.json.bak
rm -f release/proxy/*.log
echo "[]" > release/proxy/rules.json

# Clean up any recordings or logs
rm -rf release/logs/*
rm -rf release/recordings/*

# Create a fresh Zip package
echo "[*] Creating a fresh standalone ZIP archive..."
rm -f NetSense_Release.zip
powershell -Command "Compress-Archive -Path 'release' -DestinationPath 'NetSense_Release.zip' -Force"

# Note about dependencies
echo ""
echo "[*] Packaging Complete! 'NetSense_Release.zip' has been created."
echo "[+] The executable has been statically compiled and has no external DLL requirements (C++ runtime and GLFW3 are statically linked)."
echo "[+] Standalone mitmdump.exe is bundled. The application is ready to run on any clean Windows PC without installing MSYS2, MinGW, or Python."
echo "[+] Bundled CA certificates will be auto-installed silently to Windows Root CAs on startup."


