#include <windows.h>
#include <iostream>
#include <string>

// To compile:
// g++ uninstall_certificate.cpp -o uninstall_certificate.exe -O3 -mwindows

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Requires UAC elevation, but we will simply execute certutil which will prompt if needed,
    // or we can request elevation via manifest. For certutil -delstore, it requires admin rights for "root".
    
    // We will use ShellExecute to run certutil elevated
    std::wstring cmd = L"/C certutil -delstore -user root mitmproxy";
    
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas"; // Request elevation
    sei.lpFile = L"cmd.exe";
    sei.lpParameters = cmd.c_str();
    sei.nShow = SW_HIDE; // Hide the command prompt window
    
    if (ShellExecuteExW(&sei)) {
        MessageBoxW(NULL, L"NetSense proxy certificates have been uninstalled successfully.", L"NetSense Certificate Uninstaller", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxW(NULL, L"Failed to uninstall certificates. You may need to run this as Administrator.", L"NetSense Certificate Uninstaller", MB_OK | MB_ICONERROR);
    }

    return 0;
}
