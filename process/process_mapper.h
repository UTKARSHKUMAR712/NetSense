#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
std::string GetProcessName(DWORD pid);
void ClearProcessCache();
