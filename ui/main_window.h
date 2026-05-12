#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// Creates and runs the main window. Blocks until window is closed.
int RunUI(HINSTANCE hInstance, int nCmdShow);

// Called by the monitoring thread to request a UI repaint
void RequestUIRefresh();
