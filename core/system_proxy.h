#pragma once
#include <string>

// ─────────────────────────────────────────────────────────────
// SystemProxy — reads, sets, and restores Windows system-wide
// proxy settings via the WinINet / Internet Options registry key.
//
// On startup:  Save existing settings, then point all traffic to
//              127.0.0.1:<port>.
// On shutdown: Restore saved settings exactly (including "no proxy"
//              state).  Always called even on crash via atexit().
// ─────────────────────────────────────────────────────────────
namespace SystemProxy {

    // Capture current system proxy and activate 127.0.0.1:port
    // Returns true on success.
    bool Activate(int port);

    // Restore whatever was saved by Activate().
    // Safe to call multiple times (idempotent).
    void Restore();

    // Returns true if Activate() has been called and proxy is live.
    bool IsActive();

    // Returns e.g. "127.0.0.1:8080"
    std::string ActiveAddress();
}
