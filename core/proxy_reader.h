#pragma once
// Phase 5 — Proxy log reader
// Watches netsense_proxy.log (written by mitmproxy addon) and feeds
// entries into g_state.logLines as human-readable strings.
void StartProxyReader();
void StopProxyReader();

// Phase 6 — HTTPS Inspection Mode (mitmdump server)
bool StartProxyServer();
void StopProxyServer();
