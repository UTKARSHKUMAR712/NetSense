#pragma once
#include "../flow_pipeline.h"

// ── WebSocket Analyzer Module ─────────────────────────────────
// Identifies WebSocket handshakes, classifies message opcodes
// (Text=1 / Binary=2), and detects JSON payloads within WS frames.
// Adds [WS], [WS:JSON], or [WS:BIN] tags accordingly.
class WebSocketAnalyzerModule : public IAnalyzerModule {
public:
    void Analyze(ProxyFlow& flow) override;
};
