#include "flow_pipeline.h"
#include "domain_cache.h"
#include "modules/mime_classifier.h"
#include "modules/stream_detector.h"
#include "modules/api_detector.h"
#include "modules/tracker_detector.h"
#include "modules/auth_detector.h"
#include "modules/risk_analyzer.h"
#include "modules/websocket_analyzer.h"
#include "../utils/structured_log.h"

std::vector<std::unique_ptr<IAnalyzerModule>> FlowPipeline::_modules;

// ─────────────────────────────────────────────────────────────
// Pipeline Registration
// Order matters: MIME → Stream → API → Tracker → Auth → Risk → WS
// ─────────────────────────────────────────────────────────────
void FlowPipeline::Initialize() {
    DomainCache::Initialize();
    _modules.clear();

    // 1. MIME Classifier: validate/enrich content-type first
    _modules.push_back(std::make_unique<MimeClassifierModule>());

    // 2. Stream Detector: HLS/DASH/YouTube/WebRTC
    _modules.push_back(std::make_unique<StreamDetectorModule>());

    // 3. API Detector: REST/GraphQL/JSON-RPC/Polling
    _modules.push_back(std::make_unique<ApiDetectorModule>());

    // 4. Tracker Detector: DomainCache O(1) lookup
    _modules.push_back(std::make_unique<TrackerDetectorModule>());

    // 5. Auth Detector: Bearer/JWT/Basic/Session
    _modules.push_back(std::make_unique<AuthDetectorModule>());

    // 6. Risk Analyzer: MUST run last — aggregates all signals
    _modules.push_back(std::make_unique<RiskAnalyzerModule>());

    // 7. WebSocket Analyzer: opcode/frame classification
    _modules.push_back(std::make_unique<WebSocketAnalyzerModule>());

    StructuredLog::Info(LogChannel::PROXY,
        "FlowPipeline v3.0 initialized: 7 modular analyzers registered.");
}

// ─────────────────────────────────────────────────────────────
// ProcessFlow: runs all modules sequentially on background thread
// ─────────────────────────────────────────────────────────────
void FlowPipeline::ProcessFlow(ProxyFlow& flow) {
    for (auto& mod : _modules) {
        mod->Analyze(flow);
    }
}
