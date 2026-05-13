#include "flow_pipeline.h"
#include "domain_cache.h"
#include "../utils/structured_log.h"
#include <iostream>

std::vector<std::unique_ptr<IAnalyzerModule>> FlowPipeline::_modules;

// Placeholder module for Phase 1 to prove the pipeline works
class BasicTagModule : public IAnalyzerModule {
public:
    void Analyze(ProxyFlow& flow) override {
        // Tag based on simple rules to bootstrap Phase 1
        DomainCategory cat = DomainCache::Classify(flow.host);
        
        if (cat == DomainCategory::TRACKER || cat == DomainCategory::AD) {
            flow.insight.isTracker = true;
            flow.insight.tags.push_back("[TRACKER]");
            flow.insight.riskLevel = "MEDIUM";
        }
        
        if (cat == DomainCategory::API || flow.content_type.find("json") != std::string::npos) {
            flow.insight.isAPI = true;
            flow.insight.tags.push_back("[API]");
            flow.insight.apiType = "JSON";
        }

        if (cat == DomainCategory::CDN) {
            flow.insight.isMedia = true;
            flow.insight.tags.push_back("[CDN]");
        }

        if (flow.is_websocket) {
            flow.insight.tags.push_back("[WS]");
        }
    }
};

void FlowPipeline::Initialize() {
    DomainCache::Initialize();
    
    // Clear old modules if re-initialized
    _modules.clear();

    // Register modules
    _modules.push_back(std::make_unique<BasicTagModule>());
    
    // In Phase 2, we will add:
    // _modules.push_back(std::make_unique<MimeClassifierModule>());
    // _modules.push_back(std::make_unique<StreamDetectorModule>());
    // _modules.push_back(std::make_unique<AuthDetectorModule>());
    // _modules.push_back(std::make_unique<RiskAnalyzerModule>());

    StructuredLog::Info(LogChannel::PROXY, "FlowPipeline initialized with Domain Cache.");
}

void FlowPipeline::ProcessFlow(ProxyFlow& flow) {
    // Run flow through every registered module
    for (auto& mod : _modules) {
        mod->Analyze(flow);
    }
}
