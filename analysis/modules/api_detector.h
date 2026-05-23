#pragma once
#include "../flow_pipeline.h"

// ── API Detector Module ───────────────────────────────────────
// Classifies REST, GraphQL, JSON-RPC, polling endpoints.
// Sets FlowInsight::isAPI = true and populates insight.apiType.
class ApiDetectorModule : public IAnalyzerModule {
public:
    void Analyze(ProxyFlow& flow) override;

private:
    static bool IsGraphQL(const ProxyFlow& flow);
    static bool IsJsonRpc(const ProxyFlow& flow);
    static bool IsRest(const ProxyFlow& flow);
    static bool IsPolling(const ProxyFlow& flow);
    static bool IsXmlApi(const ProxyFlow& flow);
};
