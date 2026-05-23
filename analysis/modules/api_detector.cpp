#include "api_detector.h"
#include <algorithm>

// ─────────────────────────────────────────────────────────────
// API URL keyword hints
// ─────────────────────────────────────────────────────────────
static bool ci_contains(const std::string& h, const std::string& n) {
    std::string a = h, b = n;
    std::transform(a.begin(), a.end(), a.begin(), ::tolower);
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    return a.find(b) != std::string::npos;
}

bool ApiDetectorModule::IsGraphQL(const ProxyFlow& flow) {
    return ci_contains(flow.url, "graphql") ||
           ci_contains(flow.url, "/gql") ||
           ci_contains(flow.body_preview, "\"query\"") ||
           ci_contains(flow.body_preview, "\"mutation\"");
}

bool ApiDetectorModule::IsJsonRpc(const ProxyFlow& flow) {
    return ci_contains(flow.body_preview, "\"jsonrpc\"") ||
           ci_contains(flow.url, "jsonrpc") ||
           ci_contains(flow.url, "/rpc");
}

bool ApiDetectorModule::IsXmlApi(const ProxyFlow& flow) {
    return ci_contains(flow.content_type, "xml") ||
           ci_contains(flow.content_type, "soap") ||
           ci_contains(flow.url, "/soap") ||
           ci_contains(flow.url, "/wsdl");
}

bool ApiDetectorModule::IsPolling(const ProxyFlow& flow) {
    // Polling patterns: repeated short-interval requests to same endpoint
    return ci_contains(flow.url, "poll") ||
           ci_contains(flow.url, "longpoll") ||
           ci_contains(flow.url, "comet") ||
           ci_contains(flow.url, "subscribe") ||
           ci_contains(flow.url, "events") ||
           ci_contains(flow.url, "sse");
}

bool ApiDetectorModule::IsRest(const ProxyFlow& flow) {
    // REST: JSON content type, or API path patterns
    bool hasJson = ci_contains(flow.content_type, "json");
    bool hasApiPath = ci_contains(flow.url, "/api/")  ||
                     ci_contains(flow.url, "/api?")   ||
                     ci_contains(flow.url, "/v1/")    ||
                     ci_contains(flow.url, "/v2/")    ||
                     ci_contains(flow.url, "/v3/")    ||
                     ci_contains(flow.url, "/rest/")  ||
                     ci_contains(flow.url, "/data/")  ||
                     ci_contains(flow.url, ".json");
    // Host prefix hints
    bool hasApiHost = ci_contains(flow.host, "api.") ||
                     ci_contains(flow.host, "graph.") ||
                     ci_contains(flow.host, "rest.");
    return hasJson || hasApiPath || hasApiHost;
}

void ApiDetectorModule::Analyze(ProxyFlow& flow) {
    if (flow.insight.isAPI) return; // already classified

    // Skip WebSocket and streams
    if (flow.is_websocket || flow.insight.isStream) return;

    bool detected = false;
    std::string apiType;

    if (IsGraphQL(flow)) {
        detected = true;
        apiType = "GraphQL";
        flow.insight.tags.push_back("[API:GraphQL]");
    } else if (IsJsonRpc(flow)) {
        detected = true;
        apiType = "JSON-RPC";
        flow.insight.tags.push_back("[API:RPC]");
    } else if (IsXmlApi(flow)) {
        detected = true;
        apiType = "XML/SOAP";
        flow.insight.tags.push_back("[API:XML]");
    } else if (IsPolling(flow)) {
        detected = true;
        apiType = "Polling/SSE";
        flow.insight.tags.push_back("[API:POLL]");
    } else if (IsRest(flow)) {
        detected = true;
        apiType = "REST";
        flow.insight.tags.push_back("[API]");
    }

    if (detected) {
        flow.insight.isAPI = true;
        flow.insight.apiType = apiType;
    }
}
