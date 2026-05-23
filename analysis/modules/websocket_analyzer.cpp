#include "websocket_analyzer.h"

void WebSocketAnalyzerModule::Analyze(ProxyFlow& flow) {
    if (!flow.is_websocket && flow.type != "WS_MSG") return;

    // Opcode 1 = Text, Opcode 2 = Binary, -1 = unknown
    if (flow.ws_opcode == 1) {
        // Text frame — check if payload looks like JSON
        if (!flow.ws_message.empty() &&
            (flow.ws_message[0] == '{' || flow.ws_message[0] == '[')) {
            flow.insight.tags.push_back("[WS:JSON]");
            flow.insight.mime = "application/json";
            flow.insight.isAPI = true;
            flow.insight.apiType = "WebSocket/JSON";
        } else {
            flow.insight.tags.push_back("[WS:TEXT]");
        }
    } else if (flow.ws_opcode == 2) {
        flow.insight.tags.push_back("[WS:BIN]");
    } else {
        // Fallback for WS connection flows
        flow.insight.tags.push_back("[WS]");
    }
}
