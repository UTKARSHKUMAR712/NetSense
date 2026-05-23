#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include <string>
#include <vector>
#include <ctime>
#include <algorithm>
#include "../../third_party/json/json.hpp"

using json = nlohmann::json;

// ─────────────────────────────────────────────────────────────
// Panel state
// ─────────────────────────────────────────────────────────────
static std::string g_inspectorFilter  = "";
static std::string g_selectedFlowId  = "";
static bool        g_prettyReqH      = true;
static bool        g_prettyRspH      = true;
static bool        g_prettyBody      = true;
static bool        g_showFullscreen  = false;
static std::string g_fullscreenText  = "";
static std::string g_fullscreenTitle = "";

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────
static bool ci_contains(const std::string& h, const std::string& n) {
    std::string a = h, b = n;
    std::transform(a.begin(), a.end(), a.begin(), ::tolower);
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    return a.find(b) != std::string::npos;
}

static ImVec4 RiskColor(const std::string& risk) {
    if (risk == "CRITICAL") return ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
    if (risk == "HIGH")     return ImVec4(1.0f, 0.4f, 0.0f, 1.0f);
    if (risk == "MEDIUM")   return ImVec4(1.0f, 0.8f, 0.0f, 1.0f);
    if (risk == "LOW")      return ImVec4(0.3f, 1.0f, 0.5f, 1.0f);
    return ImVec4(0.6f, 0.6f, 0.6f, 1.0f);
}

static void ShowFullscreenModal() {
    if (g_showFullscreen) {
        ImGui::OpenPopup(g_fullscreenTitle.c_str());
    }
    ImGui::SetNextWindowSize(
        ImVec2(ImGui::GetIO().DisplaySize.x * 0.92f,
               ImGui::GetIO().DisplaySize.y * 0.92f),
        ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal(g_fullscreenTitle.c_str(), &g_showFullscreen)) {
        // Copy button in modal header
        if (ImGui::Button("Copy All", ImVec2(100, 0)))
            ImGui::SetClipboardText(g_fullscreenText.c_str());
        ImGui::SameLine();
        if (ImGui::Button("Close", ImVec2(80, 0))) {
            g_showFullscreen = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::Separator();
        ImGui::BeginChild("FS_Content", ImVec2(0, ImGui::GetContentRegionAvail().y), true);
        ImGui::InputTextMultiline("##fs_txt",
            (char*)g_fullscreenText.c_str(),
            g_fullscreenText.size() + 1,
            ImVec2(-FLT_MIN, -FLT_MIN),
            ImGuiInputTextFlags_ReadOnly);
        ImGui::EndChild();
        ImGui::EndPopup();
    }
}

// ─────────────────────────────────────────────────────────────
// Reusable JSON tab renderer
// ─────────────────────────────────────────────────────────────
static void RenderJsonTab(const char* label, const std::string& rawData, bool& prettyToggle) {
    if (ImGui::BeginTabItem(label)) {
        ImGui::Checkbox("Pretty JSON", &prettyToggle);
        ImGui::SameLine();
        if (ImGui::Button("Fullscreen")) {
            g_fullscreenTitle = std::string(label) + " (Fullscreen)";
            g_showFullscreen  = true;
            g_fullscreenText  = rawData;
        }
        ImGui::SameLine();
        if (ImGui::Button("Copy")) ImGui::SetClipboardText(rawData.c_str());
        ImGui::Separator();

        std::string displayText = rawData;
        if (prettyToggle && !displayText.empty() &&
            (displayText[0] == '{' || displayText[0] == '[')) {
            try {
                auto j = json::parse(displayText);
                displayText = j.dump(4);
            } catch (...) {}
        }
        if (g_showFullscreen && g_fullscreenTitle.find(label) != std::string::npos) {
            g_fullscreenText = displayText;
        }

        ImGui::BeginChild((std::string(label) + "_child").c_str(), ImVec2(0,0), true);
        ImGui::InputTextMultiline("##content",
            (char*)displayText.c_str(), displayText.size() + 1,
            ImVec2(-FLT_MIN, -FLT_MIN), ImGuiInputTextFlags_ReadOnly);
        ImGui::EndChild();
        ImGui::EndTabItem();
    }
}

// ─────────────────────────────────────────────────────────────
// TLS Intelligence section
// ─────────────────────────────────────────────────────────────
static void RenderTlsSection(const ProxyFlow& f) {
    ImGui::Spacing();
    ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "TLS / Secure Tunnel");
    ImGui::Separator();

    if (f.tls_valid) {
        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.4f, 1.0f), "[ENCRYPTED]");
    } else {
        ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "[UNENCRYPTED]  WARNING: Traffic is in cleartext!");
    }
    ImGui::Spacing();

    if (ImGui::BeginTable("TlsTable", 2,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Value",    ImGuiTableColumnFlags_WidthStretch);

        auto Row = [](const char* key, const std::string& val,
                      ImVec4 col = ImVec4(0.9f,0.9f,0.9f,1.0f)) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextDisabled("%s", key);
            ImGui::TableSetColumnIndex(1);
            if (val.empty()) ImGui::TextDisabled("—");
            else             ImGui::TextColored(col, "%s", val.c_str());
        };

        // TLS version with colour coding
        ImVec4 tlsVerCol = ImVec4(0.9f,0.9f,0.9f,1.0f);
        if      (f.tls_version.find("1.3") != std::string::npos) tlsVerCol = ImVec4(0.2f,1.0f,0.4f,1.0f);
        else if (f.tls_version.find("1.2") != std::string::npos) tlsVerCol = ImVec4(1.0f,0.8f,0.2f,1.0f);
        else if (!f.tls_version.empty())                          tlsVerCol = ImVec4(1.0f,0.3f,0.3f,1.0f);
        Row("TLS Version", f.tls_version.empty() ? (f.tls_valid ? "Negotiated" : "None") : f.tls_version, tlsVerCol);

        // ALPN: HTTP/2 = green, HTTP/3 = cyan
        ImVec4 alpnCol = ImVec4(0.9f,0.9f,0.9f,1.0f);
        if      (f.tls_alpn == "h2")  alpnCol = ImVec4(0.2f,1.0f,0.6f,1.0f);
        else if (f.tls_alpn == "h3")  alpnCol = ImVec4(0.2f,0.8f,1.0f,1.0f);
        else if (f.tls_alpn == "http/1.1") alpnCol = ImVec4(0.8f,0.6f,0.3f,1.0f);
        Row("ALPN Protocol", f.tls_alpn.empty() ? "HTTP/1.1" : f.tls_alpn, alpnCol);

        Row("Cipher Suite", f.tls_cipher);
        Row("SNI", f.tls_sni);
        Row("Port", std::to_string(f.port));

        ImGui::EndTable();
    }
}

// ─────────────────────────────────────────────────────────────
// Intelligence tab (streams, APIs, TLS, risk)
// ─────────────────────────────────────────────────────────────
static void RenderIntelligenceTab(const ProxyFlow& f) {
    if (!ImGui::BeginTabItem("[+] Intelligence")) return;
    ImGui::BeginChild("IntellChild", ImVec2(0, 0), false);

    // ── Risk Banner ───────────────────────────────────────────
    if (!f.insight.riskLevel.empty()) {
        ImVec4 rc = RiskColor(f.insight.riskLevel);
        ImGui::TextColored(rc, "  RISK: %s", f.insight.riskLevel.c_str());
        if (f.insight.riskLevel == "CRITICAL" || f.insight.riskLevel == "HIGH") {
            ImGui::SameLine();
            ImGui::TextColored(rc, " <-- Immediate Action Recommended!");
        }
        ImGui::Separator();
    }

    // ── Stream Detection ──────────────────────────────────────
    if (f.insight.isStream) {
        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.4f, 1.0f), "STREAM MEDIA DETECTED");
        ImGui::Separator();

        std::string streamType  = "Direct playback link identified.";
        std::string formatHint;
        if (ci_contains(f.url, ".m3u8")) {
            streamType = "HLS Playlist (Apple HTTP Live Streaming).";
            formatHint = "Open in VLC: Media > Open Network Stream";
        } else if (ci_contains(f.url, ".mpd")) {
            streamType = "MPEG-DASH Adaptive Stream.";
            formatHint = "Compatible with VLC, IINA, mpv";
        } else if (ci_contains(f.host, "googlevideo.com")) {
            streamType = "YouTube Video Chunk (videoplayback).";
            formatHint = "Use yt-dlp or paste into VLC";
        } else if (ci_contains(f.url, "live") || ci_contains(f.url, "/hls/")) {
            streamType = "Live Stream chunk identified.";
            formatHint = "Open in VLC or stream via ffmpeg";
        }

        if (!f.insight.mime.empty()) {
            ImGui::Text("Format: %s", f.insight.mime.c_str());
        }
        ImGui::TextWrapped("%s", streamType.c_str());
        if (!formatHint.empty()) {
            ImGui::TextColored(ImVec4(0.6f,0.6f,0.6f,1.0f), "Tip: %s", formatHint.c_str());
        }
        ImGui::Spacing();
        ImGui::TextWrapped("Stream URL:");
        ImGui::InputText("##streamurl",
            (char*)f.url.c_str(), f.url.size() + 1,
            ImGuiInputTextFlags_ReadOnly);
        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.1f, 0.6f, 0.2f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.15f, 0.8f, 0.3f, 1.0f));
        if (ImGui::Button("  COPY DIRECT STREAM LINK  ", ImVec2(280, 40))) {
            ImGui::SetClipboardText(f.url.c_str());
        }
        ImGui::PopStyleColor(2);
        ImGui::SameLine();
        if (ImGui::Button("Fullscreen##stream", ImVec2(110, 40))) {
            g_fullscreenTitle = "Stream URL (Fullscreen)";
            g_fullscreenText  = f.url;
            g_showFullscreen  = true;
        }
    }
    // ── API/ChatGPT/LLM Response Detection ───────────────────
    else if (f.insight.isAPI) {
        ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.2f, 1.0f),
            "API ENDPOINT DETECTED  [%s]", f.insight.apiType.c_str());
        ImGui::Separator();

        bool isChatGptLike = ci_contains(f.host, "api.openai.com")   ||
                             ci_contains(f.host, "claude.ai")         ||
                             ci_contains(f.host, "generativelanguage") ||
                             ci_contains(f.host, "api.anthropic.com") ||
                             ci_contains(f.url, "/chat/completions")   ||
                             ci_contains(f.url, "/generate")           ||
                             ci_contains(f.url, "/completions");

        if (isChatGptLike) {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.8f, 1.0f),
                "LLM / AI Response Detected");
            ImGui::TextWrapped(
                "This is a request to an AI/LLM API (ChatGPT, Claude, Gemini, etc.).\n"
                "The body_preview below contains the structured JSON response.\n"
                "Look for the 'choices[0].message.content' or 'text' field.");
            ImGui::Spacing();
        } else {
            ImGui::Text("Structured data endpoint. Type: %s", f.insight.apiType.c_str());
        }

        if (!f.body_preview.empty()) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.3f, 1.0f), "Extracted Payload:");

            std::string preview = f.body_preview;
            try {
                auto j = json::parse(preview);
                // For ChatGPT-style: extract message content
                if (isChatGptLike && j.contains("choices") && j["choices"].is_array()
                    && !j["choices"].empty()) {
                    std::string content;
                    auto& ch = j["choices"][0];
                    if (ch.contains("message") && ch["message"].contains("content"))
                        content = ch["message"]["content"].get<std::string>();
                    else if (ch.contains("text"))
                        content = ch["text"].get<std::string>();

                    if (!content.empty()) {
                        ImGui::Spacing();
                        ImGui::TextColored(ImVec4(0.2f,1.0f,0.6f,1.0f), "AI Response:");
                        ImGui::BeginChild("AIResp", ImVec2(0, 120), true);
                        ImGui::TextWrapped("%s", content.c_str());
                        ImGui::EndChild();
                        ImGui::Spacing();
                        if (ImGui::Button("Copy AI Response##ai")) {
                            ImGui::SetClipboardText(content.c_str());
                        }
                        ImGui::SameLine();
                    }
                }
                preview = j.dump(4);
            } catch (...) {}

            ImGui::SameLine(0, 10);
            if (ImGui::Button("Fullscreen##intell")) {
                g_fullscreenTitle = "Extracted API Payload (Fullscreen)";
                g_fullscreenText  = preview;
                g_showFullscreen  = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Copy JSON##intell")) {
                ImGui::SetClipboardText(preview.c_str());
            }

            ImGui::InputTextMultiline("##intell_payload",
                (char*)preview.c_str(), preview.size() + 1,
                ImVec2(-FLT_MIN, ImGui::GetContentRegionAvail().y - 10),
                ImGuiInputTextFlags_ReadOnly);
        } else {
            ImGui::Spacing();
            ImGui::TextDisabled(
                "No body captured. Enable body capture in Settings > Body Capture.");
        }
    }
    // ── Auth Detection ────────────────────────────────────────
    else if (f.insight.isAuth) {
        ImGui::TextColored(ImVec4(0.8f, 0.2f, 0.8f, 1.0f),
            "AUTH FLOW DETECTED  [%s]", f.insight.authType.c_str());
        ImGui::Separator();
        ImGui::Text("Authentication type: %s", f.insight.authType.c_str());

        const auto& vp = f.insight.vaultPayload;
        if (!vp.username.empty()) {
            ImGui::TextColored(ImVec4(0.3f,1.0f,0.5f,1.0f),
                "Username: %s", vp.username.c_str());
        }
        if (!vp.bearerToken.empty()) {
            ImGui::Spacing();
            ImGui::Text("Token (truncated):");
            std::string trunc = vp.bearerToken.size() > 64
                ? vp.bearerToken.substr(0, 64) + "..." : vp.bearerToken;
            ImGui::TextColored(ImVec4(0.85f,0.85f,0.85f,1.0f), "%s", trunc.c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy Token##intell"))
                ImGui::SetClipboardText(vp.bearerToken.c_str());
        }
        if (!vp.authCookies.empty()) {
            ImGui::Spacing();
            ImGui::Text("Auth Cookies:");
            ImGui::TextWrapped("%s", vp.authCookies.c_str());
        }
    }
    else {
        ImGui::TextDisabled("No advanced intelligence for this flow.");
        ImGui::TextDisabled("Select an [API], [STREAM], or [AUTH] tagged flow to view extractions.");
    }

    ImGui::Spacing();
    ImGui::Separator();
    // ── TLS Intelligence (always visible) ────────────────────
    RenderTlsSection(f);

    ImGui::EndChild();
    ImGui::EndTabItem();
}

// ─────────────────────────────────────────────────────────────
// Direct Link tab — extract all stream/API URLs from raw headers
// ─────────────────────────────────────────────────────────────
static void RenderDirectLinkTab(const ProxyFlow& f) {
    if (!ImGui::BeginTabItem("[>] Direct Link")) return;
    ImGui::BeginChild("DLChild", ImVec2(0,0), false);

    ImGui::TextColored(ImVec4(0.4f,0.9f,1.0f,1.0f),
        "Direct Link Extractor & Resource Inspector");
    ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1.0f),
        "Automatically extracts stream URLs, API endpoints, and key payloads.");
    ImGui::Separator();
    ImGui::Spacing();

    // Main URL
    ImGui::TextColored(ImVec4(0.9f,0.9f,0.3f,1.0f), "Full URL:");
    ImGui::InputText("##dl_url",
        (char*)f.url.c_str(), f.url.size() + 1, ImGuiInputTextFlags_ReadOnly);
    ImGui::SameLine();
    if (ImGui::Button("Copy##dlurl")) ImGui::SetClipboardText(f.url.c_str());

    ImGui::Spacing();

    // Stream: offer big copy button
    if (f.insight.isStream || ci_contains(f.url, ".m3u8") ||
        ci_contains(f.url, ".mpd") || ci_contains(f.url, "videoplayback")) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.05f, 0.55f, 0.15f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.1f, 0.75f, 0.25f, 1.0f));
        if (ImGui::Button("  COPY STREAM LINK (Open in VLC/IDM/ffmpeg)  ",
                          ImVec2(ImGui::GetContentRegionAvail().x, 40))) {
            ImGui::SetClipboardText(f.url.c_str());
        }
        ImGui::PopStyleColor(2);
        ImGui::Spacing();
    }

    // Parse redirect chain
    if (!f.redirect_chain.empty()) {
        ImGui::TextColored(ImVec4(1.0f,0.7f,0.2f,1.0f), "Redirect Chain:");
        ImGui::TextWrapped("%s", f.redirect_chain.c_str());
        if (ImGui::SmallButton("Copy Redirect##dl"))
            ImGui::SetClipboardText(f.redirect_chain.c_str());
        ImGui::Spacing();
    }

    // Query parameters parsed
    if (!f.query_params.empty() && f.query_params != "{}") {
        ImGui::TextColored(ImVec4(0.8f,0.8f,0.3f,1.0f), "Query Parameters:");
        ImGui::BeginChild("QP", ImVec2(0, 100), true);
        // Try to parse as JSON
        try {
            auto j = json::parse(f.query_params);
            for (auto& [k, v] : j.items()) {
                ImGui::TextColored(ImVec4(0.5f,0.9f,0.5f,1.0f), "  %s", k.c_str());
                ImGui::SameLine();
                ImGui::Text("= %s", v.get<std::string>().c_str());
            }
        } catch (...) {
            ImGui::TextUnformatted(f.query_params.c_str());
        }
        ImGui::EndChild();
        ImGui::Spacing();
    }

    // API body payload extraction
    if (f.insight.isAPI && !f.body_preview.empty()) {
        ImGui::TextColored(ImVec4(1.0f,0.6f,0.2f,1.0f), "API Payload:");

        std::string pretty = f.body_preview;
        try {
            auto j = json::parse(pretty);
            pretty = j.dump(4);
        } catch (...) {}

        if (ImGui::Button("Copy Payload##dl"))
            ImGui::SetClipboardText(pretty.c_str());
        ImGui::SameLine();
        if (ImGui::Button("Fullscreen##dl")) {
            g_fullscreenTitle = "API Payload (Fullscreen)";
            g_fullscreenText  = pretty;
            g_showFullscreen  = true;
        }
        ImGui::InputTextMultiline("##dl_body",
            (char*)pretty.c_str(), pretty.size() + 1,
            ImVec2(-FLT_MIN, 200),
            ImGuiInputTextFlags_ReadOnly);
        ImGui::Spacing();
    }

    // Response headers key info
    if (!f.raw_rsp_headers.empty()) {
        ImGui::TextColored(ImVec4(0.6f,0.6f,1.0f,1.0f), "Key Response Headers:");
        ImGui::BeginChild("RspHdrKey", ImVec2(0, 120), true);
        try {
            auto j = json::parse(f.raw_rsp_headers);
            // Focus on important headers
            const char* important[] = {
                "content-type","location","set-cookie","content-length",
                "x-request-id","x-trace-id","cache-control","etag",nullptr
            };
            for (int i = 0; important[i]; ++i) {
                for (auto& [k, v] : j.items()) {
                    if (ci_contains(k, important[i])) {
                        ImGui::TextColored(ImVec4(0.5f,0.8f,0.5f,1.0f),
                            "  %-22s", k.c_str());
                        ImGui::SameLine();
                        ImGui::TextUnformatted(v.get<std::string>().c_str());
                    }
                }
            }
        } catch (...) {
            ImGui::TextUnformatted(f.raw_rsp_headers.c_str());
        }
        ImGui::EndChild();
    }

    ImGui::EndChild();
    ImGui::EndTabItem();
}

// ─────────────────────────────────────────────────────────────
// Main Inspector Panel
// ─────────────────────────────────────────────────────────────
void RenderInspectorPanel() {
    std::lock_guard<std::mutex> lk(g_state.mtx);

    // ── Filter Bar ────────────────────────────────────────────
    char filterBuf[256];
    strncpy(filterBuf, g_inspectorFilter.c_str(), sizeof(filterBuf));
    filterBuf[sizeof(filterBuf)-1] = '\0';
    ImGui::Text("Filter:"); ImGui::SameLine();
    ImGui::SetNextItemWidth(320);
    if (ImGui::InputText("##InspectorFilter", filterBuf, sizeof(filterBuf)))
        g_inspectorFilter = filterBuf;
    ImGui::SameLine();
    if (ImGui::Button("Clear")) g_inspectorFilter = "";
    ImGui::SameLine();
    ImGui::TextDisabled("  Syntax: host, url, tag ([API], [STREAM], [AUTH]...)");
    ImGui::Separator();

    // ── Flow Table ────────────────────────────────────────────
    // selectedFlow must be declared in outer scope so it persists past EndTable/EndChild
    ProxyFlow* selectedFlow = nullptr;

    ImGui::BeginChild("FlowTableChild",
        ImVec2(0, ImGui::GetContentRegionAvail().y * 0.48f), true);

    if (ImGui::BeginTable("InspectorFlows", 8,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_SizingStretchProp)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Time",   ImGuiTableColumnFlags_WidthFixed,   60.0f);
        ImGui::TableSetupColumn("Tag",    ImGuiTableColumnFlags_WidthFixed,   90.0f);
        ImGui::TableSetupColumn("Risk",   ImGuiTableColumnFlags_WidthFixed,   65.0f);
        ImGui::TableSetupColumn("St",     ImGuiTableColumnFlags_WidthFixed,   38.0f);
        ImGui::TableSetupColumn("Host",   ImGuiTableColumnFlags_WidthStretch, 0.2f);
        ImGui::TableSetupColumn("URL",    ImGuiTableColumnFlags_WidthStretch, 0.6f);
        ImGui::TableSetupColumn("Size",   ImGuiTableColumnFlags_WidthFixed,   58.0f);
        ImGui::TableSetupColumn("ms",     ImGuiTableColumnFlags_WidthFixed,   48.0f);
        ImGui::TableHeadersRow();

        for (auto it = g_state.proxyFlows.rbegin(); it != g_state.proxyFlows.rend(); ++it) {
            auto& f = *it;
            if (f.type != "RSP") continue;

            if (!g_inspectorFilter.empty()) {
                if (!ci_contains(f.host,          g_inspectorFilter) &&
                    !ci_contains(f.url,           g_inspectorFilter) &&
                    !ci_contains(f.insight_tags,  g_inspectorFilter) &&
                    !ci_contains(f.insight.apiType, g_inspectorFilter) &&
                    !ci_contains(f.insight.authType, g_inspectorFilter)) {
                    continue;
                }
            }

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);

            char timeBuf[16];
            time_t rawtime = (time_t)f.ts;
            struct tm* timeinfo = localtime(&rawtime);
            strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", timeinfo);

            bool is_selected = (g_selectedFlowId == f.id);
            if (ImGui::Selectable(
                (std::string(timeBuf) + "##" + f.id).c_str(),
                is_selected, ImGuiSelectableFlags_SpanAllColumns))
            {
                g_selectedFlowId = f.id;
            }
            if (is_selected) selectedFlow = &f;

            // ── Tag column ────────────────────────────────────
            ImGui::TableSetColumnIndex(1);
            if (f.insight.isStream)
                ImGui::TextColored(ImVec4(0.2f,0.8f,1.0f,1.0f), "[STREAM]");
            else if (f.insight.isAPI) {
                std::string lbl = "[API]";
                if (!f.insight.apiType.empty() && f.insight.apiType != "REST")
                    lbl = "[" + f.insight.apiType + "]";
                ImGui::TextColored(ImVec4(1.0f,0.6f,0.2f,1.0f), "%s", lbl.c_str());
            }
            else if (f.insight.isAuth)
                ImGui::TextColored(ImVec4(0.8f,0.2f,0.8f,1.0f), "[AUTH]");
            else if (f.insight.isTracker)
                ImGui::TextColored(ImVec4(1.0f,0.3f,0.3f,1.0f), "[TRACKER]");
            else if (f.insight.isMedia)
                ImGui::TextColored(ImVec4(0.5f,0.8f,0.3f,1.0f), "[CDN]");
            else if (f.is_websocket)
                ImGui::TextColored(ImVec4(0.6f,0.4f,1.0f,1.0f), "[WS]");
            else
                ImGui::TextColored(ImVec4(0.6f,0.6f,0.6f,1.0f), "%s", f.method.c_str());

            // ── Risk column ───────────────────────────────────
            ImGui::TableSetColumnIndex(2);
            if (!f.insight.riskLevel.empty())
                ImGui::TextColored(RiskColor(f.insight.riskLevel),
                    "%s", f.insight.riskLevel.c_str());
            else
                ImGui::TextDisabled("—");

            // ── Status column ─────────────────────────────────
            ImGui::TableSetColumnIndex(3);
            ImVec4 sc = ImVec4(1,1,1,1);
            if      (f.status >= 200 && f.status < 300) sc = ImVec4(0.2f,1.0f,0.4f,1.0f);
            else if (f.status >= 300 && f.status < 400) sc = ImVec4(1.0f,0.8f,0.2f,1.0f);
            else if (f.status >= 400)                    sc = ImVec4(1.0f,0.3f,0.3f,1.0f);
            ImGui::TextColored(sc, "%d", f.status);

            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(f.host.c_str());

            ImGui::TableSetColumnIndex(5);
            ImGui::TextUnformatted(f.url.c_str());
            if (f.insight.isStream && !f.insight.mime.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.4f,0.4f,0.4f,1.0f), "(%s)", f.insight.mime.c_str());
            }

            ImGui::TableSetColumnIndex(6);
            ImGui::Text("%lld B", f.rsp_size);

            ImGui::TableSetColumnIndex(7);
            ImGui::Text("%.0f", f.duration_ms);
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::Separator();

    // ── Detail Pane ───────────────────────────────────────────
    ImGui::BeginChild("DetailPane", ImVec2(0, 0), true);
    if (selectedFlow) {
        ProxyFlow& sf = *selectedFlow;

        // URL + Copy
        ImGui::TextColored(ImVec4(0.0f,1.0f,0.6f,1.0f), "URL:"); ImGui::SameLine();
        ImGui::TextWrapped("%s", sf.url.c_str());
        ImGui::SameLine();
        if (ImGui::Button("Copy URL")) ImGui::SetClipboardText(sf.url.c_str());

        // Tags strip
        std::string allTags;
        for (const auto& t : sf.insight.tags) allTags += t + " ";
        if (!allTags.empty() || !sf.insight_tags.empty()) {
            ImGui::TextColored(ImVec4(1.0f,0.8f,0.0f,1.0f),
                "Tags: %s %s", allTags.c_str(), sf.insight_tags.c_str());
        }

        ImGui::Spacing();
        if (ImGui::BeginTabBar("DetailTabs")) {
            RenderJsonTab("Request Headers",  sf.raw_req_headers, g_prettyReqH);
            RenderJsonTab("Response Headers", sf.raw_rsp_headers, g_prettyRspH);
            RenderJsonTab("Body Preview",     sf.body_preview,    g_prettyBody);
            RenderDirectLinkTab(sf);
            RenderIntelligenceTab(sf);
            ImGui::EndTabBar();
        }
    } else {
        ImGui::Spacing();
        ImGui::TextDisabled("  Select a flow from the table above to view details.");
        ImGui::TextDisabled("  Use the filter bar to search by host, URL, or tag.");
    }
    ImGui::EndChild();

    // ── Fullscreen Modal ──────────────────────────────────────
    ShowFullscreenModal();
}
