#include "panels.h"
#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include <vector>
#include <string>
#include <algorithm>
#include <ctime>
#include <map>

// Helper to split string by delimiter
static std::vector<std::string> SplitString(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        // Trim leading space
        size_t start = item.find_first_not_of(" ");
        if (start != std::string::npos) item = item.substr(start);
        result.push_back(item);
    }
    return result;
}

// ─────────────────────────────────────────────────────────────
// Aggregated catcher entries (built from live flow buffer)
// ─────────────────────────────────────────────────────────────
struct CredEntry {
    std::string host;
    std::string username;
    std::string password;
    double      ts = 0;
};
struct TokenEntry {
    std::string host;
    std::string token;
    std::string tokenType; // "JWT" / "Bearer"
    double      ts = 0;
};
struct CookieEntry {
    std::string host;
    std::string cookies;
    double      ts = 0;
};

static std::vector<CredEntry>   g_creds;
static std::vector<TokenEntry>  g_tokens;
static std::vector<CookieEntry> g_cookies;
static double g_lastCatcherRefresh = 0.0;

// Refresh aggregated data from live flows every 2 seconds
static void RefreshCatcherData() {
    double now = (double)time(nullptr);
    if (now - g_lastCatcherRefresh < 2.0) return;
    g_lastCatcherRefresh = now;

    g_creds.clear();
    g_tokens.clear();
    g_cookies.clear();

    std::lock_guard<std::mutex> lk(g_state.mtx);
    for (auto& f : g_state.proxyFlows) {
        const auto& vp = f.insight.vaultPayload;

        // Credentials
        if (!vp.username.empty() || !vp.password.empty()) {
            // Deduplicate by host+user
            bool dup = false;
            for (auto& c : g_creds) {
                if (c.host == f.host && c.username == vp.username) { dup = true; break; }
            }
            if (!dup) {
                g_creds.push_back({f.host, vp.username, vp.password, f.ts});
            }
        }

        // Tokens
        if (!vp.bearerToken.empty()) {
            bool dup = false;
            for (auto& t : g_tokens) {
                if (t.host == f.host && t.token == vp.bearerToken) { dup = true; break; }
            }
            if (!dup) {
                // Check if JWT (has 2 dots)
                int dots = 0;
                for (char c : vp.bearerToken) if (c == '.') ++dots;
                g_tokens.push_back({f.host, vp.bearerToken, dots==2 ? "JWT" : "Bearer", f.ts});
            }
        }

        // Cookies
        if (!vp.authCookies.empty()) {
            bool dup = false;
            for (auto& ck : g_cookies) {
                if (ck.host == f.host) { dup = true; break; }
            }
            if (!dup) {
                g_cookies.push_back({f.host, vp.authCookies, f.ts});
            }
        }
    }

    // Sort by timestamp descending
    std::sort(g_creds.begin(), g_creds.end(),   [](auto& a, auto& b){ return a.ts > b.ts; });
    std::sort(g_tokens.begin(), g_tokens.end(),  [](auto& a, auto& b){ return a.ts > b.ts; });
    std::sort(g_cookies.begin(), g_cookies.end(),[](auto& a, auto& b){ return a.ts > b.ts; });
}

static bool g_revealPasswords = false;

void RenderCatcherPanel() {
    RefreshCatcherData();

    // ── Header ────────────────────────────────────────────────
    ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "[CATCHER] Auto-Capture Vault");
    ImGui::SameLine();
    ImGui::TextDisabled("  |  Live data from intercepted traffic");
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 220);
    ImGui::TextColored(ImVec4(1.0f,0.8f,0.0f,1.0f),
        "Creds: %d  Tokens: %d  Cookies: %d",
        (int)g_creds.size(), (int)g_tokens.size(), (int)g_cookies.size());
    ImGui::Separator();

    static int g_selectedTab = 0; // 0=Creds, 1=Tokens, 2=Cookies
    static std::string g_selectedId = "";

    // Split view sizes
    float listHeight = ImGui::GetContentRegionAvail().y * 0.65f;
    float detailHeight = ImGui::GetContentRegionAvail().y - listHeight - 8.0f;

    if (ImGui::BeginTabBar("CatcherTabs")) {

        // ── Credentials Tab ───────────────────────────────────
        if (ImGui::BeginTabItem("Credentials")) {
            if (g_selectedTab != 0) { g_selectedTab = 0; g_selectedId = ""; }

            ImGui::Checkbox("Reveal Passwords", &g_revealPasswords);
            ImGui::SameLine();
            if (ImGui::Button("Clear##creds")) { g_creds.clear(); g_selectedId = ""; }
            ImGui::Separator();

            if (g_creds.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1.0f), "  No credentials captured yet.");
                ImGui::TextColored(ImVec4(0.4f,0.4f,0.4f,1.0f),
                    "  Login attempts (POST /login, /auth) will appear here automatically.");
            } else {
                ImGui::BeginChild("CredsList", ImVec2(0, listHeight), true);
                if (ImGui::BeginTable("CredsTable", 4,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupScrollFreeze(0,1);
                    ImGui::TableSetupColumn("Time",     ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("Host",     ImGuiTableColumnFlags_WidthStretch, 0.35f);
                    ImGui::TableSetupColumn("Username", ImGuiTableColumnFlags_WidthStretch, 0.3f);
                    ImGui::TableSetupColumn("Password", ImGuiTableColumnFlags_WidthStretch, 0.35f);
                    ImGui::TableHeadersRow();

                    for (auto& c : g_creds) {
                        std::string rowId = c.host + "|" + c.username;
                        bool isSelected = (g_selectedId == rowId);
                        
                        ImGui::TableNextRow();
                        if (isSelected) {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImColor(40, 60, 90, 255));
                        }

                        // Time
                        ImGui::TableSetColumnIndex(0);
                        char tbuf[32]; time_t ts = (time_t)c.ts;
                        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&ts));
                        std::string selLabel = std::string(tbuf) + "##cred_" + rowId;
                        if (ImGui::Selectable(selLabel.c_str(), isSelected, ImGuiSelectableFlags_SpanAllColumns)) {
                            g_selectedId = rowId;
                        }
                        
                        // Host
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextColored(ImVec4(0.4f,0.9f,1.0f,1.0f), "%s", c.host.c_str());
                        
                        // Username
                        ImGui::TableSetColumnIndex(2);
                        if (!c.username.empty())
                            ImGui::TextColored(ImVec4(0.3f,1.0f,0.5f,1.0f), "%s", c.username.c_str());
                        else
                            ImGui::TextDisabled("(none)");
                            
                        // Password — masked unless revealed or hovered
                        ImGui::TableSetColumnIndex(3);
                        if (!c.password.empty()) {
                            if (g_revealPasswords) {
                                ImGui::TextColored(ImVec4(1.0f,0.4f,0.4f,1.0f), "%s", c.password.c_str());
                            } else {
                                std::string masked(c.password.size(), '*');
                                ImGui::TextColored(ImVec4(0.6f,0.6f,0.6f,1.0f), "%s", masked.c_str());
                                if (ImGui::IsItemHovered()) {
                                    ImGui::SetTooltip("%s", c.password.c_str());
                                }
                            }
                        } else {
                            ImGui::TextDisabled("(none)");
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }

        // ── Tokens Tab ────────────────────────────────────────
        if (ImGui::BeginTabItem("Tokens")) {
            if (g_selectedTab != 1) { g_selectedTab = 1; g_selectedId = ""; }

            if (ImGui::Button("Clear##tokens")) { g_tokens.clear(); g_selectedId = ""; }
            ImGui::Separator();

            if (g_tokens.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1.0f), "  No tokens captured yet.");
                ImGui::TextColored(ImVec4(0.4f,0.4f,0.4f,1.0f),
                    "  OAuth Bearer tokens and JWTs will appear here automatically.");
            } else {
                ImGui::BeginChild("TokensList", ImVec2(0, listHeight), true);
                if (ImGui::BeginTable("TokensTable", 4,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupScrollFreeze(0,1);
                    ImGui::TableSetupColumn("Time",  ImGuiTableColumnFlags_WidthFixed,  70.0f);
                    ImGui::TableSetupColumn("Type",  ImGuiTableColumnFlags_WidthFixed,  55.0f);
                    ImGui::TableSetupColumn("Host",  ImGuiTableColumnFlags_WidthStretch, 0.25f);
                    ImGui::TableSetupColumn("Token", ImGuiTableColumnFlags_WidthStretch, 0.75f);
                    ImGui::TableHeadersRow();

                    for (auto& t : g_tokens) {
                        std::string rowId = t.host + "|" + t.token;
                        bool isSelected = (g_selectedId == rowId);
                        
                        ImGui::TableNextRow();
                        if (isSelected) {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImColor(40, 60, 90, 255));
                        }
                        
                        ImGui::TableSetColumnIndex(0);
                        char tbuf[32]; time_t ts = (time_t)t.ts;
                        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&ts));
                        std::string selLabel = std::string(tbuf) + "##tok_" + rowId;
                        if (ImGui::Selectable(selLabel.c_str(), isSelected, ImGuiSelectableFlags_SpanAllColumns)) {
                            g_selectedId = rowId;
                        }

                        ImGui::TableSetColumnIndex(1);
                        ImVec4 typeCol = t.tokenType == "JWT"
                            ? ImVec4(1.0f, 0.6f, 0.2f, 1.0f)
                            : ImVec4(0.6f, 0.4f, 1.0f, 1.0f);
                        ImGui::TextColored(typeCol, "%s", t.tokenType.c_str());

                        ImGui::TableSetColumnIndex(2);
                        ImGui::TextColored(ImVec4(0.4f,0.9f,1.0f,1.0f), "%s", t.host.c_str());

                        ImGui::TableSetColumnIndex(3);
                        std::string display = t.token.size() > 60
                            ? t.token.substr(0, 60) + "..." : t.token;
                        ImGui::TextColored(ImVec4(0.85f,0.85f,0.85f,1.0f), "%s", display.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }

        // ── Cookies Tab ───────────────────────────────────────
        if (ImGui::BeginTabItem("Cookies")) {
            if (g_selectedTab != 2) { g_selectedTab = 2; g_selectedId = ""; }

            if (ImGui::Button("Clear##cookies")) { g_cookies.clear(); g_selectedId = ""; }
            ImGui::Separator();

            if (g_cookies.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1.0f), "  No cookies captured yet.");
                ImGui::TextColored(ImVec4(0.4f,0.4f,0.4f,1.0f),
                    "  Authentication cookies will appear here automatically.");
            } else {
                ImGui::BeginChild("CookiesList", ImVec2(0, listHeight), true);
                if (ImGui::BeginTable("CookiesTable", 3,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupScrollFreeze(0,1);
                    ImGui::TableSetupColumn("Time",    ImGuiTableColumnFlags_WidthFixed,  70.0f);
                    ImGui::TableSetupColumn("Host",    ImGuiTableColumnFlags_WidthStretch, 0.3f);
                    ImGui::TableSetupColumn("Cookies", ImGuiTableColumnFlags_WidthStretch, 0.7f);
                    ImGui::TableHeadersRow();

                    for (auto& ck : g_cookies) {
                        std::string rowId = ck.host;
                        bool isSelected = (g_selectedId == rowId);
                        
                        ImGui::TableNextRow();
                        if (isSelected) {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImColor(40, 60, 90, 255));
                        }
                        
                        ImGui::TableSetColumnIndex(0);
                        char tbuf[32]; time_t ts = (time_t)ck.ts;
                        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&ts));
                        std::string selLabel = std::string(tbuf) + "##cookie_" + rowId;
                        if (ImGui::Selectable(selLabel.c_str(), isSelected, ImGuiSelectableFlags_SpanAllColumns)) {
                            g_selectedId = rowId;
                        }

                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextColored(ImVec4(0.4f,0.9f,1.0f,1.0f), "%s", ck.host.c_str());

                        ImGui::TableSetColumnIndex(2);
                        std::string display = ck.cookies.size() > 80
                            ? ck.cookies.substr(0, 80) + "..." : ck.cookies;
                        ImGui::TextUnformatted(display.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    // ── Bottom Detail Pane ────────────────────────────────────
    ImGui::Spacing();
    ImGui::Separator();
    
    if (g_selectedId.empty()) {
        ImGui::TextDisabled("Select an item above to view details.");
        return;
    }

    ImGui::BeginChild("VaultDetailPane", ImVec2(0, 0), true);

    if (g_selectedTab == 0) { // Creds
        const CredEntry* sel = nullptr;
        for (auto& c : g_creds) if (c.host + "|" + c.username == g_selectedId) { sel = &c; break; }
        if (sel) {
            ImGui::TextColored(ImVec4(1.0f,0.4f,0.4f,1.0f), "[CREDENTIAL DETAILS]");
            ImGui::Separator();
            ImGui::TextDisabled("Host: "); ImGui::SameLine(); ImGui::Text("%s", sel->host.c_str());
            ImGui::TextDisabled("User: "); ImGui::SameLine(); ImGui::TextColored(ImVec4(0.3f,1.0f,0.5f,1.0f), "%s", sel->username.c_str());
            ImGui::TextDisabled("Pass: "); ImGui::SameLine(); ImGui::TextColored(ImVec4(1.0f,0.4f,0.4f,1.0f), "%s", sel->password.c_str());
            ImGui::Spacing();
            if (ImGui::Button("Copy Password")) ImGui::SetClipboardText(sel->password.c_str());
            ImGui::SameLine();
            if (ImGui::Button("Copy Username")) ImGui::SetClipboardText(sel->username.c_str());
        } else {
            g_selectedId = "";
        }
    } 
    else if (g_selectedTab == 1) { // Tokens
        const TokenEntry* sel = nullptr;
        for (auto& t : g_tokens) if (t.host + "|" + t.token == g_selectedId) { sel = &t; break; }
        if (sel) {
            ImGui::TextColored(ImVec4(1.0f,0.6f,0.2f,1.0f), "[TOKEN DETAILS]");
            ImGui::SameLine(ImGui::GetContentRegionAvail().x - 100);
            if (ImGui::Button("Copy Token")) ImGui::SetClipboardText(sel->token.c_str());
            ImGui::Separator();
            
            ImGui::TextDisabled("Host: "); ImGui::SameLine(); ImGui::Text("%s", sel->host.c_str());
            ImGui::TextDisabled("Type: "); ImGui::SameLine(); ImGui::TextColored(ImVec4(0.8f,0.5f,1.0f,1.0f), "%s", sel->tokenType.c_str());
            ImGui::Spacing();
            ImGui::TextDisabled("Raw Token:");
            
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.08f, 0.08f, 1.0f));
            // Fix: pass valid buffer size (+1) and use a local copy to avoid modifying c_str (even though it's read-only)
            std::string tokenCopy = sel->token;
            tokenCopy.resize(tokenCopy.size() + 1);
            ImGui::InputTextMultiline("##tkview", &tokenCopy[0], tokenCopy.size(), 
                ImVec2(-FLT_MIN, ImGui::GetContentRegionAvail().y - 30.0f), ImGuiInputTextFlags_ReadOnly);
            ImGui::PopStyleColor();
            
            if (sel->tokenType == "JWT" && ImGui::Button("Decrypt JWT payload")) {
                // Future expansion: auto base64-decode the middle payload
                // Could spawn a popup or modify the display
            }
        } else {
            g_selectedId = "";
        }
    }
    else if (g_selectedTab == 2) { // Cookies
        const CookieEntry* sel = nullptr;
        for (auto& ck : g_cookies) if (ck.host == g_selectedId) { sel = &ck; break; }
        if (sel) {
            ImGui::TextColored(ImVec4(0.4f,0.9f,1.0f,1.0f), "[COOKIE DETAILS]");
            ImGui::SameLine(ImGui::GetContentRegionAvail().x - 100);
            if (ImGui::Button("Copy Cookies")) ImGui::SetClipboardText(sel->cookies.c_str());
            ImGui::SameLine();
            if (ImGui::Button("Export to TXT")) {
                std::string path = "recordings/cookies_" + sel->host + "_" + std::to_string(time(NULL)) + ".txt";
                FILE* f = fopen(path.c_str(), "w");
                if (f) {
                    fprintf(f, "Host: %s\n\n%s\n", sel->host.c_str(), sel->cookies.c_str());
                    fclose(f);
                }
            }
            ImGui::Separator();
            
            ImGui::TextDisabled("Host: "); ImGui::SameLine(); ImGui::Text("%s", sel->host.c_str());
            ImGui::Spacing();
            
            if (ImGui::BeginTabBar("CookieDetailTabs")) {
                if (ImGui::BeginTabItem("Parsed Table")) {
                    ImGui::BeginChild("CookieTableChild", ImVec2(0, 0), true);
                    if (ImGui::BeginTable("ParsedCookiesTable", 3,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
                        ImGui::TableSetupScrollFreeze(0, 1);
                        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        auto pairs = SplitString(sel->cookies, ';');
                        for (const auto& pair : pairs) {
                            if (pair.empty()) continue;
                            size_t eq = pair.find('=');
                            std::string key = (eq != std::string::npos) ? pair.substr(0, eq) : pair;
                            std::string val = (eq != std::string::npos) ? pair.substr(eq + 1) : "";
                            
                            std::string keyLower = key;
                            for (char& c : keyLower) c = tolower(c);

                            // Determine type/color
                            std::string typeStr = "Standard";
                            ImVec4 color = ImVec4(0.7f, 0.7f, 0.7f, 1.0f);
                            
                            if (keyLower.find("session") != std::string::npos || 
                                keyLower.find("auth") != std::string::npos ||
                                keyLower.find("token") != std::string::npos ||
                                keyLower.find("sid") != std::string::npos ||
                                keyLower.find("jwt") != std::string::npos ||
                                keyLower.find("__host-") != std::string::npos ||
                                keyLower.find("__secure-") != std::string::npos) {
                                typeStr = "Auth / Session";
                                color = ImVec4(0.3f, 1.0f, 0.5f, 1.0f); // Green
                            } else if (keyLower.find("_ga") != std::string::npos ||
                                       keyLower.find("analytics") != std::string::npos ||
                                       keyLower.find("track") != std::string::npos ||
                                       keyLower == "_fbp" || keyLower == "_gcl_au") {
                                typeStr = "Tracking";
                                color = ImVec4(1.0f, 0.6f, 0.2f, 1.0f); // Orange
                            } else if (keyLower.find("cf_") != std::string::npos || 
                                       keyLower.find("__cf") != std::string::npos) {
                                typeStr = "Security / WAF";
                                color = ImVec4(0.4f, 0.8f, 1.0f, 1.0f); // Blue
                            } else if (keyLower == "lang" || keyLower == "theme") {
                                typeStr = "Preference";
                                color = ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
                            }

                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::TextColored(color, "%s", key.c_str());
                            
                            ImGui::TableSetColumnIndex(1);
                            ImGui::TextColored(color, "%s", typeStr.c_str());
                            
                            ImGui::TableSetColumnIndex(2);
                            ImGui::TextWrapped("%s", val.c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }
                
                if (ImGui::BeginTabItem("Raw String")) {
                    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.08f, 0.08f, 1.0f));
                    std::string cookieCopy = sel->cookies;
                    cookieCopy.resize(cookieCopy.size() + 1);
                    ImGui::InputTextMultiline("##ckview", &cookieCopy[0], cookieCopy.size(), 
                        ImVec2(-FLT_MIN, ImGui::GetContentRegionAvail().y - 10.0f), ImGuiInputTextFlags_ReadOnly);
                    ImGui::PopStyleColor();
                    ImGui::EndTabItem();
                }
                
                ImGui::EndTabBar();
            }
        } else {
            g_selectedId = "";
        }
    }

    ImGui::EndChild();
}
