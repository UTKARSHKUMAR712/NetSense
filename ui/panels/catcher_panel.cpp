#include "panels.h"
#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include <vector>
#include <string>
#include <algorithm>
#include <ctime>

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

    if (ImGui::BeginTabBar("CatcherTabs")) {

        // ── Credentials Tab ───────────────────────────────────
        if (ImGui::BeginTabItem("Credentials")) {
            ImGui::Checkbox("Reveal Passwords", &g_revealPasswords);
            ImGui::SameLine();
            if (ImGui::Button("Clear##creds")) g_creds.clear();
            ImGui::Separator();

            if (g_creds.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1.0f), "  No credentials captured yet.");
                ImGui::TextColored(ImVec4(0.4f,0.4f,0.4f,1.0f),
                    "  Login attempts (POST /login, /auth) will appear here automatically.");
            } else {
                ImGui::BeginChild("CredsList", ImVec2(0,0), false);
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
                        ImGui::TableNextRow();
                        // Time
                        ImGui::TableSetColumnIndex(0);
                        char tbuf[32]; time_t ts = (time_t)c.ts;
                        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&ts));
                        ImGui::TextDisabled("%s", tbuf);
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
                            ImGui::SameLine();
                            if (ImGui::SmallButton(("Copy##pw" + c.host + c.username).c_str())) {
                                ImGui::SetClipboardText(c.password.c_str());
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
            if (ImGui::Button("Clear##tokens")) g_tokens.clear();
            ImGui::Separator();

            if (g_tokens.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1.0f), "  No tokens captured yet.");
                ImGui::TextColored(ImVec4(0.4f,0.4f,0.4f,1.0f),
                    "  OAuth Bearer tokens and JWTs will appear here automatically.");
            } else {
                ImGui::BeginChild("TokensList", ImVec2(0,0), false);
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
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        char tbuf[32]; time_t ts = (time_t)t.ts;
                        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&ts));
                        ImGui::TextDisabled("%s", tbuf);

                        ImGui::TableSetColumnIndex(1);
                        ImVec4 typeCol = t.tokenType == "JWT"
                            ? ImVec4(1.0f, 0.6f, 0.2f, 1.0f)
                            : ImVec4(0.6f, 0.4f, 1.0f, 1.0f);
                        ImGui::TextColored(typeCol, "%s", t.tokenType.c_str());

                        ImGui::TableSetColumnIndex(2);
                        ImGui::TextColored(ImVec4(0.4f,0.9f,1.0f,1.0f), "%s", t.host.c_str());

                        ImGui::TableSetColumnIndex(3);
                        // Show truncated token inline
                        std::string display = t.token.size() > 60
                            ? t.token.substr(0, 60) + "..." : t.token;
                        ImGui::TextColored(ImVec4(0.85f,0.85f,0.85f,1.0f), "%s", display.c_str());
                        if (ImGui::IsItemHovered()) {
                            ImGui::SetTooltip("%s", t.token.c_str());
                        }
                        ImGui::SameLine();
                        if (ImGui::SmallButton(("Copy##tk" + t.host).c_str())) {
                            ImGui::SetClipboardText(t.token.c_str());
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }

        // ── Cookies Tab ───────────────────────────────────────
        if (ImGui::BeginTabItem("Cookies")) {
            if (ImGui::Button("Clear##cookies")) g_cookies.clear();
            ImGui::Separator();

            if (g_cookies.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1.0f), "  No cookies captured yet.");
                ImGui::TextColored(ImVec4(0.4f,0.4f,0.4f,1.0f),
                    "  Authentication cookies will appear here automatically.");
            } else {
                ImGui::BeginChild("CookiesList", ImVec2(0,0), false);
                if (ImGui::BeginTable("CookiesTable", 3,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupScrollFreeze(0,1);
                    ImGui::TableSetupColumn("Time",    ImGuiTableColumnFlags_WidthFixed,  70.0f);
                    ImGui::TableSetupColumn("Host",    ImGuiTableColumnFlags_WidthStretch, 0.3f);
                    ImGui::TableSetupColumn("Cookies", ImGuiTableColumnFlags_WidthStretch, 0.7f);
                    ImGui::TableHeadersRow();

                    for (auto& ck : g_cookies) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        char tbuf[32]; time_t ts = (time_t)ck.ts;
                        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&ts));
                        ImGui::TextDisabled("%s", tbuf);

                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextColored(ImVec4(0.4f,0.9f,1.0f,1.0f), "%s", ck.host.c_str());

                        ImGui::TableSetColumnIndex(2);
                        std::string display = ck.cookies.size() > 80
                            ? ck.cookies.substr(0, 80) + "..." : ck.cookies;
                        ImGui::TextUnformatted(display.c_str());
                        if (ImGui::IsItemHovered()) {
                            ImGui::SetTooltip("%s", ck.cookies.c_str());
                        }
                        ImGui::SameLine();
                        if (ImGui::SmallButton(("Copy##ck" + ck.host).c_str())) {
                            ImGui::SetClipboardText(ck.cookies.c_str());
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }
}
