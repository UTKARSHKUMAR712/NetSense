#include "panels.h"
#include "../../imgui/imgui.h"
#include "../../core/app_data.h"

void RenderCatcherPanel() {
    ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "NetSense+ 3.0 Auto-Capture Vault");
    ImGui::Separator();
    
    if (ImGui::BeginTabBar("CatcherTabs")) {
        if (ImGui::BeginTabItem("Credentials")) {
            ImGui::Text("Captured Logins & Passwords will appear here.");
            // To be implemented fully in Phase 4
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Tokens")) {
            ImGui::Text("Captured OAuth and Session Tokens will appear here.");
            // To be implemented fully in Phase 4
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Cookies")) {
            ImGui::Text("Captured Cookies will appear here.");
            // To be implemented fully in Phase 4
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}
