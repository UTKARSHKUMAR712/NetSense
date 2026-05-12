#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include "../../core/traffic_db.h"
#include <windows.h>

void RenderSettingsPanel() {
    std::lock_guard<std::mutex> lk(g_state.mtx);
    ImGui::TextColored(ImVec4(0, 0.8f, 0.6f, 1), "NetSense+ Settings");
    ImGui::Separator();
    
    ImGui::Text("Core Settings");
    ImGui::InputInt("Proxy Port", &g_settings.proxyPort);
    
    if (ImGui::SliderFloat("UI Font Size Scale", &g_settings.uiScale, 0.5f, 2.5f, "%.2fx")) {
        ImGui::GetIO().FontGlobalScale = g_settings.uiScale * 0.5f;
    }
    
    ImGui::Spacing();
    ImGui::Text("Privacy & Capture");
    ImGui::Checkbox("Capture Body Content", &g_settings.enableBodyPreview);
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Warning: Capturing body increases memory/disk usage significantly.");
    }
    
    ImGui::Checkbox("Capture Form Data", &g_settings.storeFormData);
    ImGui::Checkbox("XOR Encrypt Session Payloads (WIP)", &g_settings.encryptSensitiveFields);
    
    ImGui::Spacing();
    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Data Management");
    ImGui::Separator();
    
    if (ImGui::Button("Delete Logs Only", ImVec2(150, 0))) {
        g_state.logLines.clear();
        system("del /Q recordings\\*.txt 2>nul");
        system("del /Q proxy\\netsense_proxy.log 2>nul");
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete DB Only", ImVec2(150, 0))) {
        TrafficDB::ClearDatabase();
    }
    ImGui::SameLine();
    if (ImGui::Button("Master Clean", ImVec2(150, 0))) {
        g_state.logLines.clear();
        g_state.proxyFlows.clear();
        system("del /Q recordings\\*.txt 2>nul");
        system("del /Q proxy\\netsense_proxy.log 2>nul");
        TrafficDB::ClearDatabase();
    }
}
