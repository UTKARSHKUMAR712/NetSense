#include "../../imgui/imgui.h"
#include "../../core/app_data.h"

void RenderMobilePanel() {
    std::lock_guard<std::mutex> lk(g_state.mtx);
    ImGui::TextColored(ImVec4(0, 0.8f, 0.6f, 1), "Mobile Interception Setup (Phase 9)");
    ImGui::Separator();
    
    ImGui::Text("1. Connect your phone to the same Wi-Fi network as this PC.");
    ImGui::Text("2. Set your phone's HTTP Proxy to this PC's IP address and Port 8080.");
    ImGui::Text("3. Visit http://mitm.it on your phone to install the Certificate.");
    
    ImGui::Spacing();
    ImGui::TextDisabled("(QR Code generator will be implemented here later)");
}
