#include "../imgui/imgui.h"

void SetupTheme() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    // Dark Hacker Theme
    colors[ImGuiCol_Text]                   = ImVec4(0.80f, 0.85f, 0.80f, 1.00f);
    colors[ImGuiCol_TextDisabled]           = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
    colors[ImGuiCol_WindowBg]               = ImVec4(0.04f, 0.05f, 0.08f, 1.00f);
    colors[ImGuiCol_ChildBg]                = ImVec4(0.06f, 0.08f, 0.12f, 1.00f);
    colors[ImGuiCol_PopupBg]                = ImVec4(0.08f, 0.10f, 0.15f, 0.94f);
    colors[ImGuiCol_Border]                 = ImVec4(0.00f, 0.82f, 0.55f, 0.30f);
    colors[ImGuiCol_BorderShadow]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]                = ImVec4(0.08f, 0.12f, 0.18f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.00f, 0.82f, 0.55f, 0.40f);
    colors[ImGuiCol_FrameBgActive]          = ImVec4(0.00f, 0.82f, 0.55f, 0.60f);
    colors[ImGuiCol_TitleBg]                = ImVec4(0.04f, 0.05f, 0.08f, 1.00f);
    colors[ImGuiCol_TitleBgActive]          = ImVec4(0.00f, 0.82f, 0.55f, 0.80f);
    colors[ImGuiCol_TitleBgCollapsed]       = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
    colors[ImGuiCol_MenuBarBg]              = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]            = ImVec4(0.02f, 0.02f, 0.02f, 0.53f);
    colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.31f, 0.31f, 0.31f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.41f, 0.41f, 0.41f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
    colors[ImGuiCol_CheckMark]              = ImVec4(0.00f, 0.82f, 0.55f, 1.00f);
    colors[ImGuiCol_SliderGrab]             = ImVec4(0.00f, 0.82f, 0.55f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]       = ImVec4(0.00f, 0.82f, 0.55f, 1.00f);
    colors[ImGuiCol_Button]                 = ImVec4(0.08f, 0.14f, 0.22f, 1.00f);
    colors[ImGuiCol_ButtonHovered]          = ImVec4(0.00f, 0.82f, 0.55f, 0.80f);
    colors[ImGuiCol_ButtonActive]           = ImVec4(0.00f, 0.82f, 0.55f, 1.00f);
    colors[ImGuiCol_Header]                 = ImVec4(0.00f, 0.82f, 0.55f, 0.31f);
    colors[ImGuiCol_HeaderHovered]          = ImVec4(0.00f, 0.82f, 0.55f, 0.80f);
    colors[ImGuiCol_HeaderActive]           = ImVec4(0.00f, 0.82f, 0.55f, 1.00f);
    colors[ImGuiCol_Tab]                    = ImVec4(0.08f, 0.12f, 0.18f, 1.00f);
    colors[ImGuiCol_TabHovered]             = ImVec4(0.00f, 0.82f, 0.55f, 0.80f);
    colors[ImGuiCol_TabActive]              = ImVec4(0.00f, 0.82f, 0.55f, 0.60f);

    style.WindowRounding = 4.0f;
    style.ChildRounding = 4.0f;
    style.FrameRounding = 3.0f;
    style.GrabRounding = 3.0f;
    style.PopupRounding = 4.0f;
    style.ScrollbarRounding = 9.0f;
}
