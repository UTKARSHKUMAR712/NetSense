#!/usr/bin/env bash
# ============================================================
#  NetSense+ build script  — MSYS2 UCRT64 / MinGW g++
#  Run from the Netsense/ project root inside MSYS2 terminal:
#    bash build.sh
# ============================================================

set -e

SRC_CORE="core/network_monitor.cpp"
SRC_DNS="dns/dns_resolver.cpp"
SRC_PROC="process/process_mapper.cpp"
SRC_DB="core/traffic_db.cpp"
SRC_ANALYSIS="analysis/traffic_analyzer.cpp"
SRC_SQLITE="third_party/sqlite/sqlite3.c"
OBJ_SQLITE="sqlite3.o"
SRC_MAIN="main.cpp"
SRC_PROXY="core/proxy_reader.cpp"

SRC_IMGUI="imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp imgui/imgui_impl_glfw.cpp imgui/imgui_impl_opengl3.cpp"
SRC_UI="ui/main_ui.cpp ui/theme.cpp ui/panels/main_panel.cpp ui/panels/inspector_panel.cpp ui/panels/rules_panel.cpp ui/panels/session_panel.cpp ui/panels/mobile_panel.cpp ui/panels/settings_panel.cpp"
SRC_RULES="rules/rule_manager.cpp"
SRC_PROXY="core/proxy_reader.cpp"

OUTPUT="NetSense.exe"

FLAGS=(
  -std=c++20
  -O2
  -static
  -static-libgcc
  -static-libstdc++
  -mwindows
  -DWIN32_LEAN_AND_MEAN
  -DNOMINMAX
  -D_WIN32_WINNT=0x0600
  -I.
)

LIBS=(
  -lws2_32
  -ladvapi32
  -liphlpapi
  -lpsapi
  -lgdi32
  -lcomctl32
  -luser32
  -lkernel32
  -lglfw3
  -lopengl32
)

echo "[*] Compiling SQLite3 (C library)..."
gcc -O2 -c "$SRC_SQLITE" -o "$OBJ_SQLITE"

echo "[*] Building NetSense+ (ImGui Version)..."
g++ "${FLAGS[@]}" \
    "$SRC_MAIN" \
    "$SRC_CORE" \
    "$SRC_DNS"  \
    "$SRC_PROC" \
    "$SRC_PROXY" \
    "$SRC_DB" \
    "$SRC_ANALYSIS" \
    "$OBJ_SQLITE" \
    "$SRC_RULES" \
    $SRC_UI   \
    $SRC_IMGUI \
    "${LIBS[@]}" \
    -o "$OUTPUT"

echo "[+] Build successful: $OUTPUT"
rm -f "$OBJ_SQLITE"
echo "[!] Run as Administrator for full packet access."
