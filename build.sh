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
SRC_ANALYSIS="analysis/traffic_analyzer.cpp analysis/flow_pipeline.cpp analysis/domain_cache.cpp analysis/modules/stream_detector.cpp analysis/modules/api_detector.cpp analysis/modules/tracker_detector.cpp analysis/modules/auth_detector.cpp analysis/modules/risk_analyzer.cpp analysis/modules/mime_classifier.cpp analysis/modules/websocket_analyzer.cpp"
SRC_SQLITE="third_party/sqlite/sqlite3.c"
OBJ_SQLITE="sqlite3.o"
SRC_MAIN="main.cpp"
SRC_PROXY="core/proxy_reader.cpp"

SRC_IMGUI="imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp imgui/imgui_impl_glfw.cpp imgui/imgui_impl_opengl3.cpp"
SRC_UI="ui/main_ui.cpp ui/theme.cpp ui/panels/main_panel.cpp ui/panels/inspector_panel.cpp ui/panels/rules_panel.cpp ui/panels/rule_editor_modal.cpp ui/panels/rule_runtime_panel.cpp ui/panels/session_panel.cpp ui/panels/settings_panel.cpp ui/panels/catcher_panel.cpp"
SRC_RULES="rules/rule_manager.cpp"
SRC_PROXY="core/proxy_reader.cpp"
SRC_SETTINGS="core/settings_persist.cpp"
SRC_SYSPROXY="core/system_proxy.cpp"
SRC_BACKEND="backend/runtime_health.cpp"
SRC_UTILS="utils/structured_log.cpp"

# ── Output layout ──────────────────────────────────────────
RELEASE_DIR="release"
OUTPUT="${RELEASE_DIR}/NetSense.exe"

mkdir -p "${RELEASE_DIR}/proxy"
mkdir -p "${RELEASE_DIR}/recordings"

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
  -lcomdlg32
  -luser32
  -lkernel32
  -lwininet
  -lglfw3
  -lopengl32
)

echo "[*] Compiling SQLite3 (C library)..."
gcc -O2 -c "$SRC_SQLITE" -o "$OBJ_SQLITE"

echo "[*] Compiling Windows Resources (UAC Administrator Manifest)..."
windres resources.rc -O coff -o resources.o

echo "[*] Building NetSense+ (ImGui Version)..."
g++ "${FLAGS[@]}" \
    "$SRC_MAIN" \
    "$SRC_CORE" \
    "$SRC_DNS"  \
    "$SRC_PROC" \
    "$SRC_PROXY" \
    "$SRC_DB" \
    $SRC_ANALYSIS \
    "$SRC_SETTINGS" \
    "$SRC_SYSPROXY" \
    "$SRC_BACKEND" \
    "$SRC_UTILS" \
    "$OBJ_SQLITE" \
    resources.o \
    "$SRC_RULES" \
    $SRC_UI   \
    $SRC_IMGUI \
    "${LIBS[@]}" \
    -o "$OUTPUT"

echo "[+] Build successful: $OUTPUT"
rm -f "$OBJ_SQLITE" resources.o

# ── Copy runtime files into release/ ───────────────────────
echo "[*] Copying proxy runtime files to ${RELEASE_DIR}/proxy/ ..."
cp -u proxy/netsense_addon.py    "${RELEASE_DIR}/proxy/"
cp -u proxy/rule_engine.py       "${RELEASE_DIR}/proxy/"
cp -u proxy/predefined_packs.py  "${RELEASE_DIR}/proxy/"
cp -u proxy/predefined_packs.json "${RELEASE_DIR}/proxy/"
# rules.json is generated at runtime; seed with empty array if missing
[ -f "${RELEASE_DIR}/proxy/rules.json" ] || echo "[]" > "${RELEASE_DIR}/proxy/rules.json"

# Copy mitmdump.exe if present in project root (common location after pip install)
if [ -f "mitmdump.exe" ]; then
    cp -u mitmdump.exe "${RELEASE_DIR}/"
    echo "[*] Copied mitmdump.exe -> ${RELEASE_DIR}/mitmdump.exe"
fi

echo ""
echo "========================================="
echo "  Release layout:"
echo "  ${RELEASE_DIR}/"
echo "    NetSense.exe          <- main app"
echo "    mitmdump.exe          <- mitmproxy (place here)"
echo "    proxy/"
echo "      netsense_addon.py   <- mitmproxy addon"
echo "      rule_engine.py      <- rule execution"
echo "      rules.json          <- live rules (auto-generated)"
echo "      predefined_packs.json"
echo "      netsense_proxy.log  <- written at runtime"
echo "      netsense_alerts.log <- written at runtime"
echo "    recordings/           <- session exports"
echo "========================================="
echo "[!] Run NetSense.exe as Administrator for full packet access."
