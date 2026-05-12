#pragma once
// ============================================================
//  backend/plugin_caps.h — Plugin Capability Flags
//  Even before plugins exist, define the sandbox boundary now.
//  Future addons/plugins declare which capabilities they need.
//  The runtime can deny capabilities based on trust level.
//  Reusable: identical model for WiFi Analyzer addons, etc.
// ============================================================
#include <cstdint>
#include <string>
#include <vector>

// ── Capability flags (bitmask) ────────────────────────────────
enum class Capability : uint32_t {
    None              = 0,

    // Traffic access
    ReadFlowHeaders   = 1 << 0,  // Can read req/rsp headers
    ReadFlowBodies    = 1 << 1,  // Can read req/rsp bodies
    ModifyFlowHeaders = 1 << 2,  // Can inject/replace headers
    ModifyFlowBodies  = 1 << 3,  // Can modify response bodies
    BlockFlows        = 1 << 4,  // Can kill connections
    RedirectFlows     = 1 << 5,  // Can redirect requests

    // Storage access
    ReadDB            = 1 << 6,  // Can query SQLite history
    WriteDB           = 1 << 7,  // Can write to SQLite
    ReadFiles         = 1 << 8,  // Can read files from disk
    WriteFiles        = 1 << 9,  // Can write files to disk

    // System access
    LaunchProcesses   = 1 << 10, // Can spawn child processes
    ModifySystemProxy = 1 << 11, // Can change WinInet proxy settings
    ReadProcessList   = 1 << 12, // Can enumerate running processes

    // UI access
    RenderUI          = 1 << 13, // Can add ImGui panel
    EmitNotifications = 1 << 14, // Can post alerts to UI

    // Networking
    RawSocketAccess   = 1 << 15, // Can open raw sockets (elevated)
    DNSAccess         = 1 << 16, // Can query/modify DNS

    // Predefined profiles
    ReadOnly          = ReadFlowHeaders | ReadDB | ReadFiles,
    Standard          = ReadOnly | ModifyFlowHeaders | WriteDB |
                        RenderUI | EmitNotifications,
    Privileged        = Standard | ModifyFlowBodies | BlockFlows |
                        RedirectFlows | WriteFiles | LaunchProcesses,
    Unrestricted      = 0xFFFFFFFF
};

inline Capability operator|(Capability a, Capability b) {
    return static_cast<Capability>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline Capability operator&(Capability a, Capability b) {
    return static_cast<Capability>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline bool HasCap(Capability set, Capability cap) {
    return (static_cast<uint32_t>(set) & static_cast<uint32_t>(cap)) != 0;
}

// ── Trust levels ──────────────────────────────────────────────
enum class TrustLevel { Untrusted, Community, Verified, Internal };

// ── Plugin manifest (future use) ─────────────────────────────
struct PluginManifest {
    std::string   id;
    std::string   name;
    std::string   version;
    std::string   author;
    TrustLevel    trust      = TrustLevel::Untrusted;
    Capability    requested  = Capability::None;  // what plugin asks for
    Capability    granted    = Capability::None;  // what runtime allows
};

// ── Capability strings (for logging/UI) ──────────────────────
inline std::vector<std::string> CapabilityNames(Capability caps) {
    std::vector<std::string> result;
    auto check = [&](Capability c, const char* name) {
        if (HasCap(caps, c)) result.push_back(name);
    };
    check(Capability::ReadFlowHeaders,   "ReadFlowHeaders");
    check(Capability::ReadFlowBodies,    "ReadFlowBodies");
    check(Capability::ModifyFlowHeaders, "ModifyFlowHeaders");
    check(Capability::ModifyFlowBodies,  "ModifyFlowBodies");
    check(Capability::BlockFlows,        "BlockFlows");
    check(Capability::RedirectFlows,     "RedirectFlows");
    check(Capability::ReadDB,            "ReadDB");
    check(Capability::WriteDB,           "WriteDB");
    check(Capability::ReadFiles,         "ReadFiles");
    check(Capability::WriteFiles,        "WriteFiles");
    check(Capability::LaunchProcesses,   "LaunchProcesses");
    check(Capability::ModifySystemProxy, "ModifySystemProxy");
    check(Capability::ReadProcessList,   "ReadProcessList");
    check(Capability::RenderUI,          "RenderUI");
    check(Capability::EmitNotifications, "EmitNotifications");
    check(Capability::RawSocketAccess,   "RawSocketAccess");
    check(Capability::DNSAccess,         "DNSAccess");
    return result;
}
