#include "risk_analyzer.h"
#include <algorithm>

// ─────────────────────────────────────────────────────────────
// Suspicious TLDs: often used for phishing / malware domains
// ─────────────────────────────────────────────────────────────
static const char* kSuspiciousTlds[] = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".click", ".bid", ".link", ".work",
    ".party", ".review", ".download", ".science",
    nullptr
};

bool RiskAnalyzerModule::IsPlaintext(const ProxyFlow& flow) {
    return flow.port == 80 || !flow.tls_valid;
}

bool RiskAnalyzerModule::IsSuspiciousTld(const std::string& host) {
    std::string h = host;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    for (int i = 0; kSuspiciousTlds[i] != nullptr; ++i) {
        // Check if host ends with this TLD
        std::string tld(kSuspiciousTlds[i]);
        if (h.size() >= tld.size() &&
            h.compare(h.size() - tld.size(), tld.size(), tld) == 0) {
            return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────
// Risk scoring runs AFTER all other detectors.
// Only upgrades risk level, never downgrades.
// ─────────────────────────────────────────────────────────────
static int RiskWeight(const std::string& r) {
    if (r == "CRITICAL") return 4;
    if (r == "HIGH")     return 3;
    if (r == "MEDIUM")   return 2;
    if (r == "LOW")      return 1;
    return 0;
}

static void SetRisk(ProxyFlow& flow, const std::string& level) {
    if (RiskWeight(level) > RiskWeight(flow.insight.riskLevel)) {
        flow.insight.riskLevel = level;
    }
}

void RiskAnalyzerModule::Analyze(ProxyFlow& flow) {
    bool plaintext = IsPlaintext(flow);
    bool hasCreds  = !flow.insight.vaultPayload.password.empty() ||
                     !flow.insight.vaultPayload.username.empty();
    bool hasToken  = !flow.insight.vaultPayload.bearerToken.empty();
    bool suspTld   = IsSuspiciousTld(flow.host);

    // ── CRITICAL: cleartext credentials ──────────────────────
    if (hasCreds && plaintext) {
        SetRisk(flow, "CRITICAL");
        flow.insight.isSuspicious = true;
        flow.insight.tags.push_back("[RISK:CRITICAL]");
        return;
    }

    // ── CRITICAL: token over unencrypted connection ───────────
    if (hasToken && plaintext) {
        SetRisk(flow, "CRITICAL");
        flow.insight.isSuspicious = true;
        flow.insight.tags.push_back("[RISK:CRITICAL]");
        return;
    }

    // ── HIGH: suspicious TLD + any auth or creds ─────────────
    if (suspTld && (flow.insight.isAuth || hasCreds)) {
        SetRisk(flow, "HIGH");
        flow.insight.isSuspicious = true;
        flow.insight.tags.push_back("[RISK:HIGH]");
        return;
    }

    // ── HIGH: credentials over HTTPS ─────────────────────────
    if (hasCreds && !plaintext) {
        SetRisk(flow, "HIGH");
        flow.insight.tags.push_back("[RISK:HIGH]");
        return;
    }

    // ── MEDIUM: tracker + sensitive data ─────────────────────
    if (flow.insight.isTracker && flow.insight.isAuth) {
        SetRisk(flow, "MEDIUM");
        flow.insight.tags.push_back("[RISK:MEDIUM]");
        return;
    }

    // ── MEDIUM: any plaintext API ─────────────────────────────
    if (plaintext && flow.insight.isAPI) {
        SetRisk(flow, "MEDIUM");
        flow.insight.tags.push_back("[RISK:MEDIUM]");
        return;
    }

    // ── MEDIUM: suspicious TLD ────────────────────────────────
    if (suspTld) {
        SetRisk(flow, "MEDIUM");
        flow.insight.isSuspicious = true;
        flow.insight.tags.push_back("[RISK:MEDIUM]");
        return;
    }

    // ── LOW: normal encrypted traffic ────────────────────────
    if (!plaintext && flow.insight.riskLevel.empty()) {
        flow.insight.riskLevel = "LOW";
    }
}
