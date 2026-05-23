#include "auth_detector.h"
#include <algorithm>

static bool ci_contains(const std::string& h, const std::string& n) {
    std::string a = h, b = n;
    std::transform(a.begin(), a.end(), a.begin(), ::tolower);
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    return a.find(b) != std::string::npos;
}

// ─────────────────────────────────────────────────────────────
// JWT check: must have 2 dots and be > 20 chars
// ─────────────────────────────────────────────────────────────
bool AuthDetectorModule::LooksLikeJwt(const std::string& token) {
    if (token.size() < 20) return false;
    int dots = 0;
    for (char c : token) if (c == '.') ++dots;
    return dots == 2;
}

bool AuthDetectorModule::HasBearerToken(const ProxyFlow& flow) {
    // Vault data already has it extracted
    return !flow.insight.vaultPayload.bearerToken.empty() ||
           ci_contains(flow.raw_req_headers, "bearer ");
}

bool AuthDetectorModule::HasBasicAuth(const ProxyFlow& flow) {
    return ci_contains(flow.raw_req_headers, "basic ") ||
           ci_contains(flow.url, "Authorization=Basic");
}

bool AuthDetectorModule::HasSessionCookie(const ProxyFlow& flow) {
    return ci_contains(flow.cookies, "session") ||
           ci_contains(flow.cookies, "token")   ||
           ci_contains(flow.cookies, "auth")    ||
           ci_contains(flow.cookies, "jwt")     ||
           !flow.insight.vaultPayload.authCookies.empty();
}

bool AuthDetectorModule::IsLoginEndpoint(const ProxyFlow& flow) {
    return (flow.method == "POST") && (
        ci_contains(flow.url, "/login")   ||
        ci_contains(flow.url, "/signin")  ||
        ci_contains(flow.url, "/auth")    ||
        ci_contains(flow.url, "/oauth")   ||
        ci_contains(flow.url, "/token")   ||
        ci_contains(flow.url, "/session") ||
        ci_contains(flow.url, "/account/login")
    );
}

void AuthDetectorModule::Analyze(ProxyFlow& flow) {
    bool detected = false;
    std::string authType;

    if (HasBearerToken(flow)) {
        detected = true;
        // Distinguish OAuth2 JWT vs plain token
        if (LooksLikeJwt(flow.insight.vaultPayload.bearerToken)) {
            authType = "OAuth2/JWT";
            flow.insight.tags.push_back("[AUTH:JWT]");
        } else {
            authType = "Bearer Token";
            flow.insight.tags.push_back("[AUTH:TOKEN]");
        }
    } else if (HasBasicAuth(flow)) {
        detected = true;
        authType = "Basic Auth";
        flow.insight.tags.push_back("[AUTH:BASIC]");
        // Basic Auth over HTTP is CRITICAL
        if (flow.port == 80 || !flow.tls_valid) {
            flow.insight.riskLevel = "CRITICAL";
        }
    } else if (IsLoginEndpoint(flow)) {
        detected = true;
        authType = "Form Login";
        flow.insight.tags.push_back("[AUTH:LOGIN]");
        // Cleartext password over HTTP is CRITICAL
        if (!flow.insight.vaultPayload.password.empty() && !flow.tls_valid) {
            flow.insight.riskLevel = "CRITICAL";
        } else if (!flow.insight.vaultPayload.password.empty()) {
            // Password over HTTPS is still HIGH interest
            if (flow.insight.riskLevel.empty()) flow.insight.riskLevel = "HIGH";
        }
    } else if (HasSessionCookie(flow)) {
        detected = true;
        authType = "Session Cookie";
        flow.insight.tags.push_back("[AUTH:COOKIE]");
    }

    if (detected) {
        flow.insight.isAuth = true;
        flow.insight.authType = authType;
    }
}
