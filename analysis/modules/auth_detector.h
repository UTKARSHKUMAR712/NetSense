#pragma once
#include "../flow_pipeline.h"

// ── Auth Detector Module ──────────────────────────────────────
// Scrapes authentication signals: OAuth Bearer tokens, JWTs,
// Basic Auth, session cookies, and form-based login attempts.
// Sets insight.isAuth = true and populates insight.authType.
class AuthDetectorModule : public IAnalyzerModule {
public:
    void Analyze(ProxyFlow& flow) override;

private:
    static bool HasBearerToken(const ProxyFlow& flow);
    static bool HasBasicAuth(const ProxyFlow& flow);
    static bool HasSessionCookie(const ProxyFlow& flow);
    static bool IsLoginEndpoint(const ProxyFlow& flow);
    static bool LooksLikeJwt(const std::string& token);
};
