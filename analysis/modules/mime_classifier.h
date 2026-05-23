#pragma once
#include "../flow_pipeline.h"

// ── MIME Classifier Module ────────────────────────────────────
// Validates and enriches content_type using magic byte patterns
// detected in body_preview. Corrects missing or wrong MIME info
// from the server and sets insight.mime with the validated type.
class MimeClassifierModule : public IAnalyzerModule {
public:
    void Analyze(ProxyFlow& flow) override;

private:
    static std::string DetectFromMagicBytes(const std::string& body);
    static std::string NormalizeMime(const std::string& raw);
};
