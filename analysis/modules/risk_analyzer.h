#pragma once
#include "../flow_pipeline.h"

// ── Risk Analyzer Module ──────────────────────────────────────
// Aggregates multi-signal risk scoring after all other modules
// have run. Assigns riskLevel: CRITICAL / HIGH / MEDIUM / LOW.
// Must run LAST in the pipeline after all detectors have fired.
class RiskAnalyzerModule : public IAnalyzerModule {
public:
    void Analyze(ProxyFlow& flow) override;

private:
    static bool IsPlaintext(const ProxyFlow& flow);
    static bool IsSuspiciousTld(const std::string& host);
};
