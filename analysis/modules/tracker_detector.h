#pragma once
#include "../flow_pipeline.h"

// ── Tracker Detector Module ───────────────────────────────────
// Fast O(1) DomainCache lookup to flag trackers, ad networks,
// and CDN hosts. Sets insight.isTracker / isMedia accordingly.
class TrackerDetectorModule : public IAnalyzerModule {
public:
    void Analyze(ProxyFlow& flow) override;
};
