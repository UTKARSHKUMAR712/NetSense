#include "tracker_detector.h"
#include "../domain_cache.h"

void TrackerDetectorModule::Analyze(ProxyFlow& flow) {
    if (flow.host.empty()) return;

    DomainCategory cat = DomainCache::Classify(flow.host);

    switch (cat) {
        case DomainCategory::TRACKER:
            flow.insight.isTracker = true;
            flow.insight.isSuspicious = true;
            if (flow.insight.riskLevel.empty()) flow.insight.riskLevel = "MEDIUM";
            flow.insight.tags.push_back("[TRACKER]");
            break;

        case DomainCategory::AD:
            flow.insight.isTracker = true;
            if (flow.insight.riskLevel.empty()) flow.insight.riskLevel = "MEDIUM";
            flow.insight.tags.push_back("[AD]");
            break;

        case DomainCategory::CDN:
            flow.insight.isMedia = true;
            flow.insight.tags.push_back("[CDN]");
            break;

        case DomainCategory::API:
            // Hint only — ApiDetectorModule will classify further
            if (!flow.insight.isAPI) {
                flow.insight.tags.push_back("[API:HOST]");
            }
            break;

        default:
            break;
    }
}
