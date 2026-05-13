#include "domain_cache.h"
#include <algorithm>

std::unordered_set<std::string> DomainCache::_trackers;
std::unordered_set<std::string> DomainCache::_cdns;
std::unordered_set<std::string> DomainCache::_ads;
std::unordered_set<std::string> DomainCache::_apis;

void DomainCache::Initialize() {
    // Basic hardcoded lists for now. Can be loaded from JSON later.
    _trackers = {
        "google-analytics.com", "doubleclick.net", "hotjar.com",
        "mixpanel.com", "segment.com", "adnxs.com", "scorecardresearch.com"
    };

    _cdns = {
        "cloudfront.net", "akamaihd.net", "fastly.net",
        "fbcdn.net", "nflxvideo.net", "cdninstagram.com"
    };

    _ads = {
        "googlesyndication.com", "criteo.com", "taboola.com",
        "outbrain.com", "adform.net", "rubiconproject.com"
    };

    _apis = {
        "api.", "graph.", "graphql.", "rest." // Prefix hints
    };
}

bool DomainCache::MatchesAny(const std::string& host, const std::unordered_set<std::string>& list) {
    std::string h = host;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    
    for (const auto& domain : list) {
        if (h.find(domain) != std::string::npos) {
            return true;
        }
    }
    return false;
}

DomainCategory DomainCache::Classify(const std::string& host) {
    if (MatchesAny(host, _trackers)) return DomainCategory::TRACKER;
    if (MatchesAny(host, _ads)) return DomainCategory::AD;
    if (MatchesAny(host, _cdns)) return DomainCategory::CDN;
    if (MatchesAny(host, _apis)) return DomainCategory::API;
    return DomainCategory::UNKNOWN;
}

bool DomainCache::IsTracker(const std::string& host) {
    return MatchesAny(host, _trackers) || MatchesAny(host, _ads);
}

bool DomainCache::IsCDN(const std::string& host) {
    return MatchesAny(host, _cdns);
}
