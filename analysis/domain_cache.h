#pragma once
#include <string>
#include <unordered_set>
#include <vector>

enum class DomainCategory {
    TRACKER,
    AD,
    CDN,
    API,
    UNKNOWN
};

class DomainCache {
public:
    static void Initialize();
    static DomainCategory Classify(const std::string& host);
    static bool IsTracker(const std::string& host);
    static bool IsCDN(const std::string& host);

private:
    static std::unordered_set<std::string> _trackers;
    static std::unordered_set<std::string> _cdns;
    static std::unordered_set<std::string> _ads;
    static std::unordered_set<std::string> _apis;

    static bool MatchesAny(const std::string& host, const std::unordered_set<std::string>& list);
};
