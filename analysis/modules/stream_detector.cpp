#include "stream_detector.h"
#include <algorithm>
#include <string>

// ─────────────────────────────────────────────────────────────
// Known streaming service hostnames
// ─────────────────────────────────────────────────────────────
static const char* kStreamHosts[] = {
    "googlevideo.com", "youtube.com", "youtu.be",
    "nflxvideo.net",  "netflix.com",
    "twitch.tv",      "twitchsvc.net", "jtvnw.net",
    "hulu.com",       "hulustream.com",
    "disneyplus.com", "bamgrid.com",
    "primevideo.com", "aiv-cdn.net",
    "spotify.com",    "scdn.co",
    "soundcloud.com", "sndcdn.com",
    "vimeo.com",      "vimeocdn.com",
    "dailymotion.com","dmcdn.net",
    "akamaihd.net",   "fastly.net",
    nullptr
};

// ─────────────────────────────────────────────────────────────
// Helper: contains (case-insensitive)
// ─────────────────────────────────────────────────────────────
static bool ci_contains(const std::string& haystack, const std::string& needle) {
    std::string h = haystack, n = needle;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n) != std::string::npos;
}

// ─────────────────────────────────────────────────────────────
bool StreamDetectorModule::IsHLS(const ProxyFlow& flow) {
    return ci_contains(flow.url, ".m3u8") ||
           ci_contains(flow.content_type, "mpegurl") ||
           ci_contains(flow.content_type, "x-mpegURL");
}

bool StreamDetectorModule::IsDASH(const ProxyFlow& flow) {
    return ci_contains(flow.url, ".mpd") ||
           ci_contains(flow.content_type, "dash+xml");
}

bool StreamDetectorModule::IsYouTubeChunk(const ProxyFlow& flow) {
    return (ci_contains(flow.host, "googlevideo.com") &&
            ci_contains(flow.url, "videoplayback"));
}

bool StreamDetectorModule::IsWebRTC(const ProxyFlow& flow) {
    return ci_contains(flow.url, "stun") ||
           ci_contains(flow.url, "turn:") ||
           ci_contains(flow.url, "/webrtc") ||
           ci_contains(flow.raw_req_headers, "ICE");
}

bool StreamDetectorModule::IsLiveStream(const ProxyFlow& flow) {
    // Live streams typically have small, frequent chunks
    return ci_contains(flow.url, "live") ||
           ci_contains(flow.url, "/hls/") ||
           ci_contains(flow.url, "/dash/") ||
           ci_contains(flow.url, "chunklist") ||
           ci_contains(flow.url, "livestream");
}

// ─────────────────────────────────────────────────────────────
void StreamDetectorModule::Analyze(ProxyFlow& flow) {
    // Already tagged by a prior module — don't overwrite
    if (flow.insight.isStream) return;

    bool detected = false;
    std::string streamService;
    std::string mimeHint;

    // ── Check explicit stream format ──────────────────────────
    if (IsHLS(flow)) {
        detected = true;
        mimeHint = "HLS";
    } else if (IsDASH(flow)) {
        detected = true;
        mimeHint = "DASH";
    } else if (IsYouTubeChunk(flow)) {
        detected = true;
        mimeHint = "YouTube";
        streamService = "YouTube";
    } else if (IsWebRTC(flow)) {
        detected = true;
        mimeHint = "WebRTC";
    }

    // ── Check known streaming service hosts ───────────────────
    if (!detected) {
        for (int i = 0; kStreamHosts[i] != nullptr; ++i) {
            if (ci_contains(flow.host, kStreamHosts[i])) {
                detected = true;
                // Video content only — skip analytics/API calls
                if (ci_contains(flow.content_type, "video") ||
                    ci_contains(flow.content_type, "audio") ||
                    ci_contains(flow.url, ".ts")  ||
                    ci_contains(flow.url, ".mp4") ||
                    ci_contains(flow.url, ".aac") ||
                    ci_contains(flow.url, ".webm") ||
                    ci_contains(flow.url, "segment")) {
                    mimeHint = "Media";
                } else {
                    detected = false; // skip non-media hits on streaming domains
                }
                break;
            }
        }
    }

    if (detected) {
        flow.insight.isStream = true;
        flow.insight.mime = mimeHint;

        // Is it a live stream?
        if (IsLiveStream(flow)) {
            flow.insight.tags.push_back("[STREAM:LIVE]");
        } else {
            flow.insight.tags.push_back("[STREAM]");
        }

        // Attach service name if known
        if (!streamService.empty()) {
            flow.insight.tags.push_back("[" + streamService + "]");
        }
    }
}
