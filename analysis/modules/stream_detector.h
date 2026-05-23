#pragma once
#include "../flow_pipeline.h"

// ── Stream Detector Module ────────────────────────────────────
// Detects HLS (.m3u8), DASH (.mpd), YouTube videoplayback
// chunks, Twitch/Netflix streaming, and WebRTC signaling flows.
// Sets FlowInsight::isStream = true and populates insight.mime.
class StreamDetectorModule : public IAnalyzerModule {
public:
    void Analyze(ProxyFlow& flow) override;

private:
    static bool IsHLS(const ProxyFlow& flow);
    static bool IsDASH(const ProxyFlow& flow);
    static bool IsYouTubeChunk(const ProxyFlow& flow);
    static bool IsWebRTC(const ProxyFlow& flow);
    static bool IsLiveStream(const ProxyFlow& flow);
};
