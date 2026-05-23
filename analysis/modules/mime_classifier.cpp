#include "mime_classifier.h"
#include <algorithm>

// ─────────────────────────────────────────────────────────────
// Magic byte signatures for common formats
// ─────────────────────────────────────────────────────────────
std::string MimeClassifierModule::DetectFromMagicBytes(const std::string& body) {
    if (body.size() < 4) return "";

    // JSON: starts with { or [
    if (body[0] == '{' || body[0] == '[') return "application/json";
    // XML: starts with < (could be HTML or XML)
    if (body[0] == '<') {
        if (body.find("<!DOCTYPE html") != std::string::npos ||
            body.find("<html") != std::string::npos) return "text/html";
        return "text/xml";
    }
    // PNG: \x89PNG
    if ((unsigned char)body[0] == 0x89 && body.substr(1,3) == "PNG") return "image/png";
    // JPEG: \xFF\xD8
    if ((unsigned char)body[0] == 0xFF && (unsigned char)body[1] == 0xD8) return "image/jpeg";
    // GIF: GIF8
    if (body.substr(0,4) == "GIF8") return "image/gif";
    // WebP: RIFF....WEBP
    if (body.size() >= 12 && body.substr(0,4) == "RIFF" && body.substr(8,4) == "WEBP") return "image/webp";
    // PDF: %PDF
    if (body.substr(0,4) == "%PDF") return "application/pdf";
    // ZIP: PK\x03\x04
    if (body[0] == 'P' && body[1] == 'K' &&
        (unsigned char)body[2] == 0x03 && (unsigned char)body[3] == 0x04) return "application/zip";
    // MP4: ....ftyp
    if (body.size() >= 8 && body.substr(4,4) == "ftyp") return "video/mp4";
    // ID3 (MP3): ID3
    if (body.substr(0,3) == "ID3") return "audio/mpeg";

    return "";
}

std::string MimeClassifierModule::NormalizeMime(const std::string& raw) {
    std::string r = raw;
    // Strip parameters: "application/json; charset=utf-8" -> "application/json"
    auto semi = r.find(';');
    if (semi != std::string::npos) r = r.substr(0, semi);
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    // Trim spaces
    while (!r.empty() && r.back() == ' ') r.pop_back();
    return r;
}

void MimeClassifierModule::Analyze(ProxyFlow& flow) {
    std::string declared = NormalizeMime(flow.content_type);

    // If we already have insight.mime set by stream detector, keep it
    if (!flow.insight.mime.empty() && flow.insight.isStream) return;

    // Detect from body if declared type is missing or generic
    std::string detected;
    if (!flow.body_preview.empty()) {
        detected = DetectFromMagicBytes(flow.body_preview);
    }

    if (!detected.empty() && detected != declared) {
        // Body detection overrides missing content-type
        if (declared.empty() || declared == "application/octet-stream") {
            flow.insight.mime = detected;
        } else {
            // Mismatch: keep declared but note discrepancy
            flow.insight.mime = declared + " (magic:" + detected + ")";
        }
    } else if (!declared.empty()) {
        flow.insight.mime = declared;
    } else if (!detected.empty()) {
        flow.insight.mime = detected;
    }
}
