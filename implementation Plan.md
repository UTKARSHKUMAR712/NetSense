# NetSense+ 3.0: Advanced Architecture & Implementation Plan

> [!IMPORTANT]
> **Performance Guarantee**
> This upgrade is designed with strict memory and CPU limits. Heavy payloads will be lazy-loaded, domain lookups will be cached, and the UI will use virtualization to ensure NetSense+ never freezes, even with 100,000+ flows.

This document serves as the absolute blueprint for NetSense+ 3.0. It encompasses all features from the `upgrade_3.0_.md` file but dives deeper into the specific C++ and Python implementation details.

---

## 1. Flow Intelligence Pipeline (The Core Orchestrator)

**Objective:** Prevent feature explosion by orchestrating all traffic analysis through a modular, linear pipeline.

**Technical Implementation:**
We will introduce `analysis/flow_pipeline.cpp` and `analysis/flow_pipeline.h`. This orchestrator receives a raw `ProxyFlow` from the ring buffer and runs it sequentially through the pipeline on a background thread.

**Pipeline Flow:**
`Raw Flow` → `MIME Detection` → `URL Classification` → `Protocol Detection` → `Tracker Matching` → `Auth Detection` → `Stream Detection` → `Risk Scoring` → `Tag Aggregation` → `Event Emission` → `UI Rendering`

## 2. Analyzer Plugin System

**Objective:** Decouple analysis logic into dynamically registered plugins (`IAnalyzerModule`).

**Module Architecture (`analysis/modules/`):**
*   `stream_detector.cpp`: Detects HLS, DASH, WebRTC. Analyzes sequence numbers and chunk bitrates.
*   `api_detector.cpp`: Classifies REST, GraphQL, Polling, and JSON-RPC.
*   `tracker_detector.cpp`: Matches hosts against the Domain Intelligence Cache.
*   `auth_detector.cpp`: Looks for OAuth scopes, JWT signatures, and Basic Auth.
*   `risk_analyzer.cpp`: Aggregates signals (e.g., cleartext passwords + unknown `.xyz` domain = `CRITICAL` risk).
*   `mime_classifier.cpp`: Fast byte-level magic number inspection for payload validation.
*   `websocket_analyzer.cpp`: Intercepts `[WS CONNECT]`, `[WS SEND]`, `[WS RECV]`.

## 3. Unified Flow Metadata Model

**Objective:** Provide a unified struct to hold all insights, strictly preventing scattered string tags.

```cpp
struct CatcherData {
    std::string username;
    std::string password; // masked in UI unless hovered
    std::string bearerToken;
    std::string authCookies;
};

struct FlowInsight {
    // Fast Boolean Bitfield (Memory Efficient)
    bool isAPI : 1;
    bool isStream : 1;
    bool isTracker : 1;
    bool isAuth : 1;
    bool isMedia : 1;
    bool isSuspicious : 1;

    // Structured Classifications
    std::string apiType;    // e.g. "GraphQL", "REST"
    std::string mime;       // e.g. "application/json"
    std::string authType;   // e.g. "OAuth2", "Basic"
    std::string riskLevel;  // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    
    // Extracted Sensitive Vault Data
    CatcherData vaultPayload;

    std::vector<std::string> tags; // Final rendered tags
};
```

## 4. [CATCHER] Auto-Capture Vaults

**Objective:** A background intelligence engine that silently aggregates sensitive data traversing the network into dedicated, searchable databases.

1.  **Credentials Vault:** Auto-captures usernames, passwords, and form data from login attempts (`POST` requests to `/login`, `/auth`).
2.  **Token Viewer:** Extracts OAuth Bearer tokens, JWTs, and API session tokens, validating their expiration if possible.
3.  **Cookie Database:** Aggregates and displays all `Set-Cookie` and `Cookie` parameters intercepted, mapped by domain.
4.  **Browser Data Viewer:** Tracks browser-specific telemetry, user-agent signatures, and canvas fingerprinting attempts.

## 5. Strict Performance Limits & Caching

**Objective:** Ensure CPU usage is minimized, RAM is preserved, and the UI never freezes.

*   **UI Virtualization:** The flow table will use `ImGuiListClipper`. Only the exact number of rows visible on your monitor are calculated and rendered per frame.
*   **Lazy Body Parsing:** Heavy bodies (JSON, images) are mapped in memory but NEVER parsed until explicitly clicked in the Inspector pane.
*   **Zero-Copy Architecture:** The pipeline will pass `std::shared_ptr<ProxyFlow>` to avoid duplicating raw traffic data.
*   **Domain Intelligence Cache:** Tracker, CDN, and ad domains are loaded into an `std::unordered_set` at startup to bypass slow `std::regex` lookups.
*   **Async Workers:** All pipeline modules execute on the `TrafficAnalyzer` background thread pool.

## 6. Advanced Stream & WebSocket Intelligence

*   **Stream Intelligence:** Detects `.m3u8` and `.mpd`. It will track `videoplayback` chunk sequences to estimate active streaming bitrates and differentiate between live broadcasts and buffered VoD (Video on Demand).
*   **WebSocket Inspector:** Opcode type tracking (Binary vs Text). Real-time, interleaved message timeline. JSON payload expansion directly inside the WebSocket frames.

## 7. TLS Intelligence & Decryption

*   **Deep Cryptographic Metrics:** Extracts TLS version (1.2 vs 1.3), negotiated cipher suite, certificate issuer, SNI, and ALPN (HTTP/2 vs HTTP/3).
*   **Decryption UX Flow:** If a flow is encrypted but passing through (unintercepted), the UI will provide an inline "Decrypt" button that opens a helper to install the mitmproxy CA certificate.

## 8. Search, Query & Timeline Engine

*   **Advanced Query Syntax:** Implementing a lightweight AST parser for filtering:
    `tag:API mime:json process:brave.exe risk:HIGH method:POST`
*   **Timeline View:** A dynamic bar chart rendering flow bursts, API spikes, upload spikes, and stream startup events over a sliding window.

## 9. HAR Export

*   **Industry Standard Format:** Export selected flows, or the entire SQLite session, into standard `.har` format for use in Chrome DevTools or Postman. Import `.har` files for offline analysis using NetSense's advanced UI.

---

## Execution Phasing

1.  **Phase 1 (The Core Engine):** Implement the `FlowInsight` struct, `FlowPipeline` orchestrator, and the `Domain Intelligence Cache`.
2.  **Phase 2 (Python to C++ Bridge):** Update `netsense_addon.py` to extract deep TLS metrics and Catcher components.
3.  **Phase 3 (Modular Analyzers):** Build `stream_detector.cpp`, `auth_detector.cpp`, and the rest of the plugins.
4.  **Phase 4 (Catcher Databases):** Build the SQLite integration and memory buffers for the Cookie, Token, and Credential vaults.
5.  **Phase 5 (UI Mastery):** Implement the `ImGuiListClipper` virtualization, the Query Search Bar, HAR Export, and the Timeline graph.
