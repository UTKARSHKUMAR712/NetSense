# NetSense+ 3.0: Advanced Architecture & Inspection Upgrade Plan

## 1. Flow Intelligence Pipeline
**Objective:** Orchestrate flow analysis through a structured pipeline to prevent feature explosion.
* **Pipeline Structure:** `Raw Flow` → `MIME Detection` → `URL Classification` → `Protocol Detection` → `Tracker Matching` → `Auth Detection` → `Stream Detection` → `Risk Scoring` → `Tag Aggregation` → `Event Emission` → `UI Rendering`.
* **Core Components:** `analysis/flow_pipeline.cpp` and `analysis/flow_pipeline.h`.

## 2. Analyzer Plugin System
**Objective:** Decouple analysis logic into dynamically registered plugins instead of a single monolithic file.
* **Modules (`analysis/modules/`):**
  * `stream_detector.cpp`
  * `api_detector.cpp`
  * `tracker_detector.cpp`
  * `auth_detector.cpp`
  * `risk_analyzer.cpp`
  * `mime_classifier.cpp`
  * `websocket_analyzer.cpp`

## 3. Flow Metadata Model
**Objective:** Provide a unified struct to hold all insights, avoiding scattered string tags.
* **Structure:** `FlowInsight` containing boolean flags (`isAPI`, `isStream`, `isAuth`, etc.), string categorizations (`apiType`, `authType`, `riskLevel`), and aggregated `tags`.

## 4. [CATCHER] Auto-Capture Vaults
**Objective:** Automatically extract and categorize sensitive data traversing the network into dedicated databases.
* **Credentials Vault:** Captures usernames, passwords, and form data from login attempts.
* **Token Viewer:** Extracts OAuth Bearer tokens, JWTs, and API session tokens.
* **Cookie Database:** Aggregates and displays all `Set-Cookie` and `Cookie` parameters intercepted.
* **Browser Data Viewer:** Tracks browser-specific telemetry and fingerprints.

## 5. Strict Performance Limits & Caching
**Objective:** Ensure CPU usage is minimized, RAM is preserved, and the UI never freezes during data overload.
* **UI Virtualization:** Rendering using `ImGuiListClipper` ensures only visible flows are drawn.
* **Lazy Parsing:** Heavy bodies (JSON, images) are only parsed when explicitly clicked.
* **Domain Intelligence Cache:** Tracker, CDN, and ad domains are cached in-memory to bypass slow regex.
* **Async Workers:** All pipeline intelligence is strictly offloaded from the UI thread.

## 6. Advanced Stream & WebSocket Intelligence
**Objective:** Go beyond basic URL tagging and identify deep media metrics.
* **Stream Detection:** HLS (`.m3u8`), DASH (`.mpd`), progressive MP4, WebRTC. Differentiate livestreams vs. buffered content.
* **WebSocket Inspector:** Opcode type tracking, JSON payload detection, and a real-time message timeline view.

## 7. TLS Intelligence & Decryption
**Objective:** Provide deep visibility into the secure tunnel.
* **Metrics:** TLS version, cipher suite, certificate issuer, SNI, ALPN (HTTP/2 vs HTTP/3).
* **Decryption Control:** If traffic is encrypted but not intercepted, provide an "Add button to decrypt" to prompt CA installation or adjust interception rules.

## 8. Search, Query & Timeline Engine
**Objective:** Powerful data retrieval and visual correlation.
* **Search:** Indexed filtering supporting syntaxes like `tag:API mime:json process:brave.exe risk:HIGH`.
* **Timeline View:** Visual representations of flow bursts, API spikes, upload spikes, and stream startup events.

## 9. HAR Export
**Objective:** Industry-standard debugging interoperability.
* **Capabilities:** Export selected flows, export full sessions, and import HAR files for offline NetSense+ analysis.

---

**Execution Strategy:**
This upgrade will strictly follow the pipeline architecture approach. Foundational metadata models (`FlowInsight`) and the `FlowPipeline` orchestrator will be built first, followed by individual plugin detectors, and finally the UI presentation layers and auto-capture vaults.
