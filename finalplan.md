# 🚀 NetSense+ — Final Plan (Complete)

## 🧠 Project Vision

NetSense+ is a **user-friendly network analyzer** that shows:

* What apps are using internet
* Which websites they connect to
* Real-time request/response activity
* Full API URLs (via proxy mode)

> Goal: Replace complex tools like Wireshark with a **simple, real-time, human-readable interface**

---

## 🧩 Core Features

### 🟢 1. Live Network Monitor (Default Mode)

* Detect running apps (Brave, Chrome, etc.)
* Show domains:
* Show allthings accesing etc :
  * youtube.com
  * googlevideo.com
* Show bandwidth usage (per app)
* Real-time updates

---

### 🔍 2. API URL Inspector (Proxy Mode)

* Capture full request URLs:

  * GET /api/search?q=Believer
* Show:

  * Method (GET/POST)
  * Full URL
  * Status (200 OK)
  * Response size
  * Time taken

---

### 🔁 3. Request–Response Visualization

* ⬆️ Request sent
* ⬇️ Response received
* Grouped by app + domain

---

### 📊 4. Smart Insights

* “YouTube streaming detected”
* “High bandwidth usage by Brave”
* “New device connected”

---

## 🖥️ UI Design (Dear ImGui)

### Layout:

#### Left Panel:

* App list

  * Brave
  * Chrome
  * System

#### Right Panel:

* Live domains per app
* Bandwidth usage

#### Bottom Panel:

* API Requests (Proxy Mode)

---

## ⚙️ Tech Stack

### Core Engine

* **C++**
* Npcap (packet capture)
* Windows API (process detection)

### UI

* **Dear ImGui**
* GLFW + OpenGL

### Proxy Engine

* **Python**
* mitmproxy (HTTPS interception)

---

## 🔁 System Architecture

```
[C++ Network Engine] ─────┐
                          ├──> [ImGui UI]
[mitmproxy (Python)] ────┘
```

---

# 🧱 Development Phases (FULL ROADMAP)

---

## 🥇 Phase 1 — Network Scanner (Foundation)

### Goal:

Detect active connections and map them to apps + domains
if needed decrypt this 

### Tasks:

* Setup Npcap
* Capture packets / connections
* Get local IP range
* Detect active IPs
* Map IP → domain (DNS/SNI)
* Map connection → process (Brave, Chrome)

### Example Output:

```
Brave → youtube.com
Chrome → google.com
```

---

## 🥈 Phase 2 — Core UI (ImGui Integration)

### Goal:

Display data in real-time dashboard

### Tasks:

* Setup Dear ImGui + GLFW + OpenGL
* Create multi-panel layout
* Render:

  * App list
  * Domain activity
  * Live updates (refresh loop)

### Output:

* Working UI showing live connections

---

## 🥉 Phase 3 — Bandwidth & Metrics

### Goal:

Show real-time usage

### Tasks:

* Track bytes per connection
* Aggregate per app
* Create graphs (ImGui plots)
* Show:

  * Upload / Download speed
  * Top bandwidth user

---

## 🏆 Phase 4 — Request/Response Engine

### Goal:

Simulate request-response flow

### Tasks:

* Detect outgoing packets → mark as request
* Detect incoming packets → mark as response
* Match flows using:

  * IP + port pairs
* Show latency & size

---

## 🔍 Phase 5 — Proxy Integration (API URLs)

### Goal:

Capture full URLs using proxy

### Use:

* mitmproxy

### Tasks:

* Run proxy server (127.0.0.1:8080)
* Capture HTTP/HTTPS traffic
* Parse:

  * Method
  * Full URL
  * Status code
* Send logs to C++ UI

---

## 🔐 Phase 6 — HTTPS Inspection Mode

### Goal:

Enable full API visibility (user-controlled)

### Tasks:

* Add toggle:

  * OFF → Normal mode
  * ON → Inspection mode

* Guide user:

  * Install certificate
  * Enable proxy

### Output:

```
GET https://api.example.com/search?q=Believer
```

---

## 🧠 Phase 7 — Smart Insights Engine

### Goal:

Convert raw data into human-readable insights

### Tasks:

* Detect patterns:

  * Streaming (YouTube)
  * Messaging (WhatsApp)
* Generate messages:

  * “High usage detected”
  * “New device connected”

---

## 📊 Phase 8 — Advanced UI & UX

### Tasks:

* Add filters (by app/domain)
* Search bar for requests
* Expandable request cards
* Dark hacker-style UI polish

---

## 🚀 Phase 9 — Optimization & Packaging

### Tasks:

* Optimize CPU usage
* Reduce memory footprint
* Bundle:

  * C++ app
  * Python proxy
* Create installer (.exe)

---

## 🧪 Phase 10 — Testing & Stability

### Tasks:

* Test with:

  * Brave
  * Chrome
  * Background apps
* Handle:

  * crashes
  * edge cases
* Improve reliability

---



## 💡 Unique Selling Points

* Simple UI (no packet spam)
* App-based network view
* Full API URL capture (proxy mode)
* Real-time + human-readable insights

---

## 🎯 Final Goal

> “A clean, powerful network analyzer that anyone can understand”

---


###  Do This but give Disclamer to user:

* Monitor All traffic in that netweork
* Use on public WiFi to capture чуж data
* Enable HTTPS interception 
* Install certificates 
* Capture everthing


---

### ⚠️ Golden Rule:

> give disclamer and warning

---

### ✅ Always:

* Keep everything **local**
* Require **user permission**
* Provide **clear ON/OFF controls**
* Be transparent about inspection mode

---
