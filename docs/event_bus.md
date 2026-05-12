# Event Bus Design — NetSense+

> **Status:** Designed, not yet implemented. This document is the implementation spec.

---

## Why EventBus?

Without EventBus:
- ProxyReader directly calls `g_state.addLog()` (tight coupling)
- Rule hits directly mutate UI counters (tight coupling)
- Adding a new subscriber (e.g. analytics) requires modifying 5 files

With EventBus:
- ProxyReader emits `Event{FlowCaptured}` — done
- DB writer, UI, logger, analytics each subscribe independently
- Adding a new subscriber = 3 lines, zero modification to emitter

---

## Event Types

```cpp
enum class EventType {
    // Traffic
    FlowCaptured,      // new HTTP flow (REQ+RSP pair)
    FlowModified,      // rule modified a flow

    // Rules
    RuleHit,           // rule matched but didn't block
    RuleBlocked,       // rule killed the connection
    RuleRedirected,    // rule issued a redirect
    RuleAlertRaised,   // ALERT_ON_MATCH fired

    // Proxy lifecycle
    ProxyStarted,
    ProxyStopped,
    ProxyCrashed,
    ProxyRestarted,

    // Sessions / Storage
    SessionStarted,
    SessionEnded,
    SessionExported,
    DBWriteError,

    // Runtime
    RuntimeError,
    SubsystemStale,    // health monitor detected dead thread

    // UI
    LogLineAdded,
    SettingsSaved
};
```

---

## Event Struct

```cpp
struct Event {
    EventType   type;
    double      ts;          // TimeUtils::NowSec()
    std::string source;      // "proxy_reader", "rule_manager", "ui"
    std::string payload;     // JSON string (structured data)
};
```

---

## EventBus API

```cpp
class EventBus {
public:
    using Handler = std::function<void(const Event&)>;

    // Subscribe — called once at startup (UI thread)
    static SubscriptionId Subscribe(EventType, Handler);
    static void Unsubscribe(SubscriptionId);

    // Emit — thread-safe, non-blocking, queued
    static void Emit(Event);

    // Dispatch — call from UI frame or worker thread
    // Drains the queue and calls handlers
    static void Dispatch(int maxEvents = 64);

private:
    static std::mutex                                    _mtx;
    static std::unordered_map<EventType, std::vector<Handler>> _subs;
    static std::deque<Event>                             _queue;  // ring-capped at 1024
};
```

---

## Example Usage

### Emitter (any thread):
```cpp
EventBus::Emit({
    EventType::RuleBlocked,
    TimeUtils::NowSec(),
    "rule_engine",
    R"({"rule_id":"sh_sqli1","url":"evil.com/?q=OR 1=1"})"
});
```

### Subscriber (setup at startup):
```cpp
// DB writer subscribes to FlowCaptured
EventBus::Subscribe(EventType::FlowCaptured, [](const Event& e) {
    auto j = json::parse(e.payload);
    TrafficDB::QueueFlowInsert(g_state.currentSessionId, ParseFlow(j));
});

// UI log panel subscribes to all rule events
EventBus::Subscribe(EventType::RuleBlocked, [](const Event& e) {
    g_state.addLog("[BLOCKED] " + e.payload);
});
```

---

## Dispatch Strategy

`EventBus::Dispatch()` is called:
1. From the UI render thread at the start of each frame
2. From `ProxyLoop()` on each iteration (for non-UI subscribers)

This guarantees handlers run with no locks held from the emitter's context.

---

## Implementation Order

1. Create `backend/event_bus.h/.cpp` with queue + subscribe/emit/dispatch
2. Wire `ProxyReader` → emit `FlowCaptured` instead of direct `g_state` mutation
3. Wire DB writer as subscriber to `FlowCaptured`
4. Wire log panel as subscriber to rule events
5. Remove all direct `g_state.addLog()` calls from non-UI code — use EventBus instead
