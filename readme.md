# Netsense

Netsense is a lightweight network analysis and proxy orchestration toolkit designed to monitor, analyze, and manipulate network traffic for debugging, testing, and rule-driven proxying.

Key capabilities
- Real-time network monitoring and flow pipeline for capturing traffic and extracting protocol-level signals.
- Rule engine and proxy addon for applying configurable policies to traffic (filtering, routing, rewriting).
- Traffic analysis components (traffic_analyzer, domain_cache) for detecting patterns and summarizing flows.
- DNS resolving and inspection via the `dns` module.
- Recording and replay: capture traffic sessions and replay them for deterministic testing.
- ImGui-based UI for interactive inspection and control (under `ui/` and `imgui/`).

Quick start
- See `build.sh` and `package.sh` for build helpers.
- On Windows, open the project in Visual Studio or use your preferred C++ toolchain to build the executable.
- The UI binary lives in the top-level build output; run the produced executable to launch the ImGui interface and start monitoring.

Repository layout (high level)
- `core/` — core runtime, settings, persistence and traffic DB.
- `analysis/` — traffic analysis, flow pipeline, domain cache.
- `dns/` — DNS resolver and helpers.
- `proxy/` — Python addons, rule engine hooks, proxy integration code.
- `rules/` — C++ rule management logic and types.
- `ui/`, `imgui/` — graphical interface and ImGui sources.
- `recordings/`, `replay/` — capture and replay helpers.
- `storage/` — storage backend integrations (SQLite, JSON helpers).

How it is typically used
- Run Netsense locally while reproducing network activity to inspect flows and diagnose issues.
- Define custom rules to redirect or transform traffic for testing proxies or simulating network conditions.
- Record problematic sessions and replay them to reproduce bugs deterministically.

Contributing
- Open issues describing bugs or feature requests.
- Submit PRs with focused changes; follow existing coding style and provide a brief description of behavior.

Where to look next
- Implementation notes and detailed design are in `docs/` (see `proxy_pipeline.md`, `rules.md`, `threading.md`).

If you want, I can expand this README with build commands, examples, or screenshots—tell me what to add.
