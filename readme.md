# Netsense

Netsense is a lightweight network analysis and proxy orchestration toolkit designed to monitor, analyze, and manipulate network traffic for debugging, testing, and rule-driven proxying.

Key capabilities
- Real-time network monitoring and flow pipeline for capturing traffic and extracting protocol-level signals.
- Rule engine and proxy addon for applying configurable policies to traffic (filtering, routing, rewriting).
- Traffic analysis components (traffic_analyzer, domain_cache) for detecting patterns and summarizing flows.
- DNS resolving and inspection via the `dns` module.
- Recording and replay: capture traffic sessions and replay them for deterministic testing.
- ImGui-based UI for interactive inspection and control (under `ui/` and `imgui/`).
- <img width="1918" height="1007" alt="Screenshot 2026-06-03 014236" src="https://github.com/user-attachments/assets/81256392-c11f-4baf-a742-a470cbb5dc43" />
<img width="747" height="582" alt="Screenshot 2026-06-03 003136" src="https://github.com/user-attachments/assets/fe0dad16-55e3-4d9b-ba64-c988ab3be44b" />
<img width="802" height="596" alt="Screenshot 2026-06-03 003735" src="https://github.com/user-attachments/assets/8db0c3be-886a-44e9-a4fa-5b2e76d4cd76" />
<img width="1919" height="983" alt="Screenshot 2026-06-03 013955" src="https://github.com/user-attachments/assets/d2697bc5-333d-475c-9177-f84f5d9ae920" />
<img width="1906" height="939" alt="Screenshot 2026-06-03 014211" src="https://github.com/user-attachments/assets/c4747dbb-76b7-490f-9a3b-340d0cf23ba3" />
<img width="1919" height="1007" alt="Screenshot 2026-06-03 014236" src="https://github.com/user-attachments/assets/53b89c33-74b9-4cac-bf90-08f0c01d4641" />
<img width="1910" height="1000" alt="Screenshot 2026-06-03 014434" src="https://github.com/user-attachments/assets/c1c6ea3b-4df2-451d-afce-6f6eec298604" />
<img width="1919" height="967" alt="Screenshot 2026-06-03 014451" src="https://github.com/user-attachments/assets/f8e11a06-dfe7-4872-85f3-3d249902b901" />
<img width="1919" height="999" alt="Screenshot 2026-06-03 014504" src="https://github.com/user-attachments/assets/f87a7fa1-34d8-4899-9e2c-245e3088161f" />
<img width="1919" height="1017" alt="Screenshot 2026-06-03 014548" src="https://github.com/user-attachments/assets/fb4fb525-6e33-4961-99c4-cee1d18310f8" />
<img width="1915" height="1004" alt="Screenshot 2026-06-03 014556" src="https://github.com/user-attachments/assets/de619229-9ad5-4a0c-ba3d-5fb03f448c6c" />
<img width="1919" height="984" alt="Screenshot 2026-06-03 014612" src="https://github.com/user-attachments/assets/a4af3e9e-d531-4dd7-b96f-cf5202069f4e" />
<img width="1919" height="841" alt="Screenshot 2026-06-03 014620" src="https://github.com/user-attachments/assets/27e1624d-0a82-4f15-adf9-02988d32a5ef" />


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
