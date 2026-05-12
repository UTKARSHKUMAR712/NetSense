#pragma once
void StartDnsResolver();
void StopDnsResolver();
// Returns cached hostname or raw IP if not yet resolved.
// Queues a background lookup on first call.
std::string ResolveIP(const std::string& ip);
