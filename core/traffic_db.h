#pragma once
#include <string>
#include <vector>
#include "app_data.h"

namespace TrafficDB {
    bool Initialize(const std::string& dbPath);
    void Shutdown();
    
    // Sessions
    int  StartSession(const std::string& name);
    void EndSession(int sessionId);
    std::vector<std::pair<int, std::string>> GetAllSessions();
    
    // Flows
    void QueueFlowInsert(int sessionId, const ProxyFlow& flow);
    
    // Sync read
    std::vector<ProxyFlow> LoadFlowsForSession(int sessionId, int limit = 100, int offset = 0);
    
    // Cleanup
    void ClearDatabase();
}
