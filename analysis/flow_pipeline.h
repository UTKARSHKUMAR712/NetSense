#pragma once
#include "../core/app_data.h"
#include <memory>
#include <vector>

// Forward declarations for modules we will build in Phase 2/3
class IAnalyzerModule {
public:
    virtual ~IAnalyzerModule() = default;
    virtual void Analyze(ProxyFlow& flow) = 0;
};

class FlowPipeline {
public:
    // Initialize the pipeline and register modules
    static void Initialize();

    // Process a single flow through all registered modules sequentially
    static void ProcessFlow(ProxyFlow& flow);

private:
    static std::vector<std::unique_ptr<IAnalyzerModule>> _modules;
};
