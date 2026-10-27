#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dmaforensics {

struct EventHeader {
    std::uint32_t version;
    std::uint32_t type;
    std::uint64_t timestamp100ns;
    std::uint64_t sequenceId;
    std::uint32_t sessionId;
    std::uint32_t payloadSize;
};

struct TelemetryEvent {
    EventHeader header;
    std::vector<std::uint8_t> payload;
};

class KernelClient {
public:
    KernelClient() = default;
    KernelClient(const KernelClient&) = delete;
    KernelClient& operator=(const KernelClient&) = delete;

    bool Open();
    void Close();
    bool IsOpen() const noexcept;
    std::vector<TelemetryEvent> ReadEvents(std::uint64_t sequenceAfter, std::uint32_t maximumEvents);
    bool ClearSessionBuffer();
    std::string LastError() const;

private:
    void* deviceHandle_ = nullptr;
    std::string lastError_;
};

} // namespace dmaforensics
