#pragma once

#include "Common.hpp"

namespace DmaForensics {

struct EventBuffer {
    WDFSPINLOCK Lock;
    TelemetryEvent* Events;
    ULONG Head;
    ULONG Count;
    ULONG64 NextSequenceId;
    ULONG64 DroppedEvents;
    ULONG SessionId;
};

NTSTATUS EventBufferInitialize(_Out_ EventBuffer* Buffer, _In_ WDFOBJECT Parent);
VOID EventBufferDestroy(_Inout_ EventBuffer* Buffer);
VOID EventBufferClear(_Inout_ EventBuffer* Buffer);
NTSTATUS EventBufferPush(_Inout_ EventBuffer* Buffer, _In_ EventType Type, _In_reads_bytes_(PayloadSize) const VOID* Payload, _In_ ULONG PayloadSize);
NTSTATUS EventBufferRead(_Inout_ EventBuffer* Buffer, _In_ const EventBatchRequest* Request, _Out_writes_bytes_(OutputLength) EventBatchResponse* Response, _In_ ULONG OutputLength);
VOID EventBufferGetStatistics(_Inout_ EventBuffer* Buffer, _Out_ StatisticsResponse* Response);

} // namespace DmaForensics
