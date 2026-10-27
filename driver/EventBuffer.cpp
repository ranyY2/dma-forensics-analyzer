#include "EventBuffer.hpp"

namespace DmaForensics {

static ULONG64 QueryTimestamp() {
    return KeQueryInterruptTime();
}

NTSTATUS EventBufferInitialize(EventBuffer* buffer, WDFOBJECT parent) {
    if (buffer == nullptr) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(buffer, sizeof(*buffer));
    NTSTATUS status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &buffer->Lock);
    if (!NT_SUCCESS(status)) return status;
    buffer->Events = static_cast<TelemetryEvent*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TelemetryEvent) * DMAF_RING_CAPACITY, DMAF_POOL_TAG));
    if (buffer->Events == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(buffer->Events, sizeof(TelemetryEvent) * DMAF_RING_CAPACITY);
    buffer->NextSequenceId = 1;
    buffer->SessionId = static_cast<ULONG>(KeQueryInterruptTime());
    UNREFERENCED_PARAMETER(parent);
    return STATUS_SUCCESS;
}

VOID EventBufferDestroy(EventBuffer* buffer) {
    if (buffer == nullptr) return;
    if (buffer->Events != nullptr) {
        ExFreePoolWithTag(buffer->Events, DMAF_POOL_TAG);
        buffer->Events = nullptr;
    }
}

VOID EventBufferClear(EventBuffer* buffer) {
    if (buffer == nullptr || buffer->Lock == nullptr) return;
    WdfSpinLockAcquire(buffer->Lock);
    buffer->Head = 0;
    buffer->Count = 0;
    WdfSpinLockRelease(buffer->Lock);
}

NTSTATUS EventBufferPush(EventBuffer* buffer, EventType type, const VOID* payload, ULONG payloadSize) {
    if (buffer == nullptr || buffer->Events == nullptr || payloadSize > DMAF_EVENT_PAYLOAD_MAX) return STATUS_INVALID_PARAMETER;
    WdfSpinLockAcquire(buffer->Lock);
    ULONG index = (buffer->Head + buffer->Count) % DMAF_RING_CAPACITY;
    if (buffer->Count == DMAF_RING_CAPACITY) {
        buffer->Head = (buffer->Head + 1) % DMAF_RING_CAPACITY;
        index = (buffer->Head + buffer->Count - 1) % DMAF_RING_CAPACITY;
        buffer->DroppedEvents++;
        buffer->Count--;
    }
    TelemetryEvent* event = &buffer->Events[index];
    RtlZeroMemory(event, sizeof(*event));
    event->Header = { DMAF_PROTOCOL_VERSION, type, QueryTimestamp(), buffer->NextSequenceId++, buffer->SessionId, payloadSize };
    if (payloadSize != 0 && payload != nullptr) RtlCopyMemory(event->Payload, payload, payloadSize);
    buffer->Count++;
    WdfSpinLockRelease(buffer->Lock);
    return STATUS_SUCCESS;
}

NTSTATUS EventBufferRead(EventBuffer* buffer, const EventBatchRequest* request, EventBatchResponse* response, ULONG outputLength) {
    if (buffer == nullptr || request == nullptr || response == nullptr || request->StructureVersion != DMAF_PROTOCOL_VERSION) return STATUS_INVALID_PARAMETER;
    constexpr ULONG headerSize = FIELD_OFFSET(EventBatchResponse, Events);
    if (outputLength < headerSize + sizeof(TelemetryEvent)) return STATUS_BUFFER_TOO_SMALL;
    ULONG capacity = (outputLength - headerSize) / sizeof(TelemetryEvent);
    ULONG wanted = min(request->MaximumEvents, capacity);
    WdfSpinLockAcquire(buffer->Lock);
    ULONG copied = 0;
    for (ULONG i = 0; i < buffer->Count && copied < wanted; ++i) {
        ULONG index = (buffer->Head + i) % DMAF_RING_CAPACITY;
        if (buffer->Events[index].Header.SequenceId > request->SequenceAfter) response->Events[copied++] = buffer->Events[index];
    }
    response->StructureVersion = DMAF_PROTOCOL_VERSION;
    response->EventCount = copied;
    response->FirstSequenceId = copied ? response->Events[0].Header.SequenceId : 0;
    response->LastSequenceId = copied ? response->Events[copied - 1].Header.SequenceId : 0;
    WdfSpinLockRelease(buffer->Lock);
    return STATUS_SUCCESS;
}

VOID EventBufferGetStatistics(EventBuffer* buffer, StatisticsResponse* response) {
    if (buffer == nullptr || response == nullptr) return;
    WdfSpinLockAcquire(buffer->Lock);
    response->StructureVersion = DMAF_PROTOCOL_VERSION;
    response->Capacity = DMAF_RING_CAPACITY;
    response->Pending = buffer->Count;
    response->NextSequenceId = buffer->NextSequenceId;
    response->DroppedEvents = buffer->DroppedEvents;
    WdfSpinLockRelease(buffer->Lock);
}

} // namespace DmaForensics
