#include "Device.hpp"

namespace DmaForensics {

static NTSTATUS Complete(WDFREQUEST request, NTSTATUS status, ULONG_PTR information = 0) {
    WdfRequestCompleteWithInformation(request, status, information);
    return status;
}

VOID EvtIoDeviceControl(WDFQUEUE queue, WDFREQUEST request, size_t outputLength, size_t inputLength, ULONG controlCode) {
    auto device = WdfIoQueueGetDevice(queue);
    auto context = GetDeviceContext(device);
    if (context == nullptr) { Complete(request, STATUS_DEVICE_NOT_READY); return; }

    switch (controlCode) {
    case IOCTL_DMAF_GET_VERSION: {
        if (outputLength < sizeof(VersionResponse)) { Complete(request, STATUS_BUFFER_TOO_SMALL); return; }
        VersionResponse* response = nullptr;
        NTSTATUS status = WdfRequestRetrieveOutputBuffer(request, sizeof(VersionResponse), reinterpret_cast<PVOID*>(&response), nullptr);
        if (!NT_SUCCESS(status)) { Complete(request, status); return; }
        *response = { DMAF_PROTOCOL_VERSION, 0, 1, DMAF_PROTOCOL_VERSION };
        Complete(request, STATUS_SUCCESS, sizeof(*response));
        return;
    }
    case IOCTL_DMAF_GET_STATISTICS: {
        if (outputLength < sizeof(StatisticsResponse)) { Complete(request, STATUS_BUFFER_TOO_SMALL); return; }
        StatisticsResponse* response = nullptr;
        NTSTATUS status = WdfRequestRetrieveOutputBuffer(request, sizeof(StatisticsResponse), reinterpret_cast<PVOID*>(&response), nullptr);
        if (!NT_SUCCESS(status)) { Complete(request, status); return; }
        RtlZeroMemory(response, sizeof(*response));
        EventBufferGetStatistics(&context->Buffer, response);
        Complete(request, STATUS_SUCCESS, sizeof(*response));
        return;
    }
    case IOCTL_DMAF_GET_DEVICE_EVENTS: {
        if (inputLength < sizeof(EventBatchRequest) || outputLength < FIELD_OFFSET(EventBatchResponse, Events) + sizeof(TelemetryEvent) || outputLength > MAXULONG) { Complete(request, STATUS_BUFFER_TOO_SMALL); return; }
        EventBatchRequest* input = nullptr;
        EventBatchResponse* output = nullptr;
        NTSTATUS status = WdfRequestRetrieveInputBuffer(request, sizeof(EventBatchRequest), reinterpret_cast<PVOID*>(&input), nullptr);
        if (!NT_SUCCESS(status)) { Complete(request, status); return; }
        status = WdfRequestRetrieveOutputBuffer(request, FIELD_OFFSET(EventBatchResponse, Events) + sizeof(TelemetryEvent), reinterpret_cast<PVOID*>(&output), nullptr);
        if (!NT_SUCCESS(status)) { Complete(request, status); return; }
        status = EventBufferRead(&context->Buffer, input, output, static_cast<ULONG>(outputLength));
        if (!NT_SUCCESS(status)) { Complete(request, status); return; }
        Complete(request, STATUS_SUCCESS, FIELD_OFFSET(EventBatchResponse, Events) + output->EventCount * sizeof(TelemetryEvent));
        return;
    }
    case IOCTL_DMAF_CLEAR_SESSION_BUFFER:
        if (inputLength != 0 || outputLength != 0) { Complete(request, STATUS_INVALID_PARAMETER); return; }
        EventBufferClear(&context->Buffer);
        Complete(request, STATUS_SUCCESS);
        return;
    default:
        Complete(request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }
}

} // namespace DmaForensics
