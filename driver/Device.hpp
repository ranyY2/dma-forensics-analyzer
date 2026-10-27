#pragma once

#include "Common.hpp"
#include "EventBuffer.hpp"

namespace DmaForensics {

struct DeviceContext {
    EventBuffer Buffer;
    PVOID PnpNotificationCookie;
};

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DeviceContext, GetDeviceContext);

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;
EVT_WDF_OBJECT_CONTEXT_CLEANUP EvtDeviceContextCleanup;

NTSTATUS CreateTelemetryDevice(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit);

} // namespace DmaForensics
