#include "PnpMonitor.hpp"
#include "Device.hpp"

namespace DmaForensics {

static NTSTATUS PnpNotificationCallback(PVOID NotificationStructure, PVOID Context) {
    UNREFERENCED_PARAMETER(NotificationStructure);
    auto device = static_cast<WDFDEVICE>(Context);
    if (device == nullptr) return STATUS_SUCCESS;
    auto context = GetDeviceContext(device);
    UCHAR payload[sizeof(ULONG)] = {};
    ULONG eventMarker = 1;
    RtlCopyMemory(payload, &eventMarker, sizeof(eventMarker));
    EventBufferPush(&context->Buffer, EventType::PnpEvent, payload, sizeof(payload));
    return STATUS_SUCCESS;
}

NTSTATUS RegisterPnpNotifications(WDFDEVICE device) {
    auto context = GetDeviceContext(device);
    return IoRegisterPlugPlayNotification(
        EventCategoryHardwareProfileChange,
        0,
        nullptr,
        WdfDriverWdmGetDriverObject(WdfDeviceGetDriver(device)),
        PnpNotificationCallback,
        device,
        &context->PnpNotificationCookie);
}

VOID UnregisterPnpNotifications(PVOID cookie) {
    if (cookie != nullptr) IoUnregisterPlugPlayNotification(cookie);
}

} // namespace DmaForensics
