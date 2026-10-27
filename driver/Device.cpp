#include "Device.hpp"
#include "PnpMonitor.hpp"

namespace DmaForensics {

static const GUID DmaForensicsInterfaceGuid = { 0x9b65d4e0, 0x2d61, 0x4e72, { 0x8c, 0x0d, 0x6b, 0x8b, 0xf9, 0x1e, 0x9d, 0x4b } };

NTSTATUS CreateTelemetryDevice(WDFDRIVER driver, PWDFDEVICE_INIT deviceInit) {
    UNREFERENCED_PARAMETER(driver);
    NTSTATUS status = WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    if (!NT_SUCCESS(status)) return status;
    DECLARE_CONST_UNICODE_STRING(deviceSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = WdfDeviceInitAssignSDDLString(deviceInit, &deviceSddl);
    if (!NT_SUCCESS(status)) return status;

    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, DeviceContext);
    attributes.EvtCleanupCallback = EvtDeviceContextCleanup;
    WDFDEVICE device;
    status = WdfDeviceCreate(&deviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) return status;
    auto context = GetDeviceContext(device);
    status = EventBufferInitialize(&context->Buffer, device);
    if (!NT_SUCCESS(status)) return status;
    context->PnpNotificationCookie = nullptr;

    status = WdfDeviceCreateDeviceInterface(device, &DmaForensicsInterfaceGuid, nullptr);
    if (!NT_SUCCESS(status)) return status;

    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;
    WDFQUEUE queue;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) return status;
    status = RegisterPnpNotifications(device);
    if (!NT_SUCCESS(status)) return status;
    return STATUS_SUCCESS;
}

VOID EvtDeviceContextCleanup(WDFOBJECT object) {
    auto device = static_cast<WDFDEVICE>(object);
    auto context = GetDeviceContext(device);
    UnregisterPnpNotifications(context->PnpNotificationCookie);
    EventBufferDestroy(&context->Buffer);
}

} // namespace DmaForensics
