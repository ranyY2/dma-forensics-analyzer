#include "Device.hpp"

namespace DmaForensics {

EVT_WDF_DRIVER_DEVICE_ADD EvtDeviceAdd;

NTSTATUS EvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT deviceInit) {
    return CreateTelemetryDevice(driver, deviceInit);
}

} // namespace DmaForensics

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, DmaForensics::EvtDeviceAdd);
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    return WdfDriverCreate(driverObject, registryPath, &attributes, &config, WDF_NO_HANDLE);
}
