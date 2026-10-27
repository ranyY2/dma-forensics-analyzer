#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>

#define DMAF_POOL_TAG 'FAMD'
#define DMAF_DEVICE_NAME L"\\Device\\DmaForensics"
#define DMAF_SYMBOLIC_NAME L"\\DosDevices\\DmaForensics"
#define DMAF_INTERFACE_NAME L"{9B65D4E0-2D61-4E72-8C0D-6B8BF91E9D4B}"
#define DMAF_EVENT_PAYLOAD_MAX 192u
#define DMAF_RING_CAPACITY 512u
#define DMAF_PROTOCOL_VERSION 1u

#define IOCTL_DMAF_GET_VERSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_DMAF_GET_DEVICE_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_DMAF_GET_STATISTICS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_DMAF_CLEAR_SESSION_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA)

namespace DmaForensics {

enum class EventType : ULONG {
    PciDeviceArrival = 1,
    PciDeviceRemoval = 2,
    DriverLoad = 3,
    ProcessCreate = 4,
    ProcessExit = 5,
    ImageLoad = 6,
    RegistryDriverChange = 7,
    SecurityStateChange = 8,
    PnpEvent = 9,
    EventGap = 10,
};

struct EventHeader {
    ULONG Version;
    EventType Type;
    ULONG64 Timestamp100ns;
    ULONG64 SequenceId;
    ULONG SessionId;
    ULONG PayloadSize;
};

struct TelemetryEvent {
    EventHeader Header;
    UCHAR Payload[DMAF_EVENT_PAYLOAD_MAX];
};

struct VersionResponse {
    ULONG StructureVersion;
    ULONG DriverVersionMajor;
    ULONG DriverVersionMinor;
    ULONG ProtocolVersion;
};

struct StatisticsResponse {
    ULONG StructureVersion;
    ULONG Capacity;
    ULONG Pending;
    ULONG64 NextSequenceId;
    ULONG64 DroppedEvents;
};

struct EventBatchRequest {
    ULONG StructureVersion;
    ULONG MaximumEvents;
    ULONG64 SequenceAfter;
};

struct EventBatchResponse {
    ULONG StructureVersion;
    ULONG EventCount;
    ULONG64 FirstSequenceId;
    ULONG64 LastSequenceId;
    TelemetryEvent Events[1];
};

} // namespace DmaForensics
