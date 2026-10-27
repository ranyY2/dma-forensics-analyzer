#pragma once

#include "Common.hpp"

namespace DmaForensics {

NTSTATUS RegisterPnpNotifications(_In_ WDFDEVICE Device);
VOID UnregisterPnpNotifications(_In_opt_ PVOID Cookie);

} // namespace DmaForensics
