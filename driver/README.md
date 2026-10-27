# KMDF Telemetry Driver Skeleton

Dieses Verzeichnis enthält den minimalen, defensiven KMDF-Slice.

## Enthalten

- NonPagedPoolNx-Ringbuffer mit 512 begrenzten Events
- monotone Sequenznummer, Session-ID und Kernel-Zeitstempel
- KMDF Device Interface mit Admin/System-ACL
- versionierte, gepufferte IOCTLs
- Hardware-Profile-PnP-Notification als begrenztes Live-Signal
- keine Datei-, Registry-, Netzwerk-, Prozessspeicher- oder PCI-Config-Schreibzugriffe

## Build

Erfordert Visual Studio mit WDK und KMDF-Templates. Der aktuelle Rechner besitzt laut Prüfung weder WDK-Includes noch `msbuild`; ein Build oder Laden ist hier daher absichtlich nicht behauptet.

```text
msbuild driver\DmaForensics.vcxproj /p:Configuration=Debug /p:Platform=x64
```

Vor einem Test muss der Treiber in einer isolierten Hyper-V-/VMware-VM oder auf einem dedizierten Test-PC mit Testsignierung installiert werden. Driver Verifier und ein Kernel-Debugger sind Pflicht.

## Bewusste Grenzen

`IoRegisterPlugPlayNotification` ist kein vollständiger PCI-Historienlieferant. Die detaillierte Hardware-/Treiberauflösung bleibt im Usermode und wird mit SetupAPI, PnP, Registry und EVTX korreliert. Signaturprüfung und Hashing finden niemals im Kernel statt.
