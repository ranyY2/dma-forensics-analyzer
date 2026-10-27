# Kernel-Testplan

## Voraussetzungen

- isolierte Hyper-V-/VMware-VM oder dedizierter Test-PC
- WDK passend zur Windows-Version
- Visual Studio KMDF-Toolchain
- Kernel Debugger und Driver Verifier
- Testzertifikat/Testsignierung nur in der isolierten Umgebung

## Reihenfolge

1. Build mit Warnungen als Fehler und statischer Analyse.
2. Driver Verifier: Special Pool, Pool Tracking, I/O Verification, Deadlock Detection, Security Checks.
3. Load/Unload mindestens 1000-mal.
4. IOCTL-Grenztests: null, zu kleine Buffer, Überlaufwerte, falsche Version, parallele Requests.
5. PnP-Hotplug und 1000+ Events; Sequenzlücken und Ringbuffer-Drops prüfen.
6. Sleep/Resume, Reboot und Geräteentfernung.
7. Erst danach optionale Prozess-/Image-/Registry-Callbacks aktivieren.

## Sicherheitsakzeptanzkriterien

- Kein IOCTL für beliebige Kernel-/Prozessspeicherzugriffe.
- Keine Datei-, Registry- oder Logänderung.
- Jede Registrierung wird beim Unload entfernt.
- Jeder Event-Payload bleibt unter dem festen Limit.
- Ein fehlendes Event wird über Sequenznummern als Gap markiert.
- Keine Aussage `DMA Cheat detected` aus Kernel-Telemetrie allein.
