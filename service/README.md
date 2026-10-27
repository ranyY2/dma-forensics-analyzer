# Usermode Service

Der Service ist die sichere Vermittlungsschicht zwischen KMDF-Treiber und Forensikpipeline.

Geplante Verantwortlichkeiten:

- Kernel-Device ueber versionierte IOCTLs oeffnen
- Sequenznummern pruefen und `EVENT_GAP` markieren
- Kernel-Telemetrie mit Usermode-Artefakten zusammenfuehren
- Collector-Lebenszyklus, Cancellation und Limits steuern
- Daten an Correlation, Database und Reporting uebergeben

Keine Kerneloperationen direkt aus GUI-Code aufrufen.
