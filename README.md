# DMA Forensics Analyzer

Dieses Repository enthält den aktuellen defensiven Forensik-MVP und die definierte Architektur für eine vollständige Client-Server-Plattform.

Die Platform-Roadmap, API-Schnittstellen, Datenbankmodelle, Result-Paket-Schema und forensischen PCIe-Identitätsregeln sind in [ARCHITECTURE.md](ARCHITECTURE.md) dokumentiert. Die KMDF-Treiber- und Kernarchitektur liegen in [KERNEL-ARCHITECTURE.md](KERNEL-ARCHITECTURE.md), [driver/README.md](driver/README.md) und [KERNEL-TEST-PLAN.md](KERNEL-TEST-PLAN.md).

## Aktueller Status

- Read-only Windows-Forensik-MVP vorhanden
- PCI/PnP- und Security-Metadaten werden gesammelt
- Timeline-, Finding- und JSON-Report-Modelle sind Teil des MVP
- Ein durchgängiger FastAPI-Workflow mit persistenter SQLite-Datenbank ist vorhanden
- Registrierung, Login, signierte Session-Tokens, Scan-Ownership und geschützte Reports sind implementiert
- Eine Webkonsole liegt unter `frontend/` und wird vom Backend ausgeliefert
- Die Webkonsole stellt `DmaForensicsScanner.exe` authentifiziert bereit und zeigt dessen SHA-256 sowie Signaturstatus
- Lokale JSON-Reports können zu einer kurzlebigen Scan-Session hochgeladen und mit Findings und Timeline angezeigt werden
- Die aktuelle IExpress-EXE ist nicht Authenticode-signiert; vor öffentlicher Produktion ist eine Code-Signatur erforderlich
- Der KMDF-Treiber bleibt als defensive Telemetrie-Extension vorgesehen und darf keine arbitrary kernel memory reads, no hooking, no anti-cheat bypasses und keine Prozessmanipulation durchführen

## Relevante technische Grenzen

- Ein PCIe-Gerät kann gegenüber Windows durch Firmware-Identität erscheinen; daher ist `VEN/DEV` oder `FriendlyName` keine Beweiserklärung für die physische Hardware.
- Jede Gerätebeurteilung muss auf Multi-Source-Korrelation, Baseline, Topologie, Treiber- und Funktionskonsistenz basieren.
- Ein einzelnes PCIe-Finding darf niemals als definitive DMA-Bestätigung behandelt werden.

## MVP-Ausführung

In PowerShell im Projektordner:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-DmaForensics.ps1 -Mode QUICK
```

## Ein-Klick-EXE

`DmaForensicsScanner.exe` öffnet eine grafische Oberfläche und startet beim Anzeigen automatisch einen read-only QUICK-Scan. Die Reports werden unter `Dokumente\DMA Forensics\output` gespeichert. Die EXE benötigt Windows PowerShell, aber keine Python- oder Zusatzinstallation.

Die EXE ist ein selbstentpackendes Windows-Paket. Sie enthält den Scanner-Core und startet keine Kernel-Funktionen; der KMDF-Treiber bleibt ein separates, noch WDK-pflichtiges Testartefakt. Die EXE ist derzeit unsigniert; der Webdownload zeigt deshalb `NotSigned`/`unsigned` und den SHA-256-Hash.

Neu bauen (Windows mit IExpress):

```powershell
.\scripts\build-scanner.ps1
```

Scan-Modi:

```powershell
.\Invoke-DmaForensics.ps1 -Mode DEEP -OutputDirectory .\output
.\Invoke-DmaForensics.ps1 -Mode FULL -OutputDirectory .\output
```

Der Scan schreibt JSON, CSV und HTML in das Ausgabe-Verzeichnis. `-NoHtml` deaktiviert nur den HTML-Export.

## Webanwendung starten

Im Projektordner:

```powershell
cd .\backend
$env:DMA_AUTH_SECRET = 'replace-this-with-a-long-random-secret'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Danach ist die Konsole unter `http://127.0.0.1:8000/` erreichbar. Angemeldete Benutzer laden dort die EXE herunter, führen den lokalen Scan aus und laden den erzeugten JSON-Report für Findings und Timeline zur Session hoch. Für Produktion müssen `DMA_AUTH_SECRET`, PostgreSQL, echte Migrationen und ein signiertes Scanner-EXE konfiguriert werden.

Smoke-Test:

```powershell
.\tests\Test-Mvp.ps1
```

## Wichtige Einschraenkung

Windows stellt die physische Anzahl der PCIe-Steckplaetze nicht auf jedem Mainboard verlaesslich bereit. `Win32_SystemSlot` liefert nur die von Firmware und Treibern gemeldeten Eintraege. Eine fehlende oder zu kleine Zahl bedeutet daher nicht automatisch, dass das Mainboard weniger Slots besitzt. Fuer die tatsaechliche Gesamtzahl sollte zusaetzlich das Mainboard-Handbuch oder die Herstellerseite verwendet werden.

## Projektstruktur

```text
architecure/   Projektarchitektur, API- und Datenbank-Contracts
backend/       geplantes API-Backend (FastAPI / ASP.NET Core)
frontend/      geplante Webplattform mit Report-UI
scanner/       signierter Windows Scanner und uploadfähiger Client
windows/       Windows-spezifische Sammlungs- und Verifikationsmuster
driver/        KMDF-Telemetrie, Ringbuffer, sichere IOCTLs
service/       Usermode-Kernelclient und Collector-Orchestrierung
collectors/    PCI, Registry, Treiber, SetupAPI, Eventlogs, Security, Execution
parsers/       Parser fuer Windows-Artefakte
models/        Gemeinsame Artefakt-, Timeline- und Finding-Modelle
correlation/   Zeit- und Identitaetskorrelation
scoring/       Erklaerbares Evidence-Scoring
database/      PostgreSQL- und Schema-Modelle, Metadata
reporting/     JSON-, CSV- und HTML-Reports
gui/           Dashboard-/Report-UI
ioc/           Erweiterbare IOC-Datenbank
tests/         Smoke-Tests und anonymisierte Fixtures
src/           Aktueller PowerShell-Core des MVP
```

## Abgrenzung

Dieses Repository enthält weiterhin den bestehenden read-only MVP und die Architektur für die kommende Plattform. Die volle Client-Server-Umsetzung ist noch nicht als produktiver Code implementiert; sie ist als Architektur- und Contract-Baseline dokumentiert.

Es gibt keine Funktionen zum Loeschen, Deaktivieren, Spoofen, Umgehen oder Testen der Umgehbarkeit. Die Plattform bleibt auf defensive, erklärbare und evidenzbasierte Erkennung fokussiert.
