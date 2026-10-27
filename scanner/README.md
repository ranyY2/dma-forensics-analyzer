# Windows Scanner Client

`DmaForensics-Scanner.ps1` ist ein älterer read-only API-Prototyp für lokale Entwicklung. Der aktuelle Website-Download ist `DmaForensicsScanner.exe`; sie erstellt Reports lokal. Der JSON-Report wird derzeit bewusst vom Benutzer im Webworkspace ausgewählt und zur kurzlebigen Scan-Session hochgeladen.

Beispiel:

```powershell
.\scanner\DmaForensics-Scanner.ps1 `
  -ApiBaseUrl http://127.0.0.1:8000 `
  -ScanId '<scan-id>' `
  -UploadToken '<upload-token>' `
  -Mode QUICK
```

Der Prototyp führt keine Änderungen am System durch. Die bereitgestellte EXE ist aktuell ein selbstentpackendes, nicht Authenticode-signiertes Windows-Paket; vor öffentlicher Produktion ist Code-Signing erforderlich.
