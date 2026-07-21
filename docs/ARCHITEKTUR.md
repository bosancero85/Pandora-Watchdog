# Architektur-Überblick

```
pandora_watchdog.py
│
├── Konfiguration (~/.pandora_watchdog/config.json)
│
├── Ordner-Wächter (watchdog.Observer)
│   └── MetadataStripperHandler
│       ├── strip_image_metadata()  (Pillow)
│       └── strip_video_metadata()  (ffmpeg-Remux)
│
├── Injektions-Wächter (watchdog.Observer, pro überwachtem Ordner)
│   └── InjectionFileHandler
│       └── build_file_info()
│           ├── get_origin_url() / parse_origin()   -> Herkunft
│           ├── sha256_of()                          -> Hash
│           ├── clamav_scan()                         -> ClamAV
│           ├── detect_real_type() / check_extension_mismatch()
│           ├── check_double_extension()
│           ├── check_exec_flag()
│           ├── YaraScanner.scan()                    -> optionale YARA-Treffer
│           └── compute_risk()                        -> Ampel-Score
│
├── Persistenz-Wächter (QTimer-Polling)
│   └── PersistenceWatcher
│       └── _hash_persistence_target()  je überwachtem Pfad
│           (Vergleich gegen persistenz_baseline.json)
│
├── GeminiClient (optional, nur wenn API-Key hinterlegt)
│   └── assess_file()  -> Textbewertung inkl. technischer Vorab-Indikatoren
│
├── SecureVault (Fernet-verschlüsselter API-Key)
│
├── SkillLibrary (lädt Kontext-Titel aus einem öffentlichen
│   Community-Repo für die Gemini-Einordnung, keine Angriffs-Anleitungen)
│
└── PyQt6-UI
    ├── Tray-Icon + Kontextmenü (PandoraWatchdogTray)
    ├── DetectionsWindow      (Tabelle aller Funde, Aktionen)
    ├── DetectionDetailDialog (Einzelansicht: Ignorieren/Quarantäne/Löschen)
    ├── QuarantineManagerDialog (Wiederherstellen/endgültig löschen)
    ├── IgnoreListDialog      (Whitelist-Verwaltung)
    └── WatchedFoldersDialog  (Ordner-/Pfad-Verwaltung, mehrfach genutzt)
```

## Datenfluss bei einem Fund

1. Neue Datei taucht in einem überwachten Ordner auf →
   `InjectionFileHandler._process()` wartet, bis die Datei stabil ist
   (Größe ändert sich nicht mehr).
2. `build_file_info()` sammelt alle Indikatoren und berechnet über
   `compute_risk()` eine Ampel-Einstufung.
3. Steht die Datei bereits auf der Ignorierliste (`is_ignored()`), wird sie
   stillschweigend übersprungen.
4. Andernfalls wird ein Signal an die UI gesendet → Eintrag erscheint in der
   `DetectionsWindow`-Tabelle, farblich nach Risiko markiert.
5. Ist ein Gemini-API-Key hinterlegt, läuft zusätzlich asynchron
   `GeminiWorker` und ergänzt die Einschätzung, sobald sie fertig ist.
6. Der Nutzer entscheidet manuell: ignorieren (Whitelist), in Quarantäne
   verschieben (mit Rückholoption) oder endgültig löschen.
