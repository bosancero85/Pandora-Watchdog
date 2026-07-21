# Pandora® Watchdog

**by AKI_SystemDown® © 2026**

Ein PyQt6-Tray-Tool für Kali Linux / Raspberry Pi (getestet auf Pi 4B, 8GB),
das zwei Aufgaben in einer Anwendung vereint:

1. **Metadaten-Bereinigung** – überwacht einen Ordner und entfernt bei jeder
   neuen Foto-/Videodatei automatisch EXIF, GPS, IPTC und Container-Metadaten.
2. **Injektions-Wächter** – überwacht typische Einfallstore (Downloads, `/tmp`,
   Desktop – frei konfigurierbar) auf jede neu auftauchende Datei, prüft sie
   auf mehrere Verdachtsmomente und zeigt alle Funde in einer persistenten
   Übersicht an, aus der heraus gezielt in Quarantäne verschoben, ignoriert
   (Whitelist) oder endgültig gelöscht werden kann.

Zusätzlich überwacht ein **Persistenz-Wächter** sensible Systemorte
(`.bashrc`, `.ssh/authorized_keys`, Autostart, Cron, systemd-User-Units) auf
unerwartete Änderungen – ein klassisches Indiz für eingenistete Malware.

> ⚠️ Dieses Tool ist rein **defensiv**. Es führt keine Angriffe aus, umgeht
> keine Schutzmaßnahmen und liefert keine Anleitungen dazu. Es erkennt,
> zeigt an und lässt den Nutzer selbst entscheiden.

---

## Features im Überblick

### Ordner-Wächter (Metadaten)
- Automatische EXIF/GPS/IPTC-Entfernung bei Bildern (Pillow)
- Automatisches Metadaten-Remuxing bei Videos (ffmpeg, `-map_metadata -1`)
- Konfigurierbares Löschen des Originals nach erfolgreicher Bereinigung
- Live-Statusanzeige im Tray-Icon (grün/gelb/rot)

### Injektions-Wächter
- Überwachung beliebig vieler Ordner auf **jede** neu auftauchende Datei
- Baseline-Scan bereits vorhandener Dateien
- Herkunfts-Ermittlung über `xdg.origin.url` (Browser-/wget-/curl-Metadaten)
- SHA256-Hashing jeder Datei
- Optionale ClamAV-Signaturprüfung
- **Magic-Bytes-Analyse**: erkennt Endungs-Spoofing (z. B. eine `.jpg`, die
  tatsächlich ein ELF-Binary oder Shell-Skript ist)
- **Doppel-Endungs-Erkennung** (`rechnung.pdf.exe`, `foto.jpg.sh` …)
- **Ausführungsrechte-Prüfung** bei eigentlich harmlosen Dateitypen
- **Optionale YARA-Regelprüfung** (`yara-python`), Regeln liegen lokal unter
  `~/.pandora_watchdog/yara_rules/`
- Automatische **Risiko-Ampel** (unauffällig / VERDÄCHTIG / GEFÄHRLICH) aus
  allen obigen Indikatoren
- Optionale KI-Einschätzung per Gemini (verschlüsselt gespeicherter API-Key),
  mit Kontext aus dem öffentlichen "Anthropic-Cybersecurity-Skills"-Repo
  (Community-Projekt, nicht von Anthropic PBC)

### Persistenz-Wächter
- Periodisches Hash-Polling sensibler Orte:
  `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile`,
  `~/.ssh/authorized_keys`, `~/.config/autostart`, `~/.config/systemd/user`,
  `/etc/crontab`, `/etc/rc.local`
- Meldet jede Abweichung von der gespeicherten Baseline sofort per Tray-Alarm

### Umgang mit Funden
- **Nichts wird automatisch gelöscht** – jede Aktion erfordert eine explizite
  Bestätigung
- **Quarantäne statt Löschen**: isolierter Ordner (`0700`), inkl.
  Wiederherstellungs-Dialog mit ursprünglichem Pfad
- **Ignorierliste (Whitelist)** per SHA256-Hash oder Namensmuster
- **CSV-Export** aller Funde für Audit-Zwecke
- Verlaufs-Log aller Aktionen unter `~/.pandora_watchdog/verlauf.log`

---

## Installation

```bash
git clone https://github.com/bosancero85/Pandora-Watchdog.git
cd Pandora-Watchdog
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Für die Video-Metadaten-Bereinigung:
```bash
sudo apt install ffmpeg
```

Optional, aber empfohlen für die Signaturprüfung:
```bash
sudo apt install clamav
sudo freshclam   # Signaturen aktualisieren
```

Optional für eigene YARA-Regeln:
```bash
pip install yara-python
```

## Start

```bash
python3 pandora_watchdog.py
```

Das Tool legt sich als Icon in die System-Tray. Rechtsklick öffnet das Menü
mit allen Funktionen (Ordner wählen, Wächter starten/stoppen, erkannte
Dateien anzeigen, Quarantäne verwalten, Ignorierliste verwalten, Gemini
API-Key hinterlegen, Verlauf anzeigen).

### Autostart (optional)

Für den Desktop-Autostart liegt eine fertige `.desktop`-Datei bereit:
```bash
cp autostart/pandora-watchdog.desktop ~/.config/autostart/
```

Alternativ als systemd-User-Dienst:
```bash
mkdir -p ~/.config/systemd/user
cp systemd/pandora-watchdog.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now pandora-watchdog.service
```
(Pfad in der `.service`-Datei ggf. an den Klon-Ort anpassen.)

## Eigene YARA-Regeln

Einfach `.yar`/`.yara`-Dateien nach `~/.pandora_watchdog/yara_rules/` legen –
sie werden beim nächsten Start automatisch kompiliert und geladen. Ein
harmloses Beispiel liegt unter [`yara_rules/beispiel_regel.yar`](yara_rules/beispiel_regel.yar).

## Konfiguration & Datenablage

Alles liegt unter `~/.pandora_watchdog/`:

| Datei/Ordner              | Inhalt                                          |
|----------------------------|-------------------------------------------------|
| `config.json`              | alle Einstellungen (Ordner, Whitelist, Optionen) |
| `verlauf.log`               | Verlauf aller Aktionen                          |
| `quarantaene/`              | isolierte, verschobene Dateien + Metadaten-JSON |
| `yara_rules/`                | eigene YARA-Regeln                              |
| `.vaultkey` / `gemini.key`  | Fernet-verschlüsselter Gemini API-Key           |
| `persistenz_baseline.json`  | Baseline-Hashes der überwachten Persistenz-Orte |

## Lizenz

Siehe [LICENSE](LICENSE).

---
**Pandora® Watchdog** — Teil des Pandora®-Projekt-Portfolios von
AKI_SystemDown® © 2026.
