#!/usr/bin/env python3
"""
================================================================================
 PANDORA® WATCHDOG | by AKI_SystemDown® © 2026
 Plattform: Raspberry Pi 4B (8GB) / Kali Linux
 Autor:     AKI_SystemDown® © 2026

 Funktion:
   1) Ordner-Watcher: ueberwacht einen Ordner via watchdog, entfernt bei jeder
      neuen Foto-/Videodatei automatisch alle Metadaten (EXIF, GPS, IPTC,
      Container-Metadata bei Videos) und verschiebt sie in einen "Clean"-Ordner.

   2) Injektions-Waechter: ueberwacht mehrere typische "Einfallstore"
      (Downloads-Ordner, /tmp, Desktop - frei konfigurierbar) auf JEDE neu
      auftauchende Datei, egal woher sie kommt. Zusaetzlich kann ein
      Baseline-Scan bereits vorhandene Dateien in diesen Ordnern erfassen.

      Fuer jeden Fund werden ermittelt:
        - Herkunfts-URL (falls Browser/wget/curl sie als xdg-Metadaten
          gesetzt haben) -> daraus Host, Port, Protokoll
        - SHA256-Hash
        - ClamAV-Signaturpruefung (falls clamscan installiert ist)
        - Gemini-Risikoeinschaetzung (SICHER/VERDAECHTIG/GEFAEHRLICH) mit
          Hintergrundwissen aus dem oeffentlichen "Anthropic-Cybersecurity-
          Skills" Repo (Community-Projekt, nicht von Anthropic PBC) - nur
          Skill-Titel/Beschreibungen als Kontext, keine Angriffs-Anleitungen

      Zusaetzlich zu ClamAV und Gemini wird jede Datei technisch gegen
      mehrere Injektions-Indikatoren geprueft:
        - Magic-Bytes-Analyse: deckt Endungs-Spoofing auf (z.B. eine ".jpg",
          die tatsaechlich ein ELF-Binary oder Shell-Skript ist)
        - Doppel-Endungs-Erkennung (z.B. "rechnung.pdf.exe")
        - Ausfuehrungsrecht bei eigentlich harmlosen Endungen (Bild/PDF/Office)
        - Optionale YARA-Regelpruefung, falls yara-python installiert ist und
          eigene Regeln unter ~/.pandora_watchdog/yara_rules liegen
      Aus all dem wird eine Ampel-Risikoeinstufung (unauffaellig /
      VERDAECHTIG / GEFAEHRLICH) berechnet und farbig in der Tabelle
      angezeigt.

      Alle Funde landen in einem persistenten "Erkannte Dateien"-Fenster
      (Tabelle mit Zeit, Pfad, Herkunft, Host:Port, Typ, ClamAV-, Risiko- und
      Gemini-Status). Es wird NIE automatisch geloescht - Auswahl per
      Checkbox + expliziter Bestaetigungsdialog. Statt sofortigem Loeschen
      koennen Dateien wahlweise in eine lokale Quarantaene verschoben werden
      (mit Wiederherstellungs-Option), oder per Hash/Namensmuster dauerhaft
      auf eine Ignorierliste (Whitelist) gesetzt werden. Ergebnisse lassen
      sich als CSV fuer Audit-Zwecke exportieren.

   3) Persistenz-Waechter: ueberwacht zusaetzlich periodisch sensible
      Systemorte, ueber die sich injizierter Code dauerhaft einnisten kann
      (~/.bashrc, ~/.profile, ~/.ssh/authorized_keys, Autostart-Ordner,
      systemd-User-Units, /etc/crontab, /etc/rc.local) und meldet jede
      Aenderung gegenueber einer gespeicherten Baseline.

   Ein Tray-Icon im Pandora-Stil zeigt den Live-Status aller Dienste
   (gruen = laeuft, gelb = verarbeitet gerade, rot = gestoppt).

 Abhaengigkeiten:
   pip install PyQt6 watchdog Pillow requests cryptography
   ffmpeg zusaetzlich fuer Video-Bereinigung:  sudo apt install ffmpeg
   ClamAV optional, aber empfohlen:            sudo apt install clamav
   yara-python optional, fuer eigene Regeln:   pip install yara-python
   Herkunfts-Erkennung nutzt os.getxattr (Linux xdg.origin.url) - wird von
   Firefox/Chromium/wget --xattr/curl --xattr beim Download gesetzt. Fehlt
   das Attribut, wird die Herkunft als "unbekannt" ausgewiesen statt geraten.
================================================================================
"""

import sys
import os
import json
import time
import stat
import shutil
import hashlib
import fnmatch
import csv
import subprocess
import threading
from datetime import datetime
from urllib.parse import urlparse

import requests
from cryptography.fernet import Fernet

try:
    import yara  # yara-python - optional
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from PyQt6.QtWidgets import (
    QApplication,
    QSystemTrayIcon,
    QMenu,
    QFileDialog,
    QMessageBox,
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QInputDialog,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QCheckBox,
    QListWidget,
    QComboBox,
)
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QAction, QFont, QBrush
from PyQt6.QtCore import Qt, QObject, pyqtSignal, QThread, QTimer

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ---------------------------------------------------------------------------
# KONFIGURATION / PFADE
# ---------------------------------------------------------------------------
CONFIG_DIR = os.path.expanduser("~/.pandora_watchdog")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
LOG_FILE = os.path.join(CONFIG_DIR, "verlauf.log")
KEYRING_FILE = os.path.join(CONFIG_DIR, ".vaultkey")
API_KEY_FILE = os.path.join(CONFIG_DIR, "gemini.key")
SKILLS_CACHE_FILE = os.path.join(CONFIG_DIR, "skills_index_cache.json")
QUARANTINE_DIR = os.path.join(CONFIG_DIR, "quarantaene")
YARA_RULES_DIR = os.path.join(CONFIG_DIR, "yara_rules")
PERSISTENCE_BASELINE_FILE = os.path.join(CONFIG_DIR, "persistenz_baseline.json")
DETECTIONS_EXPORT_DIR = os.path.expanduser("~/Pandora_Exporte")

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".bmp"}
VIDEO_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".m4v"}
IGNORE_SUFFIXES = (".part", ".crdownload", ".tmp", ".download")

# Erwartete "harmlose" Endungen, bei denen ein gesetztes Ausfuehrungsrecht
# hoechst ungewoehnlich ist und auf Manipulation/Injektion hindeuten kann.
NON_EXEC_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".json", ".xml", ".zip",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".odt", ".ods", ".rtf",
}

# Endungen, die typischerweise ausfuehrbar/skriptfaehig sind - relevant fuer
# die Doppel-Endungs-Pruefung (z.B. "rechnung.pdf.exe" oder "foto.jpg.sh").
EXECUTABLE_LIKE_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".msi", ".sh", ".bash", ".py",
    ".pl", ".php", ".js", ".vbs", ".ps1", ".jar", ".deb", ".rpm", ".appimage",
    ".elf", ".bin", ".run", ".apk", ".desktop",
}

# Magic-Bytes fuer haeufige Dateiformate -> zur Erkennung von Endungs-Spoofing
# (Datei behauptet z.B. ".jpg" zu sein, ist aber tatsaechlich ein Skript/ELF).
MAGIC_SIGNATURES = [
    (b"\x7fELF", "ELF-Binary (Linux-Executable)"),
    (b"MZ", "Windows-PE/EXE"),
    (b"%PDF-", "PDF-Dokument"),
    (b"PK\x03\x04", "ZIP/Office-Container (docx/xlsx/jar/apk...)"),
    (b"\xff\xd8\xff", "JPEG-Bild"),
    (b"\x89PNG\r\n\x1a\n", "PNG-Bild"),
    (b"GIF87a", "GIF-Bild"),
    (b"GIF89a", "GIF-Bild"),
    (b"#!/", "Shell/Interpreter-Skript (Shebang)"),
    (b"\xca\xfe\xba\xbe", "Java-Class-Datei"),
    (b"\x1f\x8b", "GZIP-Archiv"),
    (b"7z\xbc\xaf\x27\x1c", "7z-Archiv"),
    (b"Rar!\x1a\x07", "RAR-Archiv"),
]

EXT_TO_MAGIC_LABEL = {
    ".jpg": "JPEG-Bild", ".jpeg": "JPEG-Bild", ".png": "PNG-Bild",
    ".gif": "GIF-Bild", ".pdf": "PDF-Dokument",
    ".docx": "ZIP/Office-Container (docx/xlsx/jar/apk...)",
    ".xlsx": "ZIP/Office-Container (docx/xlsx/jar/apk...)",
    ".pptx": "ZIP/Office-Container (docx/xlsx/jar/apk...)",
    ".zip": "ZIP/Office-Container (docx/xlsx/jar/apk...)",
    ".jar": "ZIP/Office-Container (docx/xlsx/jar/apk...)",
    ".apk": "ZIP/Office-Container (docx/xlsx/jar/apk...)",
    ".exe": "Windows-PE/EXE",
    ".gz": "GZIP-Archiv", ".7z": "7z-Archiv", ".rar": "RAR-Archiv",
}

# Sensible Dateien/Persistenz-Orte, die ein Angreifer typischerweise
# veraendert, um sich dauerhaft einzunisten (Autostart, Shell-Rc, Cron, SSH).
def default_persistence_paths():
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".bashrc"),
        os.path.join(home, ".zshrc"),
        os.path.join(home, ".profile"),
        os.path.join(home, ".bash_profile"),
        os.path.join(home, ".ssh", "authorized_keys"),
        os.path.join(home, ".config", "autostart"),
        "/etc/crontab",
        "/etc/rc.local",
        os.path.join(home, ".config", "systemd", "user"),
    ]
    return [p for p in candidates if os.path.exists(p)]

BG_DARK = "#0d0d12"
BG_PANEL = "#1b1b28"
BORDER = "#3a3a50"
TEXT = "#d8d8e0"
ACCENT = "#00e0c0"
COLOR_OK = "#00e0c0"
COLOR_STOPPED = "#e05050"
COLOR_BUSY = "#e0c000"


def ensure_dirs():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(YARA_RULES_DIR, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, 0o700)
        os.chmod(QUARANTINE_DIR, 0o700)
    except Exception:
        pass


def default_watch_paths():
    candidates = [os.path.expanduser("~/Downloads"), "/tmp", os.path.expanduser("~/Desktop")]
    return [p for p in candidates if os.path.isdir(p)]


def _default_config():
    return {
        "watch_dir": "",
        "clean_dir": "",
        "delete_original": False,
        "watch_paths": default_watch_paths(),
        "injection_watch_enabled": False,
        "ignore_hashes": [],
        "ignore_patterns": [],
        "quarantine_instead_of_delete": True,
        "persistence_paths": default_persistence_paths(),
        "persistence_watch_enabled": False,
        "persistence_poll_seconds": 20,
        "yara_enabled": True,
    }


def load_config():
    ensure_dirs()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                defaults = _default_config()
                for key, val in defaults.items():
                    cfg.setdefault(key, val)
                return cfg
        except Exception:
            pass
    return _default_config()


def save_config(cfg):
    ensure_dirs()
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def log_event(text):
    ensure_dirs()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {text}\n")


# ---------------------------------------------------------------------------
# METADATEN-BEREINIGUNG (Ordner-Watcher)
# ---------------------------------------------------------------------------
def strip_image_metadata(src_path, dst_path):
    if not PIL_AVAILABLE:
        shutil.copy2(src_path, dst_path)
        return False, "Pillow nicht installiert - Datei unveraendert kopiert"
    try:
        with Image.open(src_path) as img:
            data = list(img.getdata())
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(data)
            save_kwargs = {}
            ext = os.path.splitext(dst_path)[1].lower()
            if ext in (".jpg", ".jpeg"):
                save_kwargs["quality"] = 95
            clean_img.save(dst_path, **save_kwargs)
        return True, "EXIF/GPS/IPTC entfernt"
    except Exception as e:
        return False, f"Fehler: {e}"


def strip_video_metadata(src_path, dst_path):
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        shutil.copy2(src_path, dst_path)
        return False, "ffmpeg nicht gefunden - Datei unveraendert kopiert"
    try:
        result = subprocess.run(
            [ffmpeg, "-y", "-i", src_path, "-map_metadata", "-1", "-c", "copy", dst_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
        )
        if result.returncode != 0:
            shutil.copy2(src_path, dst_path)
            return False, "ffmpeg-Fehler - Datei unveraendert kopiert"
        return True, "Metadaten entfernt (Remux)"
    except Exception as e:
        shutil.copy2(src_path, dst_path)
        return False, f"Fehler: {e}"


class WatcherSignals(QObject):
    file_processed = pyqtSignal(str, bool, str)
    status_changed = pyqtSignal(str)


class MetadataStripperHandler(FileSystemEventHandler):
    def __init__(self, clean_dir, signals, delete_original=False):
        super().__init__()
        self.clean_dir = clean_dir
        self.signals = signals
        self.delete_original = delete_original

    def on_created(self, event):
        if event.is_directory:
            return
        threading.Thread(target=self._process, args=(event.src_path,), daemon=True).start()

    def on_moved(self, event):
        if event.is_directory:
            return
        threading.Thread(target=self._process, args=(event.dest_path,), daemon=True).start()

    def _wait_until_stable(self, path, checks=3, interval=0.5):
        last_size = -1
        stable_count = 0
        for _ in range(120):
            if not os.path.exists(path):
                return False
            size = os.path.getsize(path)
            if size == last_size and size > 0:
                stable_count += 1
                if stable_count >= checks:
                    return True
            else:
                stable_count = 0
            last_size = size
            time.sleep(interval)
        return os.path.exists(path)

    @staticmethod
    def _unique_path(path):
        if not os.path.exists(path):
            return path
        base, ext = os.path.splitext(path)
        i = 1
        while os.path.exists(f"{base}_{i}{ext}"):
            i += 1
        return f"{base}_{i}{ext}"

    def _process(self, src_path):
        filename = os.path.basename(src_path)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in IMAGE_EXTS and ext not in VIDEO_EXTS:
            return

        self.signals.status_changed.emit("busy")
        if not self._wait_until_stable(src_path):
            self.signals.file_processed.emit(filename, False, "Datei verschwunden vor Bearbeitung")
            self.signals.status_changed.emit("running")
            return

        os.makedirs(self.clean_dir, exist_ok=True)
        dst_path = self._unique_path(os.path.join(self.clean_dir, filename))

        if ext in IMAGE_EXTS:
            ok, info = strip_image_metadata(src_path, dst_path)
        else:
            ok, info = strip_video_metadata(src_path, dst_path)

        if ok and self.delete_original:
            try:
                os.remove(src_path)
            except Exception:
                pass

        log_event(f"{filename}: {info}")
        self.signals.file_processed.emit(filename, ok, info)
        self.signals.status_changed.emit("running")


# ---------------------------------------------------------------------------
# SECURE VAULT - verschluesselte Speicherung des Gemini API-Keys
# ---------------------------------------------------------------------------
class SecureVault:
    def __init__(self):
        ensure_dirs()
        self._fernet = Fernet(self._load_or_create_key())

    def _load_or_create_key(self):
        if os.path.exists(KEYRING_FILE):
            with open(KEYRING_FILE, "rb") as f:
                return f.read()
        key = Fernet.generate_key()
        with open(KEYRING_FILE, "wb") as f:
            f.write(key)
        os.chmod(KEYRING_FILE, 0o600)
        return key

    def has_api_key(self):
        return os.path.exists(API_KEY_FILE)

    def load_api_key(self):
        if not os.path.exists(API_KEY_FILE):
            return None
        try:
            with open(API_KEY_FILE, "rb") as f:
                token = f.read()
            return self._fernet.decrypt(token).decode("utf-8")
        except Exception:
            return None

    def save_api_key(self, api_key):
        token = self._fernet.encrypt(api_key.encode("utf-8"))
        tmp = API_KEY_FILE + ".tmp"
        with open(tmp, "wb") as f:
            f.write(token)
        os.chmod(tmp, 0o600)
        os.replace(tmp, API_KEY_FILE)


# ---------------------------------------------------------------------------
# SKILL LIBRARY - Erkennungswissen aus dem oeffentlichen
# "Anthropic-Cybersecurity-Skills" Repo (Community-Projekt, nicht Anthropic
# PBC) - es werden nur Titel/Beschreibungen als Kontext genutzt.
# ---------------------------------------------------------------------------
class SkillLibrary:
    INDEX_URL = "https://raw.githubusercontent.com/mukul975/Anthropic-Cybersecurity-Skills/main/index.json"

    DEFENSIVE_HINTS = (
        "detecting", "analyzing", "hunting", "monitoring", "defending",
        "forensics", "incident-response", "response", "identifying",
        "investigating", "correlating", "triaging", "hardening", "securing",
        "malware", "phishing", "download",
    )

    def __init__(self):
        ensure_dirs()
        self.skills = self._load_index()

    def _load_index(self):
        try:
            resp = requests.get(self.INDEX_URL, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            with open(SKILLS_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f)
            return data.get("skills", [])
        except Exception:
            if os.path.exists(SKILLS_CACHE_FILE):
                try:
                    with open(SKILLS_CACHE_FILE, "r", encoding="utf-8") as f:
                        return json.load(f).get("skills", [])
                except Exception:
                    pass
            return []

    def defensive_context(self):
        relevant = []
        for s in self.skills:
            name = (s.get("name") or "").lower()
            desc = (s.get("description") or "").lower()
            if any(h in name or h in desc for h in self.DEFENSIVE_HINTS):
                relevant.append(f"- {s.get('name')}: {s.get('description')}")
            if len(relevant) >= 12:
                break
        if not relevant:
            return "Keine passenden Erkennungs-Skills geladen (Repo nicht erreichbar oder leer)."
        return "\n".join(relevant)


# ---------------------------------------------------------------------------
# CLAMAV - optionale lokale Signaturpruefung einzelner Dateien
# ---------------------------------------------------------------------------
def clamav_scan(path):
    clamscan = shutil.which("clamscan")
    if not clamscan:
        return None, "ClamAV (clamscan) nicht installiert"
    try:
        result = subprocess.run(
            [clamscan, "--no-summary", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        output = result.stdout.decode(errors="ignore").strip()
        if "FOUND" in output:
            return True, output
        return False, "Kein Signaturfund"
    except Exception as e:
        return None, f"ClamAV-Fehler: {e}"


# ---------------------------------------------------------------------------
# GEMINI CLIENT - liefert eine reine Risiko-Einschaetzung, keine Aktionen
# ---------------------------------------------------------------------------
class GeminiClient:
    ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def __init__(self, api_key, model="gemini-2.0-flash"):
        self.api_key = api_key
        self.model = model

    def assess_file(self, info, skill_context):
        prompt = (
            "Du bist ein rein defensives Sicherheits-Modul. Bewerte NUR das Risiko "
            "der folgenden Datei, die in einem ueberwachten Ordner aufgetaucht ist. "
            "Antworte mit einer Einstufung (SICHER / VERDAECHTIG / GEFAEHRLICH) und "
            "2-3 Saetzen Begruendung. Liefere unter keinen Umstaenden Anleitungen zum "
            "Ausfuehren von Angriffen oder zur Umgehung von Schutzmassnahmen.\n\n"
            f"Ueberwachter Ordner: {info['source_dir']}\n"
            f"Dateiname: {info['name']}\n"
            f"Dateityp: {info['ext']}\n"
            f"Groesse: {info['size']} Bytes\n"
            f"Herkunfts-URL: {info['url']}\n"
            f"Host: {info['host']}   Port: {info['port']}   Protokoll: {info['scheme']}\n"
            f"SHA256: {info['hash']}\n"
            f"ClamAV-Ergebnis: {info['clamav_msg']}\n"
            f"Echter Dateityp (Magic-Bytes): {info.get('real_type', 'unbekannt')}\n"
            f"Endung vs. echter Typ passt nicht zusammen: {info.get('ext_mismatch', False)}\n"
            f"Verdaechtige doppelte Endung: {info.get('double_ext', False)}\n"
            f"Ausfuehrungsrecht bei untypischer Endung gesetzt: {info.get('exec_flag', False)}\n"
            f"YARA-Regel-Treffer: {', '.join(info.get('yara_matches', [])) or 'keine'}\n"
            f"Automatische Vorab-Einstufung: {info.get('risk_level', 'unauffaellig')} "
            f"({info.get('risk_reason', '-')})\n\n"
            f"Hintergrundwissen (Erkennungs-Skills, nur zur Einordnung):\n{skill_context}\n"
        )
        try:
            resp = requests.post(
                self.ENDPOINT.format(model=self.model),
                params={"key": self.api_key},
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except Exception as e:
            return f"Gemini-Anfrage fehlgeschlagen: {e}"


class GeminiWorker(QThread):
    result_ready = pyqtSignal(str, dict)

    def __init__(self, client, info, skill_context):
        super().__init__()
        self.client = client
        self.info = info
        self.skill_context = skill_context

    def run(self):
        text = self.client.assess_file(self.info, self.skill_context)
        self.result_ready.emit(text, self.info)


# ---------------------------------------------------------------------------
# HERKUNFTS-ERMITTLUNG (xdg-Metadaten, die Browser beim Download setzen)
# ---------------------------------------------------------------------------
def get_origin_url(path):
    for attr in ("user.xdg.origin.url", "user.xdg.referrer.url"):
        try:
            val = os.getxattr(path, attr)
            return val.decode("utf-8", errors="ignore")
        except (OSError, AttributeError):
            continue
    return None


def parse_origin(url):
    if not url:
        return {"host": "unbekannt", "port": "unbekannt", "scheme": "unbekannt"}
    try:
        p = urlparse(url)
        port = p.port
        if not port:
            port = 443 if p.scheme == "https" else 80 if p.scheme == "http" else "unbekannt"
        return {"host": p.hostname or "unbekannt", "port": port, "scheme": p.scheme or "unbekannt"}
    except Exception:
        return {"host": "unbekannt", "port": "unbekannt", "scheme": "unbekannt"}


def sha256_of(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unbekannt"


def detect_real_type(path):
    """Liest die ersten Bytes einer Datei und vergleicht sie mit bekannten
    Magic-Bytes, um den tatsaechlichen Dateityp unabhaengig von der
    (moeglicherweise gefaelschten) Endung zu ermitteln."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except Exception:
        return None
    for sig, label in MAGIC_SIGNATURES:
        if head.startswith(sig):
            return label
    return None


def check_extension_mismatch(path, ext):
    """Vergleicht die deklarierte Endung mit dem via Magic-Bytes ermittelten
    tatsaechlichen Typ. Klassisches Indiz fuer Endungs-Spoofing bei injizierten
    Dateien (z.B. eine .jpg, die eigentlich ein Shell-Skript ist)."""
    real_type = detect_real_type(path)
    if real_type is None:
        return False, None
    expected_label = EXT_TO_MAGIC_LABEL.get(ext)
    if expected_label and real_type != expected_label:
        return True, real_type
    if ext in NON_EXEC_EXTS and real_type in (
        "ELF-Binary (Linux-Executable)", "Windows-PE/EXE",
        "Shell/Interpreter-Skript (Shebang)",
    ):
        return True, real_type
    return False, real_type


def check_double_extension(name):
    """Erkennt doppelte Endungen wie 'rechnung.pdf.exe' oder 'foto.jpg.sh',
    ein klassisches Social-Engineering-/Injektions-Muster."""
    parts = name.lower().split(".")
    if len(parts) < 3:
        return False
    last_ext = "." + parts[-1]
    inner_ext = "." + parts[-2]
    return last_ext in EXECUTABLE_LIKE_EXTS and inner_ext not in EXECUTABLE_LIKE_EXTS


def check_exec_flag(path, ext):
    """Prueft, ob fuer eine eigentlich harmlose Endung (Bild, PDF, Office...)
    das Ausfuehrungsrecht gesetzt ist - unueblich und ein moegliches Zeichen
    fuer eine manipulierte/injizierte Datei."""
    if ext not in NON_EXEC_EXTS:
        return False
    try:
        mode = os.stat(path).st_mode
        return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except Exception:
        return False


class YaraScanner:
    """Optionale YARA-Regel-Pruefung. Regeln (.yar/.yara) koennen einfach in
    den Ordner YARA_RULES_DIR gelegt werden - es wird niemals automatisch aus
    dem Internet nachgeladen."""

    def __init__(self):
        self.rules = None
        if not YARA_AVAILABLE:
            return
        rule_files = {}
        try:
            for fname in os.listdir(YARA_RULES_DIR):
                if fname.endswith((".yar", ".yara")):
                    rule_files[fname] = os.path.join(YARA_RULES_DIR, fname)
        except Exception:
            pass
        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
            except Exception:
                self.rules = None

    def scan(self, path):
        if not self.rules:
            return []
        try:
            matches = self.rules.match(path, timeout=10)
            return [m.rule for m in matches]
        except Exception:
            return []


def is_ignored(info, cfg):
    """Prueft, ob eine Datei per Hash oder Namensmuster auf der
    Ignorier-/Whitelist steht (vom Nutzer bewusst als unbedenklich markiert)."""
    if info["hash"] in cfg.get("ignore_hashes", []):
        return True
    for pattern in cfg.get("ignore_patterns", []):
        if fnmatch.fnmatch(info["name"], pattern) or fnmatch.fnmatch(info["path"], pattern):
            return True
    return False


def compute_risk(info):
    """Aggregiert alle Einzel-Indikatoren zu einem einfachen Ampel-Score:
    0=unbedenklich, 1=auffaellig, 2=hoch verdaechtig/gefaehrlich."""
    score = 0
    reasons = []
    if info.get("clamav_ok") is True:
        score += 3
        reasons.append("ClamAV-Signaturfund")
    if info.get("ext_mismatch"):
        score += 2
        reasons.append(f"Endung taeuscht Typ vor (echt: {info.get('real_type')})")
    if info.get("double_ext"):
        score += 2
        reasons.append("Doppelte/verschleiernde Dateiendung")
    if info.get("exec_flag"):
        score += 2
        reasons.append("Ausfuehrungsrecht bei untypischer Endung gesetzt")
    if info.get("yara_matches"):
        score += 3
        reasons.append(f"YARA-Treffer: {', '.join(info['yara_matches'])}")
    if score >= 4:
        level = "GEFAEHRLICH"
    elif score >= 1:
        level = "VERDAECHTIG"
    else:
        level = "unauffaellig"
    return level, "; ".join(reasons) if reasons else "keine Auffaelligkeiten"


def quarantine_file(path):
    """Verschiebt eine Datei statt sie zu loeschen in einen isolierten
    Quarantaene-Ordner (0700, keine Ausfuehrungsrechte) und legt eine
    JSON-Sidecar-Datei mit dem urspruenglichen Pfad fuer eine spaetere
    Wiederherstellung an."""
    ensure_dirs()
    name = os.path.basename(path)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = os.path.join(QUARANTINE_DIR, f"{ts}_{name}")
    i = 1
    while os.path.exists(dst):
        dst = os.path.join(QUARANTINE_DIR, f"{ts}_{i}_{name}")
        i += 1
    shutil.move(path, dst)
    try:
        os.chmod(dst, 0o600)
    except Exception:
        pass
    with open(dst + ".meta.json", "w", encoding="utf-8") as f:
        json.dump({"original_path": path, "quarantined_at": ts}, f)
    return dst


def restore_from_quarantine(quarantine_path):
    meta_path = quarantine_path + ".meta.json"
    if not os.path.exists(meta_path):
        raise FileNotFoundError("Keine Metadaten fuer diese Quarantaene-Datei gefunden.")
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    original = meta["original_path"]
    os.makedirs(os.path.dirname(original), exist_ok=True)
    dst = original
    if os.path.exists(dst):
        base, ext = os.path.splitext(dst)
        dst = f"{base}_wiederhergestellt{ext}"
    shutil.move(quarantine_path, dst)
    os.remove(meta_path)
    return dst


_yara_scanner_instance = None


def get_yara_scanner():
    global _yara_scanner_instance
    if _yara_scanner_instance is None:
        _yara_scanner_instance = YaraScanner()
    return _yara_scanner_instance


def build_file_info(path, source_dir, yara_enabled=True):
    name = os.path.basename(path)
    url = get_origin_url(path)
    origin = parse_origin(url)
    ext = os.path.splitext(name)[1].lower() or "(ohne Endung)"
    try:
        size = os.path.getsize(path)
    except Exception:
        size = 0
    clam_ok, clam_msg = clamav_scan(path)
    ext_mismatch, real_type = check_extension_mismatch(path, ext)
    double_ext = check_double_extension(name)
    exec_flag = check_exec_flag(path, ext)
    yara_matches = []
    if yara_enabled and YARA_AVAILABLE:
        yara_matches = get_yara_scanner().scan(path)

    info = {
        "path": path,
        "name": name,
        "ext": ext,
        "size": size,
        "url": url or "unbekannt",
        "host": origin["host"],
        "port": origin["port"],
        "scheme": origin["scheme"],
        "hash": sha256_of(path),
        "source_dir": source_dir,
        "clamav_ok": clam_ok,   # True=Fund, False=sauber, None=nicht verfuegbar
        "clamav_msg": clam_msg,
        "real_type": real_type,
        "ext_mismatch": ext_mismatch,
        "double_ext": double_ext,
        "exec_flag": exec_flag,
        "yara_matches": yara_matches,
        "detected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    level, reason = compute_risk(info)
    info["risk_level"] = level
    info["risk_reason"] = reason
    return info


# ---------------------------------------------------------------------------
# INJEKTIONS-WAECHTER - ueberwacht mehrere Ordner auf JEDE neue Datei
# ---------------------------------------------------------------------------
class InjectionSignals(QObject):
    new_detection = pyqtSignal(dict)
    status_changed = pyqtSignal(str)


class InjectionFileHandler(FileSystemEventHandler):
    def __init__(self, watch_root, signals, cfg=None):
        super().__init__()
        self.watch_root = watch_root
        self.signals = signals
        self.cfg = cfg or {}

    def on_created(self, event):
        if event.is_directory:
            return
        threading.Thread(target=self._process, args=(event.src_path,), daemon=True).start()

    def on_moved(self, event):
        if event.is_directory:
            return
        threading.Thread(target=self._process, args=(event.dest_path,), daemon=True).start()

    def _wait_until_stable(self, path, checks=3, interval=0.5):
        last_size = -1
        stable = 0
        for _ in range(240):
            if not os.path.exists(path):
                return False
            size = os.path.getsize(path)
            if size == last_size and size > 0:
                stable += 1
                if stable >= checks:
                    return True
            else:
                stable = 0
            last_size = size
            time.sleep(interval)
        return os.path.exists(path)

    def _process(self, path):
        name = os.path.basename(path)
        if any(name.endswith(suf) for suf in IGNORE_SUFFIXES):
            return  # noch nicht fertig heruntergeladen

        self.signals.status_changed.emit("busy")
        if not self._wait_until_stable(path):
            self.signals.status_changed.emit("running")
            return

        info = build_file_info(path, self.watch_root, yara_enabled=self.cfg.get("yara_enabled", True))
        if is_ignored(info, self.cfg):
            self.signals.status_changed.emit("running")
            return
        log_event(
            f"Injektions-Fund: {info['name']} in {self.watch_root} "
            f"(Herkunft {info['host']}:{info['port']}, ClamAV: {info['clamav_msg']}, "
            f"Risiko: {info['risk_level']})"
        )
        self.signals.new_detection.emit(info)
        self.signals.status_changed.emit("running")


def scan_existing_files(watch_paths, signals, cfg=None, max_per_dir=200):
    """Baseline-Scan: erfasst bereits vorhandene Dateien in den ueberwachten
    Ordnern (z.B. Dateien, die schon vor dem Start des Waechters dort lagen)."""
    cfg = cfg or {}

    def _worker():
        for root_dir in watch_paths:
            if not os.path.isdir(root_dir):
                continue
            try:
                entries = sorted(os.listdir(root_dir))[:max_per_dir]
            except Exception:
                continue
            for name in entries:
                full = os.path.join(root_dir, name)
                if os.path.isdir(full) or any(name.endswith(s) for s in IGNORE_SUFFIXES):
                    continue
                info = build_file_info(full, root_dir, yara_enabled=cfg.get("yara_enabled", True))
                if is_ignored(info, cfg):
                    continue
                info["baseline"] = True
                signals.new_detection.emit(info)

    threading.Thread(target=_worker, daemon=True).start()


# ---------------------------------------------------------------------------
# PERSISTENZ-WAECHTER - erkennt Veraenderungen an sensiblen Dateien, ueber die
# sich injizierter Code dauerhaft einnisten kann (Shell-Rc, Autostart, Cron,
# SSH authorized_keys, systemd-User-Units). Arbeitet per Hash-Polling, da
# watchdog auf einzelnen Dateien ausserhalb der Watch-Ordner nicht greift.
# ---------------------------------------------------------------------------
def _hash_persistence_target(path):
    """Fuer Dateien: SHA256. Fuer Ordner (z.B. autostart/systemd/user):
    kombinierter Hash aus Dateiliste + Einzel-Hashes, damit auch neu
    hinzugefuegte Dateien in solchen Ordnern auffallen."""
    if os.path.isdir(path):
        parts = []
        try:
            for fname in sorted(os.listdir(path)):
                full = os.path.join(path, fname)
                if os.path.isfile(full):
                    parts.append(f"{fname}:{sha256_of(full)}")
        except Exception:
            pass
        h = hashlib.sha256("|".join(parts).encode("utf-8"))
        return h.hexdigest()
    if os.path.isfile(path):
        return sha256_of(path)
    return None


def load_persistence_baseline():
    if os.path.exists(PERSISTENCE_BASELINE_FILE):
        try:
            with open(PERSISTENCE_BASELINE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_persistence_baseline(baseline):
    ensure_dirs()
    with open(PERSISTENCE_BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)


class PersistenceSignals(QObject):
    change_detected = pyqtSignal(str, str)  # path, meldung


class PersistenceWatcher(QObject):
    """Prueft periodisch (QTimer) eine Liste sensibler Pfade auf Aenderungen
    gegen eine gespeicherte Baseline und meldet Abweichungen - klassische
    Erkennung von Persistenz-Injektion (z.B. neue Zeile in .bashrc, neuer
    Autostart-Eintrag, neuer SSH-Key)."""

    def __init__(self, paths, poll_seconds=20):
        super().__init__()
        self.paths = paths
        self.signals = PersistenceSignals()
        self.baseline = load_persistence_baseline()
        self.timer = QTimer()
        self.timer.setInterval(max(5, poll_seconds) * 1000)
        self.timer.timeout.connect(self._check_all)

    def start(self):
        for p in self.paths:
            if p not in self.baseline:
                self.baseline[p] = _hash_persistence_target(p)
        save_persistence_baseline(self.baseline)
        self.timer.start()

    def stop(self):
        self.timer.stop()

    def _check_all(self):
        for p in self.paths:
            current = _hash_persistence_target(p)
            previous = self.baseline.get(p)
            if current is not None and previous is not None and current != previous:
                log_event(f"Persistenz-Aenderung erkannt: {p}")
                self.signals.change_detected.emit(
                    p, f"Datei/Ordner '{p}' wurde veraendert - moeglicher Persistenz-Mechanismus!"
                )
            self.baseline[p] = current
        save_persistence_baseline(self.baseline)


# ---------------------------------------------------------------------------
# DIALOGE
# ---------------------------------------------------------------------------
class WatchedFoldersDialog(QDialog):
    def __init__(self, paths, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pandora® - Ueberwachte Ordner")
        self.setStyleSheet(f"""
            QDialog {{ background-color: {BG_DARK}; color: {TEXT}; font-family: 'Consolas', monospace; }}
            QListWidget {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; color: {TEXT}; }}
            QPushButton {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 4px;
                           padding: 6px 12px; color: {TEXT}; }}
            QPushButton:hover {{ border: 1px solid {ACCENT}; }}
        """)
        self.resize(480, 320)
        self.paths = list(paths)

        layout = QVBoxLayout(self)
        self.list_widget = QListWidget()
        self.list_widget.addItems(self.paths)
        layout.addWidget(self.list_widget)

        btn_row = QHBoxLayout()
        btn_add = QPushButton("Ordner hinzufuegen...")
        btn_add.clicked.connect(self._add_folder)
        btn_remove = QPushButton("Ausgewaehlten entfernen")
        btn_remove.clicked.connect(self._remove_folder)
        btn_close = QPushButton("Schliessen")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_add)
        btn_row.addWidget(btn_remove)
        btn_row.addStretch()
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)

    def _add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Ordner hinzufuegen")
        if d and d not in self.paths:
            self.paths.append(d)
            self.list_widget.addItem(d)

    def _remove_folder(self):
        row = self.list_widget.currentRow()
        if row >= 0:
            self.list_widget.takeItem(row)
            del self.paths[row]


class IgnoreListDialog(QDialog):
    """Verwaltung der Whitelist: per SHA256-Hash (exakte Datei) oder per
    Namensmuster (z.B. '*.torrent' oder ein bestimmter Ordnerpfad)."""

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.setWindowTitle("Pandora® - Ignorierliste (Whitelist)")
        self.setStyleSheet(f"""
            QDialog {{ background-color: {BG_DARK}; color: {TEXT}; font-family: 'Consolas', monospace; }}
            QListWidget {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; color: {TEXT}; }}
            QLabel {{ color: {TEXT}; }}
            QLineEdit {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; color: {TEXT}; padding: 4px; }}
            QPushButton {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 4px;
                           padding: 6px 12px; color: {TEXT}; }}
            QPushButton:hover {{ border: 1px solid {ACCENT}; }}
        """)
        self.resize(560, 420)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Ignorierte Hashes (exakte, per SHA256 bestaetigte Dateien):"))
        self.hash_list = QListWidget()
        self.hash_list.addItems(self.cfg.get("ignore_hashes", []))
        layout.addWidget(self.hash_list)
        btn_remove_hash = QPushButton("Ausgewaehlten Hash entfernen")
        btn_remove_hash.clicked.connect(self._remove_hash)
        layout.addWidget(btn_remove_hash)

        layout.addWidget(QLabel("Ignorierte Namensmuster (z.B. *.log, /tmp/build_*):"))
        self.pattern_list = QListWidget()
        self.pattern_list.addItems(self.cfg.get("ignore_patterns", []))
        layout.addWidget(self.pattern_list)

        add_row = QHBoxLayout()
        self.pattern_input = QLineEdit()
        self.pattern_input.setPlaceholderText("z.B. *.log oder *build_cache*")
        btn_add_pattern = QPushButton("Muster hinzufuegen")
        btn_add_pattern.clicked.connect(self._add_pattern)
        add_row.addWidget(self.pattern_input)
        add_row.addWidget(btn_add_pattern)
        layout.addLayout(add_row)
        btn_remove_pattern = QPushButton("Ausgewaehltes Muster entfernen")
        btn_remove_pattern.clicked.connect(self._remove_pattern)
        layout.addWidget(btn_remove_pattern)

        btn_close = QPushButton("Schliessen und speichern")
        btn_close.clicked.connect(self._save_and_close)
        layout.addWidget(btn_close)

    def _remove_hash(self):
        row = self.hash_list.currentRow()
        if row >= 0:
            self.hash_list.takeItem(row)

    def _add_pattern(self):
        text = self.pattern_input.text().strip()
        if text:
            self.pattern_list.addItem(text)
            self.pattern_input.clear()

    def _remove_pattern(self):
        row = self.pattern_list.currentRow()
        if row >= 0:
            self.pattern_list.takeItem(row)

    def _save_and_close(self):
        self.cfg["ignore_hashes"] = [self.hash_list.item(i).text() for i in range(self.hash_list.count())]
        self.cfg["ignore_patterns"] = [self.pattern_list.item(i).text() for i in range(self.pattern_list.count())]
        save_config(self.cfg)
        self.accept()


class QuarantineManagerDialog(QDialog):
    """Zeigt alle Dateien im isolierten Quarantaene-Ordner und erlaubt gezielte
    Wiederherstellung an den urspruenglichen Ort oder endgueltiges Loeschen."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pandora® - Quarantaene-Ordner")
        self.setStyleSheet(f"""
            QDialog {{ background-color: {BG_DARK}; color: {TEXT}; font-family: 'Consolas', monospace; }}
            QTableWidget {{ background-color: {BG_PANEL}; gridline-color: {BORDER};
                             border: 1px solid {BORDER}; color: {TEXT}; }}
            QHeaderView::section {{ background-color: {BG_PANEL}; color: {ACCENT}; padding: 4px; border: none; }}
            QPushButton {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 4px;
                           padding: 6px 12px; color: {TEXT}; }}
            QPushButton:hover {{ border: 1px solid {ACCENT}; }}
            QLabel {{ color: {TEXT}; }}
        """)
        self.resize(760, 400)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"Quarantaene-Ordner: {QUARANTINE_DIR}"))

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Datei in Quarantaene", "Urspruenglicher Pfad"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        self._reload()

        btn_row = QHBoxLayout()
        btn_restore = QPushButton("Wiederherstellen")
        btn_restore.clicked.connect(self._restore_selected)
        btn_delete = QPushButton("Endgueltig loeschen")
        btn_delete.clicked.connect(self._delete_selected)
        btn_refresh = QPushButton("Aktualisieren")
        btn_refresh.clicked.connect(self._reload)
        btn_row.addWidget(btn_restore)
        btn_row.addWidget(btn_delete)
        btn_row.addStretch()
        btn_row.addWidget(btn_refresh)
        layout.addLayout(btn_row)

    def _reload(self):
        self.table.setRowCount(0)
        self.entries = []
        try:
            files = sorted(f for f in os.listdir(QUARANTINE_DIR) if not f.endswith(".meta.json"))
        except Exception:
            files = []
        for fname in files:
            full = os.path.join(QUARANTINE_DIR, fname)
            meta_path = full + ".meta.json"
            original = "unbekannt"
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        original = json.load(f).get("original_path", "unbekannt")
                except Exception:
                    pass
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(fname))
            self.table.setItem(row, 1, QTableWidgetItem(original))
            self.entries.append(full)

    def _selected_path(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.entries):
            return None
        return self.entries[row]

    def _restore_selected(self):
        path = self._selected_path()
        if not path:
            QMessageBox.information(self, "Hinweis", "Bitte eine Datei auswaehlen.")
            return
        try:
            dst = restore_from_quarantine(path)
            log_event(f"Datei aus Quarantaene wiederhergestellt: {dst}")
            QMessageBox.information(self, "Wiederhergestellt", f"Datei wiederhergestellt nach:\n{dst}")
            self._reload()
        except Exception as e:
            QMessageBox.warning(self, "Fehler", str(e))

    def _delete_selected(self):
        path = self._selected_path()
        if not path:
            QMessageBox.information(self, "Hinweis", "Bitte eine Datei auswaehlen.")
            return
        reply = QMessageBox.question(
            self, "Endgueltig loeschen bestaetigen",
            f"{os.path.basename(path)} unwiderruflich aus der Quarantaene loeschen?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                os.remove(path)
                meta = path + ".meta.json"
                if os.path.exists(meta):
                    os.remove(meta)
                log_event(f"Quarantaene-Datei endgueltig geloescht: {path}")
                self._reload()
            except Exception as e:
                QMessageBox.warning(self, "Fehler", str(e))


class DetectionDetailDialog(QDialog):
    """Detailansicht + Loesch-Bestaetigung fuer einen einzelnen Fund."""

    def __init__(self, info, gemini_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pandora® - Datei-Details")
        self.info = info
        self.decision_delete = False
        self.decision_quarantine = True
        self.decision_ignore = False
        self.setStyleSheet(f"""
            QDialog {{ background-color: {BG_DARK}; color: {TEXT}; font-family: 'Consolas', monospace; }}
            QLabel {{ color: {TEXT}; }}
            QTextEdit {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; color: {TEXT}; }}
            QPushButton {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 4px;
                           padding: 6px 12px; color: {TEXT}; }}
            QPushButton:hover {{ border: 1px solid {ACCENT}; }}
        """)
        self.resize(680, 560)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"Datei: {info['name']}  ({info['ext']}, {info['size'] / 1024:.1f} KB)"))
        layout.addWidget(QLabel(f"Ordner: {info['source_dir']}"))
        layout.addWidget(QLabel(f"Herkunfts-URL: {info['url']}"))
        layout.addWidget(QLabel(f"Host: {info['host']}    Port: {info['port']}    Protokoll: {info['scheme']}"))
        layout.addWidget(QLabel(f"SHA256: {info['hash']}"))
        layout.addWidget(QLabel(f"ClamAV: {info['clamav_msg']}"))

        risk_color = DetectionsWindow.RISK_COLORS.get(info.get("risk_level", "unauffaellig"), TEXT)
        risk_label = QLabel(f"Risiko-Einstufung: {info.get('risk_level', 'unauffaellig')}")
        risk_label.setStyleSheet(f"color: {risk_color}; font-weight: bold;")
        layout.addWidget(risk_label)
        layout.addWidget(QLabel(f"Begruendung: {info.get('risk_reason', '-')}"))

        details = []
        if info.get("real_type"):
            details.append(f"Erkannter echter Dateityp (Magic-Bytes): {info['real_type']}")
        if info.get("ext_mismatch"):
            details.append("⚠ Endung stimmt NICHT mit dem echten Dateityp ueberein!")
        if info.get("double_ext"):
            details.append("⚠ Verdaechtige doppelte Dateiendung erkannt!")
        if info.get("exec_flag"):
            details.append("⚠ Ausfuehrungsrecht bei untypischer Dateiendung gesetzt!")
        if info.get("yara_matches"):
            details.append(f"⚠ YARA-Regel-Treffer: {', '.join(info['yara_matches'])}")
        if details:
            detail_label = QLabel("\n".join(details))
            detail_label.setWordWrap(True)
            layout.addWidget(detail_label)

        layout.addWidget(QLabel("Gemini-Einschaetzung (mit Anthropic-Cybersecurity-Skills als Kontext):"))
        gemini_box = QTextEdit()
        gemini_box.setReadOnly(True)
        gemini_box.setPlainText(gemini_text or "Noch keine Einschaetzung verfuegbar.")
        layout.addWidget(gemini_box)

        btn_row = QHBoxLayout()
        btn_ignore = QPushButton("Als unbedenklich markieren (Whitelist)")
        btn_ignore.clicked.connect(self._confirm_ignore)
        btn_quarantine = QPushButton("In Quarantaene verschieben...")
        btn_quarantine.clicked.connect(self._confirm_quarantine)
        btn_delete = QPushButton("Endgueltig loeschen...")
        btn_delete.clicked.connect(self._confirm_delete)
        btn_close = QPushButton("Schliessen")
        btn_close.clicked.connect(self.reject)
        btn_row.addWidget(btn_ignore)
        btn_row.addStretch()
        btn_row.addWidget(btn_quarantine)
        btn_row.addWidget(btn_delete)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)

    def _confirm_ignore(self):
        reply = QMessageBox.question(
            self, "Whitelist bestaetigen",
            f"{self.info['name']} (Hash-basiert) dauerhaft als unbedenklich markieren?\n"
            f"Die Datei wird dann bei kuenftigen Scans nicht mehr gemeldet.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.decision_ignore = True
            self.accept()

    def _confirm_quarantine(self):
        reply = QMessageBox.question(
            self, "Quarantaene bestaetigen",
            f"{self.info['name']} in die Quarantaene verschieben?\n"
            f"Herkunft: {self.info['host']}:{self.info['port']} ({self.info['url']})",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.decision_delete = True
            self.decision_quarantine = True
            self.accept()

    def _confirm_delete(self):
        reply = QMessageBox.question(
            self, "Loeschen bestaetigen",
            f"{self.info['name']} UNWIDERRUFLICH loeschen (keine Quarantaene)?\n\n"
            f"Herkunft: {self.info['host']}:{self.info['port']} ({self.info['url']})",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.decision_delete = True
            self.decision_quarantine = False
            self.accept()


class DetectionsWindow(QDialog):
    """Persistente Uebersicht aller erkannten Dateien (Downloads, /tmp,
    Desktop, Baseline-Scan usw.). Anzeigen + gezieltes Loeschen nach
    Auswahl und Bestaetigung."""

    COLS = ["", "Zeit", "Ordner", "Datei", "Herkunft (Host:Port)", "Typ", "KB",
            "ClamAV", "Risiko", "Gemini"]

    RISK_COLORS = {
        "GEFAEHRLICH": "#e05050",
        "VERDAECHTIG": "#e0c000",
        "unauffaellig": "#00e0c0",
    }

    def __init__(self, cfg=None, parent=None):
        super().__init__(parent)
        self.cfg = cfg if cfg is not None else {}
        self.setWindowTitle("Pandora® - Erkannte Dateien")
        self.setStyleSheet(f"""
            QDialog {{ background-color: {BG_DARK}; color: {TEXT}; font-family: 'Consolas', monospace; }}
            QTableWidget {{ background-color: {BG_PANEL}; gridline-color: {BORDER};
                             border: 1px solid {BORDER}; color: {TEXT}; }}
            QHeaderView::section {{ background-color: {BG_PANEL}; color: {ACCENT}; padding: 4px; border: none; }}
            QPushButton {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 4px;
                           padding: 6px 12px; color: {TEXT}; }}
            QPushButton:hover {{ border: 1px solid {ACCENT}; }}
            QLabel {{ color: {TEXT}; }}
        """)
        self.resize(1020, 480)
        self.rows_info = []  # Liste von info-dicts, Index == Zeilennummer

        layout = QVBoxLayout(self)

        top_row = QHBoxLayout()
        self.cb_select_all = QCheckBox("Alle auswaehlen")
        self.cb_select_all.stateChanged.connect(self._toggle_select_all)
        top_row.addWidget(self.cb_select_all)
        top_row.addStretch()
        layout.addLayout(top_row)

        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(9, QHeaderView.ResizeMode.Stretch)
        self.table.cellDoubleClicked.connect(self._show_details)
        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        btn_delete = QPushButton("Ausgewaehlte endgueltig loeschen...")
        btn_delete.clicked.connect(lambda: self._delete_selected(force_permanent=True))
        btn_quarantine = QPushButton("Ausgewaehlte in Quarantaene...")
        btn_quarantine.clicked.connect(self._quarantine_selected)
        btn_ignore = QPushButton("Ausgewaehlte ignorieren (Whitelist)")
        btn_ignore.clicked.connect(self._ignore_selected)
        btn_export = QPushButton("Als CSV exportieren...")
        btn_export.clicked.connect(self._export_csv)
        btn_clear = QPushButton("Liste leeren (ohne zu loeschen)")
        btn_clear.clicked.connect(self._clear_list)
        btn_row.addWidget(btn_quarantine)
        btn_row.addWidget(btn_delete)
        btn_row.addWidget(btn_ignore)
        btn_row.addWidget(btn_export)
        btn_row.addStretch()
        btn_row.addWidget(btn_clear)
        layout.addLayout(btn_row)

    def _toggle_select_all(self, state):
        checked = state == Qt.CheckState.Checked.value
        for row in range(self.table.rowCount()):
            cb = self.table.cellWidget(row, 0)
            if isinstance(cb, QCheckBox):
                cb.setChecked(checked)

    def _selected_rows_and_infos(self):
        rows, infos = [], []
        for row in range(self.table.rowCount()):
            cb = self.table.cellWidget(row, 0)
            if isinstance(cb, QCheckBox) and cb.isChecked():
                rows.append(row)
                infos.append(self.rows_info[row])
        return rows, infos

    def add_detection(self, info):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.rows_info.append(info)

        cb = QCheckBox()
        self.table.setCellWidget(row, 0, cb)
        ts = info.get("detected_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")).split(" ")[-1]
        origin = f"{info['host']}:{info['port']}" if info["host"] != "unbekannt" else "unbekannt"
        values = [ts, info["source_dir"], info["name"], origin, info["ext"], f"{info['size'] / 1024:.1f}"]
        for col, val in enumerate(values, start=1):
            self.table.setItem(row, col, QTableWidgetItem(str(val)))

        clam_text = "Fund!" if info["clamav_ok"] else ("sauber" if info["clamav_ok"] is False else "n/a")
        self.table.setItem(row, 7, QTableWidgetItem(clam_text))

        risk_level = info.get("risk_level", "unauffaellig")
        risk_item = QTableWidgetItem(risk_level)
        color = self.RISK_COLORS.get(risk_level, TEXT)
        risk_item.setForeground(QBrush(QColor(color)))
        risk_item.setToolTip(info.get("risk_reason", ""))
        self.table.setItem(row, 8, risk_item)

        self.table.setItem(row, 9, QTableWidgetItem("Gemini laeuft..." if info.get("gemini_pending") else "-"))

    def update_gemini(self, path, text):
        for row, info in enumerate(self.rows_info):
            if info["path"] == path:
                info["gemini_text"] = text
                short = text.splitlines()[0][:60] if text else "-"
                self.table.setItem(row, 9, QTableWidgetItem(short))
                return

    def _show_details(self, row, _col):
        if row >= len(self.rows_info):
            return
        info = self.rows_info[row]
        dlg = DetectionDetailDialog(info, info.get("gemini_text", ""), parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.decision_delete:
            self._delete_files([info], [row], quarantine=dlg.decision_quarantine)
        elif dlg.decision_ignore:
            self._ignore_infos([info])

    def _delete_selected(self, force_permanent=False):
        selected_rows, selected_infos = self._selected_rows_and_infos()
        if not selected_infos:
            QMessageBox.information(self, "Hinweis", "Keine Dateien ausgewaehlt.")
            return
        names = "\n".join(f["name"] for f in selected_infos[:15])
        more = f"\n... und {len(selected_infos) - 15} weitere" if len(selected_infos) > 15 else ""
        reply = QMessageBox.question(
            self, "Loeschen bestaetigen",
            f"{len(selected_infos)} Datei(en) UNWIDERRUFLICH loeschen (keine Quarantaene)?\n\n{names}{more}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._delete_files(selected_infos, selected_rows, quarantine=False)

    def _quarantine_selected(self):
        selected_rows, selected_infos = self._selected_rows_and_infos()
        if not selected_infos:
            QMessageBox.information(self, "Hinweis", "Keine Dateien ausgewaehlt.")
            return
        names = "\n".join(f["name"] for f in selected_infos[:15])
        more = f"\n... und {len(selected_infos) - 15} weitere" if len(selected_infos) > 15 else ""
        reply = QMessageBox.question(
            self, "Quarantaene bestaetigen",
            f"{len(selected_infos)} Datei(en) in die Quarantaene verschieben?\n"
            f"(Kann spaeter im Quarantaene-Ordner wiederhergestellt werden)\n\n{names}{more}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._delete_files(selected_infos, selected_rows, quarantine=True)

    def _delete_files(self, infos, rows, quarantine=True):
        done, failed = 0, 0
        for info in infos:
            try:
                if quarantine:
                    quarantine_file(info["path"])
                    log_event(f"Datei in Quarantaene verschoben: {info['name']} aus {info['source_dir']} "
                              f"(Herkunft {info['host']}:{info['port']})")
                else:
                    os.remove(info["path"])
                    log_event(f"Datei geloescht: {info['name']} aus {info['source_dir']} "
                              f"(Herkunft {info['host']}:{info['port']})")
                done += 1
            except Exception as e:
                failed += 1
                log_event(f"Aktion fehlgeschlagen: {info['name']} - {e}")
        for row in sorted(rows, reverse=True):
            self.table.removeRow(row)
            del self.rows_info[row]
        aktion = "in Quarantaene verschoben" if quarantine else "endgueltig geloescht"
        QMessageBox.information(self, "Erledigt", f"{done} Datei(en) {aktion}, {failed} fehlgeschlagen.")

    def _ignore_selected(self):
        _, selected_infos = self._selected_rows_and_infos()
        if not selected_infos:
            QMessageBox.information(self, "Hinweis", "Keine Dateien ausgewaehlt.")
            return
        self._ignore_infos(selected_infos)

    def _ignore_infos(self, infos):
        added = 0
        for info in infos:
            if info["hash"] not in self.cfg.setdefault("ignore_hashes", []):
                self.cfg["ignore_hashes"].append(info["hash"])
                added += 1
        save_config(self.cfg)
        QMessageBox.information(
            self, "Ignorierliste",
            f"{added} Datei(en) per SHA256-Hash zur Whitelist hinzugefuegt.\n"
            f"Diese werden bei zukuenftigen Scans nicht mehr gemeldet.",
        )

    def _export_csv(self):
        if not self.rows_info:
            QMessageBox.information(self, "Hinweis", "Keine Eintraege zum Exportieren vorhanden.")
            return
        os.makedirs(DETECTIONS_EXPORT_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(
            self, "CSV exportieren",
            os.path.join(DETECTIONS_EXPORT_DIR, f"pandora_erkannte_dateien_{ts}.csv"),
            "CSV-Dateien (*.csv)",
        )
        if not path:
            return
        fields = ["detected_at", "source_dir", "name", "host", "port", "ext", "size",
                  "hash", "clamav_msg", "risk_level", "risk_reason", "url"]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for info in self.rows_info:
                    writer.writerow(info)
            QMessageBox.information(self, "Export erfolgreich", f"Exportiert nach:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export fehlgeschlagen", str(e))

    def _clear_list(self):
        self.table.setRowCount(0)
        self.rows_info.clear()


# ---------------------------------------------------------------------------
# TRAY-ICON (Pandora-Stil)
# ---------------------------------------------------------------------------
def make_status_icon(color_hex):
    pix = QPixmap(64, 64)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(QColor(BG_PANEL)))
    painter.setPen(QColor(BORDER))
    painter.drawRoundedRect(2, 2, 60, 60, 14, 14)
    painter.setBrush(QBrush(QColor(color_hex)))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(16, 16, 32, 32)
    painter.end()
    return QIcon(pix)


class PandoraWatchdogTray(QObject):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.cfg = load_config()
        self.observer = None
        self.injection_observer = None
        self.persistence_watcher = None
        self.vault = SecureVault()
        self.skill_library = None
        self._gemini_workers = []
        self.detections_window = None

        api_key = self.vault.load_api_key()
        self.gemini_client = GeminiClient(api_key) if api_key else None

        self.signals = WatcherSignals()
        self.signals.file_processed.connect(self._on_file_processed)
        self.signals.status_changed.connect(self._set_status)

        self.injection_signals = InjectionSignals()
        self.injection_signals.new_detection.connect(self._on_new_detection)
        self.injection_signals.status_changed.connect(self._set_status)

        self.icon_running = make_status_icon(COLOR_OK)
        self.icon_stopped = make_status_icon(COLOR_STOPPED)
        self.icon_busy = make_status_icon(COLOR_BUSY)

        self.tray = QSystemTrayIcon(self.icon_stopped)
        self.tray.setToolTip("Pandora® Watchdog - gestoppt")
        self._build_menu()
        self.tray.show()

        if self.cfg.get("watch_dir") and self.cfg.get("clean_dir"):
            self.start_watching()
        if self.cfg.get("injection_watch_enabled"):
            self.start_injection_watch()
        if self.cfg.get("persistence_watch_enabled"):
            self.start_persistence_watch()

        if not YARA_AVAILABLE:
            log_event("Hinweis: yara-python nicht installiert - YARA-Regelpruefung deaktiviert "
                       "(pip install yara-python fuer zusaetzliche Erkennung).")

    def _get_detections_window(self):
        if self.detections_window is None:
            self.detections_window = DetectionsWindow(cfg=self.cfg)
        return self.detections_window

    def _build_menu(self):
        menu = QMenu()
        menu.setStyleSheet(f"""
            QMenu {{ background-color: {BG_DARK}; color: {TEXT}; border: 1px solid {BORDER};
                      font-family: 'Consolas', monospace; }}
            QMenu::item {{ padding: 6px 20px; }}
            QMenu::item:selected {{ background-color: {BG_PANEL}; color: {ACCENT}; }}
            QMenu::separator {{ height: 1px; background: {BORDER}; margin: 4px 0; }}
        """)

        self.act_status = QAction("Status: gestoppt", menu)
        self.act_status.setEnabled(False)
        menu.addAction(self.act_status)
        menu.addSeparator()

        act_watch_dir = QAction("Watch-Ordner waehlen...", menu)
        act_watch_dir.triggered.connect(self.choose_watch_dir)
        menu.addAction(act_watch_dir)

        act_clean_dir = QAction("Clean-Ordner waehlen...", menu)
        act_clean_dir.triggered.connect(self.choose_clean_dir)
        menu.addAction(act_clean_dir)

        self.act_delete_original = QAction("Original nach Bereinigung loeschen", menu)
        self.act_delete_original.setCheckable(True)
        self.act_delete_original.setChecked(self.cfg.get("delete_original", False))
        self.act_delete_original.triggered.connect(self._toggle_delete_original)
        menu.addAction(self.act_delete_original)

        self.act_toggle = QAction("Ordner-Dienst starten", menu)
        self.act_toggle.triggered.connect(self.toggle_watching)
        menu.addAction(self.act_toggle)

        menu.addSeparator()

        act_manage_paths = QAction("Ueberwachte Ordner verwalten...", menu)
        act_manage_paths.triggered.connect(self.manage_watch_paths)
        menu.addAction(act_manage_paths)

        self.act_injection_toggle = QAction("Injektions-Waechter starten", menu)
        self.act_injection_toggle.triggered.connect(self.toggle_injection_watch)
        menu.addAction(self.act_injection_toggle)

        act_baseline = QAction("Baseline-Scan jetzt ausfuehren", menu)
        act_baseline.triggered.connect(self.run_baseline_scan)
        menu.addAction(act_baseline)

        act_show_detections = QAction("Erkannte Dateien anzeigen", menu)
        act_show_detections.triggered.connect(self.show_detections_window)
        menu.addAction(act_show_detections)

        act_gemini_key = QAction("Gemini API-Key hinterlegen...", menu)
        act_gemini_key.triggered.connect(self.set_gemini_key)
        menu.addAction(act_gemini_key)

        menu.addSeparator()

        act_manage_persistence = QAction("Persistenz-Orte verwalten (Autostart/Bashrc/SSH...)...", menu)
        act_manage_persistence.triggered.connect(self.manage_persistence_paths)
        menu.addAction(act_manage_persistence)

        self.act_persistence_toggle = QAction("Persistenz-Waechter starten", menu)
        self.act_persistence_toggle.triggered.connect(self.toggle_persistence_watch)
        menu.addAction(self.act_persistence_toggle)

        menu.addSeparator()

        act_quarantine = QAction("Quarantaene-Ordner verwalten...", menu)
        act_quarantine.triggered.connect(self.show_quarantine_manager)
        menu.addAction(act_quarantine)

        act_ignore_list = QAction("Ignorierliste (Whitelist) verwalten...", menu)
        act_ignore_list.triggered.connect(self.manage_ignore_list)
        menu.addAction(act_ignore_list)

        self.act_yara_toggle = QAction(f"YARA-Regelpruefung aktiv{'' if YARA_AVAILABLE else ' (yara-python fehlt)'}", menu)
        self.act_yara_toggle.setCheckable(True)
        self.act_yara_toggle.setChecked(self.cfg.get("yara_enabled", True))
        self.act_yara_toggle.setEnabled(YARA_AVAILABLE)
        self.act_yara_toggle.triggered.connect(self._toggle_yara)
        menu.addAction(self.act_yara_toggle)

        menu.addSeparator()

        act_log = QAction("Verlauf anzeigen", menu)
        act_log.triggered.connect(self.show_log)
        menu.addAction(act_log)

        menu.addSeparator()

        act_quit = QAction("Beenden", menu)
        act_quit.triggered.connect(self.quit)
        menu.addAction(act_quit)

        self.tray.setContextMenu(menu)

    # --- Ordner-Watcher (EXIF/Video) ----------------------------------------
    def choose_watch_dir(self):
        d = QFileDialog.getExistingDirectory(None, "Watch-Ordner waehlen")
        if d:
            self.cfg["watch_dir"] = d
            save_config(self.cfg)
            if self.observer:
                self.stop_watching()
                self.start_watching()

    def choose_clean_dir(self):
        d = QFileDialog.getExistingDirectory(None, "Clean-Ordner waehlen")
        if d:
            self.cfg["clean_dir"] = d
            save_config(self.cfg)

    def _toggle_delete_original(self, checked):
        self.cfg["delete_original"] = checked
        save_config(self.cfg)
        if self.observer and hasattr(self.observer, "_stripper_handler"):
            self.observer._stripper_handler.delete_original = checked

    def toggle_watching(self):
        if self.observer:
            self.stop_watching()
        else:
            self.start_watching()

    def start_watching(self):
        watch_dir = self.cfg.get("watch_dir")
        clean_dir = self.cfg.get("clean_dir")
        if not watch_dir or not os.path.isdir(watch_dir):
            QMessageBox.warning(None, "Pandora Watchdog", "Bitte zuerst einen gueltigen Watch-Ordner waehlen.")
            return
        if not clean_dir:
            QMessageBox.warning(None, "Pandora Watchdog", "Bitte zuerst einen Clean-Ordner waehlen.")
            return

        handler = MetadataStripperHandler(clean_dir, self.signals, self.cfg.get("delete_original", False))
        self.observer = Observer()
        self.observer._stripper_handler = handler
        self.observer.schedule(handler, watch_dir, recursive=False)
        self.observer.start()

        self.act_toggle.setText("Ordner-Dienst stoppen")
        self._set_status("running")
        self.tray.showMessage(
            "Pandora® Watchdog", f"Ueberwachung aktiv: {watch_dir}",
            QSystemTrayIcon.MessageIcon.Information, 3000,
        )

    def stop_watching(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
            self.observer = None
        self.act_toggle.setText("Ordner-Dienst starten")
        self._set_status("stopped")

    def _set_status(self, status):
        if status == "running":
            self.tray.setIcon(self.icon_running)
            self.tray.setToolTip("Pandora® Watchdog - laeuft")
            self.act_status.setText("Status: laeuft")
        elif status == "busy":
            self.tray.setIcon(self.icon_busy)
            self.tray.setToolTip("Pandora® Watchdog - verarbeitet...")
            self.act_status.setText("Status: verarbeitet...")
        else:
            self.tray.setIcon(self.icon_stopped)
            self.tray.setToolTip("Pandora® Watchdog - gestoppt")
            self.act_status.setText("Status: gestoppt")

    def _on_file_processed(self, filename, ok, info):
        icon = QSystemTrayIcon.MessageIcon.Information if ok else QSystemTrayIcon.MessageIcon.Warning
        self.tray.showMessage("Pandora® Watchdog", f"{filename}: {info}", icon, 4000)

    # --- Injektions-Waechter --------------------------------------------------
    def manage_watch_paths(self):
        dlg = WatchedFoldersDialog(self.cfg.get("watch_paths", []))
        if dlg.exec():
            self.cfg["watch_paths"] = dlg.paths
            save_config(self.cfg)
            if self.injection_observer:
                self.stop_injection_watch()
                self.start_injection_watch()

    def set_gemini_key(self):
        key, ok = QInputDialog.getText(
            None, "Gemini API-Key", "API-Key eingeben:", QLineEdit.EchoMode.Password
        )
        if ok and key:
            self.vault.save_api_key(key)
            self.gemini_client = GeminiClient(key)
            QMessageBox.information(None, "Gemini", "API-Key gespeichert - wird ab jetzt fuer die Einschaetzung genutzt.")

    def toggle_injection_watch(self):
        if self.injection_observer:
            self.stop_injection_watch()
        else:
            self.start_injection_watch()

    def start_injection_watch(self):
        paths = [p for p in self.cfg.get("watch_paths", []) if os.path.isdir(p)]
        if not paths:
            QMessageBox.warning(None, "Injektions-Waechter", "Keine gueltigen Ordner konfiguriert.")
            return
        if self.skill_library is None:
            self.skill_library = SkillLibrary()

        self.injection_observer = Observer()
        for root_dir in paths:
            handler = InjectionFileHandler(root_dir, self.injection_signals, self.cfg)
            self.injection_observer.schedule(handler, root_dir, recursive=False)
        self.injection_observer.start()

        self.cfg["injection_watch_enabled"] = True
        save_config(self.cfg)
        self.act_injection_toggle.setText("Injektions-Waechter stoppen")
        self._set_status("running")
        self.tray.showMessage(
            "Pandora® Injektions-Waechter",
            f"Ueberwachung aktiv: {', '.join(paths)}"
            + (" (Gemini aktiv)" if self.gemini_client else " (kein Gemini API-Key hinterlegt)"),
            QSystemTrayIcon.MessageIcon.Information, 4000,
        )

    def stop_injection_watch(self):
        if self.injection_observer:
            self.injection_observer.stop()
            self.injection_observer.join(timeout=3)
            self.injection_observer = None
        self.cfg["injection_watch_enabled"] = False
        save_config(self.cfg)
        self.act_injection_toggle.setText("Injektions-Waechter starten")

    def run_baseline_scan(self):
        paths = [p for p in self.cfg.get("watch_paths", []) if os.path.isdir(p)]
        if not paths:
            QMessageBox.warning(None, "Baseline-Scan", "Keine gueltigen Ordner konfiguriert.")
            return
        if self.skill_library is None:
            self.skill_library = SkillLibrary()
        self.tray.showMessage(
            "Pandora® Injektions-Waechter", "Baseline-Scan gestartet...",
            QSystemTrayIcon.MessageIcon.Information, 3000,
        )
        scan_existing_files(paths, self.injection_signals, self.cfg)

    def _on_new_detection(self, info):
        window = self._get_detections_window()
        info["gemini_pending"] = bool(self.gemini_client)
        window.add_detection(info)

        origin = f"{info['host']}:{info['port']}" if info["host"] != "unbekannt" else "unbekannt"
        clam_note = " | ClamAV-FUND!" if info["clamav_ok"] else ""
        self.tray.showMessage(
            "Pandora® Injektions-Waechter",
            f"{info['name']} in {info['source_dir']} (Herkunft: {origin}){clam_note}",
            QSystemTrayIcon.MessageIcon.Warning if info["clamav_ok"] else QSystemTrayIcon.MessageIcon.Information,
            5000,
        )

        if self.gemini_client:
            context = self.skill_library.defensive_context() if self.skill_library else ""
            worker = GeminiWorker(self.gemini_client, info, context)
            self._gemini_workers.append(worker)

            def _on_ready(text, i, w=worker):
                if w in self._gemini_workers:
                    self._gemini_workers.remove(w)
                if self.detections_window:
                    self.detections_window.update_gemini(i["path"], text)

            worker.result_ready.connect(_on_ready)
            worker.start()

    # --- Persistenz-Waechter --------------------------------------------------
    def manage_persistence_paths(self):
        dlg = WatchedFoldersDialog(self.cfg.get("persistence_paths", []))
        dlg.setWindowTitle("Pandora® - Ueberwachte Persistenz-Orte")
        if dlg.exec():
            self.cfg["persistence_paths"] = dlg.paths
            save_config(self.cfg)
            if self.persistence_watcher:
                self.stop_persistence_watch()
                self.start_persistence_watch()

    def toggle_persistence_watch(self):
        if self.persistence_watcher:
            self.stop_persistence_watch()
        else:
            self.start_persistence_watch()

    def start_persistence_watch(self):
        paths = self.cfg.get("persistence_paths", [])
        if not paths:
            QMessageBox.warning(self.tray, "Persistenz-Waechter", "Keine Persistenz-Orte konfiguriert.")
            return
        self.persistence_watcher = PersistenceWatcher(
            paths, self.cfg.get("persistence_poll_seconds", 20)
        )
        self.persistence_watcher.signals.change_detected.connect(self._on_persistence_change)
        self.persistence_watcher.start()
        self.cfg["persistence_watch_enabled"] = True
        save_config(self.cfg)
        self.act_persistence_toggle.setText("Persistenz-Waechter stoppen")
        self.tray.showMessage(
            "Pandora® Persistenz-Waechter",
            f"Ueberwachung aktiv fuer {len(paths)} Ort(e): {', '.join(paths[:3])}"
            + (" ..." if len(paths) > 3 else ""),
            QSystemTrayIcon.MessageIcon.Information, 4000,
        )

    def stop_persistence_watch(self):
        if self.persistence_watcher:
            self.persistence_watcher.stop()
            self.persistence_watcher = None
        self.cfg["persistence_watch_enabled"] = False
        save_config(self.cfg)
        self.act_persistence_toggle.setText("Persistenz-Waechter starten")

    def _on_persistence_change(self, path, message):
        self.tray.showMessage(
            "Pandora® Persistenz-Waechter - ACHTUNG", message,
            QSystemTrayIcon.MessageIcon.Warning, 8000,
        )
        QMessageBox.warning(None, "Persistenz-Aenderung erkannt", message)

    def show_quarantine_manager(self):
        dlg = QuarantineManagerDialog()
        dlg.exec()

    def manage_ignore_list(self):
        dlg = IgnoreListDialog(self.cfg)
        dlg.exec()

    def _toggle_yara(self, checked):
        self.cfg["yara_enabled"] = checked
        save_config(self.cfg)

    def show_detections_window(self):
        window = self._get_detections_window()
        window.show()
        window.raise_()
        window.activateWindow()

    def show_log(self):
        if not os.path.exists(LOG_FILE):
            QMessageBox.information(None, "Verlauf", "Noch keine Eintraege vorhanden.")
            return
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-30:]
        QMessageBox.information(
            None, "Verlauf (letzte 30 Eintraege)",
            "".join(lines) if lines else "Noch keine Eintraege vorhanden.",
        )

    def quit(self):
        self.stop_watching()
        self.stop_injection_watch()
        self.stop_persistence_watch()
        for w in list(self._gemini_workers):
            w.wait(1000)
        self.app.quit()


def main():
    ensure_dirs()
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setFont(QFont("Consolas", 9))

    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.critical(None, "Fehler", "Kein System-Tray auf diesem Desktop verfuegbar.")
        sys.exit(1)

    tray_app = PandoraWatchdogTray(app)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()