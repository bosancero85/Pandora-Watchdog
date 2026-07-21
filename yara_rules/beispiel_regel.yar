/*
    Beispiel-Regel fuer den Pandora Watchdog Injektions-Waechter.

    Dies ist NUR ein Format-Beispiel und erkennt keine echte Bedrohung -
    sie schlaegt lediglich an, wenn eine Textdatei das harmlose Wort
    "PANDORA_TESTMARKER" enthaelt. Nutze sie als Vorlage, um eigene,
    tatsaechlich relevante Erkennungsregeln zu ergaenzen (z.B. aus dem
    YARA-Forge- oder Neo23x0-Regelwerk, jeweils unter Beachtung der
    dortigen Lizenzbedingungen).

    Eigene .yar/.yara-Dateien einfach in diesen Ordner
    (~/.pandora_watchdog/yara_rules/) legen - sie werden beim naechsten
    Start automatisch geladen.
*/

rule Pandora_Beispiel_Testmarker
{
    meta:
        description = "Demo-Regel - erkennt einen harmlosen Test-String"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $marker = "PANDORA_TESTMARKER"

    condition:
        $marker
}
