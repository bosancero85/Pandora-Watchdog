/*
    Einsatzbereite Beispiel-Regelsammlung fuer den Pandora Watchdog
    Injektions-Waechter.

    Diese Regeln pruefen auf generische, seit Jahren oeffentlich bekannte
    Verhaltens-/String-Indikatoren, wie sie u.a. auch in offenen
    Community-Regelwerken (z.B. Neo23x0/signature-base, YARA-Forge)
    verwendet werden. Es handelt sich um DETEKTIONSMUSTER, keine
    Angriffs- oder Exploit-Bausteine.

    Jede Regel ist bewusst generisch gehalten (mehrere Treffer = hoeheres
    Risiko), damit die Falsch-Positiv-Rate ueberschaubar bleibt. Trotzdem
    gilt: YARA-Treffer sind ein Indiz, kein Beweis - der Pandora Watchdog
    zeigt sie nur an, loescht nichts automatisch.

    Eigene .yar/.yara-Dateien einfach zusaetzlich in diesen Ordner
    (~/.pandora_watchdog/yara_rules/) legen - sie werden beim naechsten
    Start automatisch geladen.
*/

rule Pandora_Beispiel_Testmarker
{
    meta:
        description = "Demo-Regel - erkennt einen harmlosen Test-String"
        severity = "info"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $marker = "PANDORA_TESTMARKER"

    condition:
        $marker
}

rule Pandora_Suspicious_PowerShell_Obfuscation
{
    meta:
        description = "Verdaechtige, oft von Malware genutzte PowerShell-Aufrufe (Encoded Commands, Download-Cradles, versteckte Fenster)"
        severity = "hoch"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $hidden1 = "-WindowStyle Hidden" nocase
        $hidden2 = "-w hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $iex = "IEX(" nocase
        $iex2 = "Invoke-Expression" nocase
        $dl1 = "Net.WebClient" nocase
        $dl2 = "DownloadString(" nocase
        $dl3 = "DownloadFile(" nocase
        $b64 = "FromBase64String(" nocase
        $amsi = "amsiutils" nocase
        $amsi2 = "AmsiScanBuffer" nocase

    condition:
        2 of them
}

rule Pandora_Suspicious_Webshell_Strings
{
    meta:
        description = "Typische Webshell-Indikatoren (PHP/JSP/ASP-Backdoors, Kommando-Ausfuehrung ueber HTTP-Parameter)"
        severity = "hoch"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $php1 = "eval(base64_decode(" nocase
        $php2 = "eval($_POST" nocase
        $php3 = "eval($_GET" nocase
        $php4 = "eval($_REQUEST" nocase
        $php5 = "system($_" nocase
        $php6 = "passthru($_" nocase
        $php7 = "shell_exec($_" nocase
        $php8 = "assert($_" nocase
        $jsp1 = "Runtime.getRuntime().exec(" ascii
        $asp1 = "eval(request" nocase
        $webshell_marker = "c99shell" nocase
        $webshell_marker2 = "r57shell" nocase

    condition:
        any of them
}

rule Pandora_Suspicious_Reverse_Shell
{
    meta:
        description = "Bekannte Reverse-Shell-/Bind-Shell-Einzeiler (Bash, Python, Netcat, Perl)"
        severity = "kritisch"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $bash1 = "/dev/tcp/" ascii
        $bash2 = "bash -i" ascii
        $nc1 = "nc -e /bin/sh" ascii
        $nc2 = "nc -e /bin/bash" ascii
        $nc3 = "ncat --sh-exec" ascii
        $py1 = "socket.socket(socket.AF_INET" ascii
        $py2 = "subprocess.call([\"/bin/sh\"" ascii
        $py3 = "pty.spawn(" ascii
        $perl1 = "socket(SOCKET" ascii
        $mkfifo = "mkfifo /tmp/" ascii

    condition:
        any of them
}

rule Pandora_Suspicious_Process_Injection_API
{
    meta:
        description = "Kombination von Windows-APIs, wie sie klassischerweise fuer Process-Hollowing/Injection genutzt werden"
        severity = "kritisch"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $api1 = "VirtualAlloc" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "CreateRemoteThread" ascii
        $api5 = "NtUnmapViewOfSection" ascii
        $api6 = "SetThreadContext" ascii
        $api7 = "ReflectiveLoader" ascii
        $mz = { 4D 5A }

    condition:
        $mz at 0 and 3 of ($api1, $api2, $api3, $api4, $api5, $api6, $api7)
}

rule Pandora_Suspicious_Persistence_Snippet
{
    meta:
        description = "Textfragmente, die typischerweise beim automatisierten Einnisten in Autostart/Cron/SSH auftauchen"
        severity = "hoch"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $cron1 = "* * * * * " ascii
        $ssh1 = "authorized_keys" ascii
        $bashrc1 = ".bashrc" ascii
        $systemd1 = "WantedBy=multi-user.target" ascii
        $systemd2 = "WantedBy=default.target" ascii
        $curl_pipe = "curl -s" ascii
        $wget_pipe = "wget -q" ascii
        $pipe_bash = "| bash" ascii
        $pipe_sh = "| sh" ascii

    condition:
        ( $curl_pipe or $wget_pipe ) and ( $pipe_bash or $pipe_sh )
        or ( $cron1 and ( $curl_pipe or $wget_pipe ) )
        or ( $ssh1 and $bashrc1 )
}

rule Pandora_Ransomware_Note_Indicators
{
    meta:
        description = "Typische Formulierungen aus Ransomware-Erpresserbriefen"
        severity = "kritisch"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $t1 = "your files have been encrypted" nocase
        $t2 = "all your files are encrypted" nocase
        $t3 = "decrypt your files" nocase
        $t4 = "send bitcoin" nocase
        $t5 = "bitcoin wallet" nocase
        $t6 = "tor browser" nocase
        $t7 = "restore my files" nocase
        $btc_addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/

    condition:
        2 of ($t*) or ( 1 of ($t*) and $btc_addr )
}

rule Pandora_Suspicious_Office_Macro
{
    meta:
        description = "Verdaechtige VBA-Makro-Konstrukte in Office-Dokumenten (Auto-Exec + Shell-Ausfuehrung)"
        severity = "hoch"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $auto1 = "AutoOpen" ascii
        $auto2 = "Document_Open" ascii
        $auto3 = "Workbook_Open" ascii
        $shell1 = "Shell(" ascii
        $shell2 = "WScript.Shell" ascii
        $shell3 = "CreateObject(\"WScript.Shell\")" ascii
        $ole1 = "powershell" nocase

    condition:
        1 of ($auto*) and 1 of ($shell*, $ole1)
}

rule Pandora_Double_Extension_Payload_Hint
{
    meta:
        description = "Zusaetzlicher Text-Hinweis auf getarnte ausfuehrbare Inhalte in vermeintlichen Dokumenten (ergaenzt die Python-seitige Endungspruefung)"
        severity = "mittel"
        author = "AKI_SystemDown"
        date = "2026-07-21"

    strings:
        $mz = { 4D 5A }
        $elf = { 7F 45 4C 46 }
        $shebang_sh = "#!/bin/sh"
        $shebang_bash = "#!/bin/bash"
        $shebang_py = "#!/usr/bin/env python"

    condition:
        $mz at 0 or $elf at 0 or $shebang_sh at 0 or $shebang_bash at 0 or $shebang_py at 0
}
