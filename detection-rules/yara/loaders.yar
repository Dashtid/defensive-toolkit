/*
    YARA Rules for Malware Loaders - 2025 Threat Landscape
    Author: Defensive Toolkit
    Date: 2025-11-26
    Description: Detects malware loaders including HijackLoader and SocGholish
                 that deliver infostealers, RATs, and ransomware payloads.
    References:
        - https://redcanary.com/blog/threat-detection/2025-threat-detection-report/
        - https://www.vmray.com/march-2025-detection-highlights-detecting-cpu-property-queries-and-another-month-of-yara-rules/
*/

import "pe"

rule HijackLoader
{
    meta:
        description = "Detects HijackLoader - modular loader delivering infostealers via paste-and-run"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://redcanary.com/blog/threat-detection/2025-threat-detection-report/"
        mitre_attack = "T1055, T1620, T1027"

    strings:
        // HijackLoader characteristics
        $loader1 = "HijackLoader" ascii wide nocase
        $loader2 = "IDAT loader" ascii wide

        // DLL sideloading targets
        $dll1 = "version.dll" ascii wide
        $dll2 = "cryptsp.dll" ascii wide
        $dll3 = "cryptbase.dll" ascii wide
        $dll4 = "winmm.dll" ascii wide
        $dll5 = "dwrite.dll" ascii wide

        // Process hollowing
        $hollow1 = "NtUnmapViewOfSection" ascii
        $hollow2 = "NtWriteVirtualMemory" ascii
        $hollow3 = "ZwUnmapViewOfSection" ascii
        $hollow4 = "NtResumeThread" ascii

        // Anti-analysis
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "CheckRemoteDebuggerPresent" ascii
        $anti3 = "NtQueryInformationProcess" ascii
        $anti4 = "GetTickCount64" ascii

        // Shellcode patterns
        $shell1 = { E8 00 00 00 00 }
        $shell2 = { 64 A1 30 00 00 00 }
        $shell3 = { 48 31 C9 48 81 E9 }

        // Configuration decryption
        $config1 = "RC4" ascii wide
        $config2 = "XOR" ascii wide
        $config3 = { 31 ?? 88 ?? 41 }

        // PNG IDAT chunk abuse (signature technique)
        $idat1 = "IDAT" ascii
        $idat2 = { 89 50 4E 47 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (1 of ($loader*)) or
            (2 of ($dll*) and 2 of ($hollow*)) or
            (2 of ($anti*) and 1 of ($shell*) and 1 of ($config*)) or
            ($idat1 and $idat2 and 1 of ($hollow*))
        )
}

rule SocGholish
{
    meta:
        description = "Detects SocGholish/FakeUpdates - JavaScript-based loader for initial access"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "high"
        reference = "https://redcanary.com/blog/threat-detection/2025-threat-detection-report/"
        mitre_attack = "T1189, T1059.007, T1027"

    strings:
        // SocGholish characteristics
        $soc1 = "SocGholish" ascii wide nocase
        $soc2 = "FakeUpdates" ascii wide nocase
        $soc3 = "Chrome_Update" ascii wide

        // Fake browser update strings
        $fake1 = "browser update" ascii wide nocase
        $fake2 = "Chrome Update" ascii wide nocase
        $fake3 = "Firefox Update" ascii wide nocase
        $fake4 = "update required" ascii wide nocase
        $fake5 = "browser is out of date" ascii wide nocase

        // JavaScript obfuscation patterns
        $js1 = "eval(" ascii
        $js2 = "fromCharCode" ascii
        $js3 = "String.fromCharCode" ascii
        $js4 = "unescape(" ascii
        $js5 = "atob(" ascii
        $js6 = "btoa(" ascii

        // WScript execution
        $wscript1 = "WScript.Shell" ascii wide
        $wscript2 = "Wscript.Run" ascii wide
        $wscript3 = "Shell.Application" ascii wide
        $wscript4 = "new ActiveXObject" ascii

        // Download patterns
        $dl1 = "XMLHTTP" ascii wide
        $dl2 = "MSXML2.ServerXMLHTTP" ascii
        $dl3 = "responseBody" ascii
        $dl4 = "ADODB.Stream" ascii

        // Stage 2 download URLs
        $url1 = ".js" ascii
        $url2 = "/update/" ascii
        $url3 = "/download/" ascii

    condition:
        (
            // JavaScript file
            (filesize < 1MB and 3 of ($js*) and 2 of ($wscript*)) or
            // Executable dropper
            (uint16(0) == 0x5A4D and filesize < 5MB and (
                (1 of ($soc*)) or
                (2 of ($fake*) and 1 of ($dl*)) or
                (2 of ($wscript*) and 2 of ($dl*)) or
                (1 of ($url*) and 2 of ($dl*))
            ))
        )
}

rule BatLoader
{
    meta:
        description = "Detects BatLoader - batch file based loader for malware delivery"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "high"
        mitre_attack = "T1059.003, T1027"

    strings:
        // Batch obfuscation
        $batch1 = "@echo off" ascii nocase
        $batch2 = "set /a" ascii nocase
        $batch3 = "setlocal enabledelayedexpansion" ascii nocase
        $batch4 = "call :" ascii nocase

        // PowerShell invocation from batch
        $ps1 = "powershell" ascii nocase
        $ps2 = "-enc " ascii nocase
        $ps3 = "-ExecutionPolicy Bypass" ascii nocase
        $ps4 = "IEX" ascii nocase
        $ps5 = "Invoke-Expression" ascii nocase

        // Download operations
        $dl1 = "curl" ascii nocase
        $dl2 = "wget" ascii nocase
        $dl3 = "certutil" ascii nocase
        $dl4 = "bitsadmin" ascii nocase

        // Persistence
        $pers1 = "schtasks" ascii nocase
        $pers2 = "reg add" ascii nocase
        $pers3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase

        // Anti-analysis
        $anti1 = "timeout /t" ascii nocase
        $anti2 = "ping 127.0.0.1" ascii nocase

    condition:
        filesize < 500KB and
        (
            (2 of ($batch*) and 2 of ($ps*) and 1 of ($dl*)) or
            (2 of ($batch*) and 2 of ($dl*) and 1 of ($pers*)) or
            ($batch1 and 2 of ($ps*) and 1 of ($anti*))
        )
}

rule GootLoader
{
    meta:
        description = "Detects GootLoader - SEO poisoning based JavaScript loader"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "high"
        mitre_attack = "T1189, T1059.007, T1027"

    strings:
        // GootLoader characteristics
        $goot1 = "GootLoader" ascii wide nocase
        $goot2 = "Gootkit" ascii wide nocase

        // Heavy JavaScript obfuscation
        $obf1 = /var [a-z]{20,}/ ascii
        $obf2 = /function [a-z]{15,}\(/ ascii
        $obf3 = "String.prototype" ascii
        $obf4 = ".split('')" ascii
        $obf5 = ".reverse()" ascii
        $obf6 = ".join('')" ascii

        // Document content manipulation
        $doc1 = "document.write" ascii
        $doc2 = "innerHTML" ascii
        $doc3 = "createElement" ascii
        $doc4 = "appendChild" ascii

        // Execution patterns
        $exec1 = "eval(" ascii
        $exec2 = "new Function" ascii
        $exec3 = "setTimeout" ascii
        $exec4 = "setInterval" ascii

        // Registry operations (via wscript)
        $reg1 = "HKCU" ascii
        $reg2 = "RegWrite" ascii
        $reg3 = "WScript.Shell" ascii

    condition:
        filesize < 2MB and
        not uint16(0) == 0x5A4D and
        (
            (1 of ($goot*)) or
            (3 of ($obf*) and 2 of ($exec*)) or
            (2 of ($doc*) and 2 of ($obf*) and 1 of ($reg*))
        )
}

rule Generic_Loader_Behavior
{
    meta:
        description = "Detects generic loader behaviors - process injection and payload execution"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "medium"
        mitre_attack = "T1055, T1620"

    strings:
        // Virtual memory operations
        $vm1 = "VirtualAlloc" ascii
        $vm2 = "VirtualAllocEx" ascii
        $vm3 = "VirtualProtect" ascii
        $vm4 = "VirtualProtectEx" ascii

        // Process injection
        $inj1 = "WriteProcessMemory" ascii
        $inj2 = "CreateRemoteThread" ascii
        $inj3 = "NtCreateThreadEx" ascii
        $inj4 = "RtlCreateUserThread" ascii
        $inj5 = "QueueUserAPC" ascii

        // Process creation
        $proc1 = "CreateProcessA" ascii
        $proc2 = "CreateProcessW" ascii
        $proc3 = "CreateProcessInternalW" ascii
        $proc4 = "NtCreateProcess" ascii

        // Anti-analysis timing
        $time1 = "GetTickCount" ascii
        $time2 = "QueryPerformanceCounter" ascii
        $time3 = "Sleep" ascii
        $time4 = "NtDelayExecution" ascii

        // Decryption indicators
        $dec1 = "CryptDecrypt" ascii
        $dec2 = "BCryptDecrypt" ascii
        $dec3 = { 31 ?? 88 ?? 4? }
        $dec4 = { 80 3? ?? 74 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (2 of ($vm*) and 2 of ($inj*)) or
            (1 of ($inj*) and 1 of ($proc*) and 1 of ($dec*)) or
            (2 of ($vm*) and 2 of ($time*) and 1 of ($dec*))
        )
}
