/*
    YARA Rules for Infostealer Detection - 2025 Threat Landscape
    Author: Defensive Toolkit
    Date: 2025-11-26
    Description: Detects prevalent infostealer families including LummaC2, Vidar,
                 RedLine, and StrelaStealer. Infostealers increased 84% in 2025.
    References:
        - https://redcanary.com/blog/threat-detection/2025-threat-detection-report/
        - https://www.ibm.com/thought-leadership/institute-business-value/en-us/report/2025-threat-intelligence-index
        - https://www.vmray.com/february-2025-detection-highlights-a-record-month-of-new-yara-rules/
*/

import "pe"

rule LummaC2_Stealer
{
    meta:
        description = "Detects LummaC2 infostealer - top threat in 2025 via paste-and-run attacks"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
        mitre_attack = "T1555, T1539, T1552"

    strings:
        // LummaC2 characteristic strings
        $lumma1 = "LummaC2" ascii wide nocase
        $lumma2 = "Lumma Stealer" ascii wide nocase
        $lumma3 = "/c2sock" ascii
        $lumma4 = "/c2conf" ascii

        // Browser data paths targeted
        $browser1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide
        $browser2 = "\\Mozilla\\Firefox\\Profiles" ascii wide
        $browser3 = "\\Microsoft\\Edge\\User Data" ascii wide

        // Crypto wallet paths
        $wallet1 = "\\Exodus\\exodus.wallet" ascii wide
        $wallet2 = "\\Electrum\\wallets" ascii wide
        $wallet3 = "\\Atomic\\Local Storage" ascii wide
        $wallet4 = "wallet.dat" ascii wide nocase

        // Network communication patterns
        $net1 = "/api/collect" ascii
        $net2 = "/api/upload" ascii
        $net3 = "multipart/form-data" ascii

        // Anti-analysis checks
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "CheckRemoteDebuggerPresent" ascii
        $anti3 = "VirtualBox" ascii wide
        $anti4 = "VMware" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($lumma*)) or
            (2 of ($browser*) and 2 of ($wallet*)) or
            (2 of ($browser*) and 2 of ($net*) and 1 of ($anti*))
        )
}

rule Vidar_Stealer
{
    meta:
        description = "Detects Vidar infostealer - commodity stealer used by multiple threat actors"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"
        mitre_attack = "T1555, T1539, T1552"

    strings:
        // Vidar configuration patterns
        $config1 = "profile_id" ascii
        $config2 = "config_id" ascii
        $config3 = "botnet" ascii

        // Characteristic DLL loading
        $dll1 = "sqlite3.dll" ascii wide
        $dll2 = "freebl3.dll" ascii wide
        $dll3 = "mozglue.dll" ascii wide
        $dll4 = "nss3.dll" ascii wide
        $dll5 = "softokn3.dll" ascii wide
        $dll6 = "vcruntime140.dll" ascii wide

        // Data collection patterns
        $collect1 = "passwords.txt" ascii wide
        $collect2 = "cookies.txt" ascii wide
        $collect3 = "autofill.txt" ascii wide
        $collect4 = "cards.txt" ascii wide
        $collect5 = "history.txt" ascii wide

        // Hardware ID collection
        $hwid1 = "GetVolumeInformationW" ascii
        $hwid2 = "ComputerName" ascii wide
        $hwid3 = "GetUserNameW" ascii

        // Screenshot capability
        $screen1 = "GdipCreateBitmapFromScan0" ascii
        $screen2 = "screenshot.jpg" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (3 of ($dll*) and 2 of ($collect*)) or
            (2 of ($config*) and 2 of ($collect*)) or
            (3 of ($dll*) and 1 of ($screen*)) or
            (2 of ($hwid*) and 2 of ($collect*))
        )
}

rule RedLine_Stealer
{
    meta:
        description = "Detects RedLine infostealer - widely distributed via malvertising"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer"
        mitre_attack = "T1555, T1539, T1552"

    strings:
        // RedLine specific strings
        $redline1 = "RedLine" ascii wide nocase
        $redline2 = "RedGate" ascii wide
        $redline3 = "\\RedLine\\" ascii wide

        // .NET characteristics
        $net1 = "StringDecrypt" ascii
        $net2 = "FromBase64String" ascii
        $net3 = "GetExecutingAssembly" ascii

        // Targeted data
        $target1 = "\\Telegram Desktop\\tdata" ascii wide
        $target2 = "\\Steam\\config" ascii wide
        $target3 = "\\Discord\\Local Storage" ascii wide
        $target4 = "\\FileZilla\\recentservers.xml" ascii wide

        // Command and control
        $c2_1 = "SOAP" ascii
        $c2_2 = "GetSettings" ascii
        $c2_3 = "SendLogs" ascii
        $c2_4 = "CommandLine" ascii

        // Crypto wallet targeting
        $crypto1 = "\\Armory\\" ascii wide
        $crypto2 = "\\Guarda\\" ascii wide
        $crypto3 = "\\Jaxx\\" ascii wide
        $crypto4 = "\\Coinomi\\" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($redline*)) or
            (2 of ($net*) and 2 of ($target*)) or
            (2 of ($target*) and 2 of ($crypto*) and 1 of ($c2_*))
        )
}

rule StrelaStealer
{
    meta:
        description = "Detects StrelaStealer - email credential stealer active since 2022"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "high"
        reference = "https://www.vmray.com/march-2025-detection-highlights-detecting-cpu-property-queries-and-another-month-of-yara-rules/"
        mitre_attack = "T1555, T1114"

    strings:
        // Email client targeting
        $email1 = "\\Microsoft\\Outlook" ascii wide
        $email2 = "\\Thunderbird\\Profiles" ascii wide
        $email3 = "logins.json" ascii wide
        $email4 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles" ascii wide

        // Registry access patterns
        $reg1 = "RegOpenKeyExW" ascii
        $reg2 = "RegQueryValueExW" ascii
        $reg3 = "IMAP Password" ascii wide
        $reg4 = "POP3 Password" ascii wide
        $reg5 = "SMTP Password" ascii wide

        // Encryption/encoding
        $enc1 = "CryptUnprotectData" ascii
        $enc2 = "BCryptDecrypt" ascii

        // Exfiltration patterns
        $exfil1 = "/mail_" ascii
        $exfil2 = "POST /submit" ascii
        $exfil3 = "multipart" ascii

        // DLL name pattern
        $dllname = /strela[a-z0-9_]*\.dll/i

    condition:
        uint16(0) == 0x5A4D and
        filesize < 3MB and
        (
            ($dllname) or
            (2 of ($email*) and 1 of ($enc*)) or
            (3 of ($reg*) and 1 of ($exfil*))
        )
}

rule Generic_Infostealer_Behavior
{
    meta:
        description = "Detects generic infostealer behaviors and patterns"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "high"
        mitre_attack = "T1555, T1539, T1552"

    strings:
        // Browser database access
        $db1 = "SELECT * FROM logins" ascii wide nocase
        $db2 = "SELECT * FROM cookies" ascii wide nocase
        $db3 = "SELECT * FROM autofill" ascii wide nocase
        $db4 = "SELECT * FROM credit_cards" ascii wide nocase

        // SQLite operations
        $sqlite1 = "sqlite3_open" ascii
        $sqlite2 = "sqlite3_exec" ascii
        $sqlite3 = "sqlite3_prepare" ascii

        // Credential decryption
        $crypt1 = "CryptUnprotectData" ascii
        $crypt2 = "BCryptDecrypt" ascii
        $crypt3 = "DPAPI" ascii wide

        // Exfiltration keywords
        $exfil1 = "password" ascii wide nocase
        $exfil2 = "credential" ascii wide nocase
        $exfil3 = "wallet" ascii wide nocase
        $exfil4 = "seed phrase" ascii wide nocase
        $exfil5 = "private key" ascii wide nocase

        // ZIP creation for exfil
        $zip1 = "PK\x03\x04"
        $zip2 = "AddFile" ascii
        $zip3 = ".zip" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            (2 of ($db*) and 1 of ($sqlite*)) or
            (1 of ($crypt*) and 3 of ($exfil*)) or
            (2 of ($sqlite*) and 1 of ($crypt*) and 1 of ($zip*))
        )
}
