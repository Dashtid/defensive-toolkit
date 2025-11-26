/*
    YARA Rules for 2025 Ransomware Families
    Author: Defensive Toolkit
    Date: 2025-11-26
    Description: Detects modern RaaS (Ransomware-as-a-Service) families including
                 LockBit 4.0, BlackCat/ALPHV, and Qilin. RaaS dominates the
                 2025 threat landscape with 46% surge in attacks on industrial operators.
    References:
        - https://www.darktrace.com/blog/2025-cyber-threat-landscape-darktraces-mid-year-review
        - https://www.vmray.com/march-2025-detection-highlights-detecting-cpu-property-queries-and-another-month-of-yara-rules/
        - https://www.cyfirma.com/research/tracking-ransomware-february-2025/
*/

import "pe"

rule LockBit_4_0
{
    meta:
        description = "Detects LockBit 4.0 ransomware - latest variant with enhanced evasion"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://www.vmray.com/march-2025-detection-highlights-detecting-cpu-property-queries-and-another-month-of-yara-rules/"
        mitre_attack = "T1486, T1490, T1489"

    strings:
        // LockBit identifiers
        $lockbit1 = "LockBit" ascii wide nocase
        $lockbit2 = ".lockbit" ascii wide
        $lockbit3 = "lockbit3" ascii wide nocase

        // Ransom note patterns
        $note1 = "restore-my-files.txt" ascii wide nocase
        $note2 = "lockbit-decryptor" ascii wide nocase
        $note3 = "LockBit Black" ascii wide
        $note4 = "your important files" ascii wide nocase

        // AMSI bypass (new in 4.0)
        $amsi1 = "AmsiScanBuffer" ascii
        $amsi2 = "AmsiInitialize" ascii
        $amsi3 = "amsi.dll" ascii wide

        // Shadow copy deletion
        $shadow1 = "vssadmin.exe delete shadows" ascii wide nocase
        $shadow2 = "wmic shadowcopy delete" ascii wide nocase
        $shadow3 = "bcdedit /set" ascii wide

        // Service termination
        $svc1 = "net stop" ascii wide
        $svc2 = "taskkill /F" ascii wide
        $svc3 = "sc stop" ascii wide

        // Encryption indicators
        $enc1 = "CryptAcquireContext" ascii
        $enc2 = "CryptEncrypt" ascii
        $enc3 = "CryptGenRandom" ascii
        $enc4 = "RSA" ascii wide
        $enc5 = "AES" ascii wide

        // Anti-analysis
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "GetTickCount" ascii
        $anti3 = "QueryPerformanceCounter" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (1 of ($lockbit*) and 1 of ($shadow*)) or
            (1 of ($note*) and 2 of ($enc*) and 1 of ($shadow*)) or
            (2 of ($amsi*) and 2 of ($enc*) and 1 of ($svc*)) or
            (1 of ($anti*) and 2 of ($enc*) and 1 of ($shadow*))
        )
}

rule BlackCat_ALPHV
{
    meta:
        description = "Detects BlackCat/ALPHV ransomware - Rust-based cross-platform ransomware"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"
        mitre_attack = "T1486, T1490, T1489"

    strings:
        // BlackCat/ALPHV identifiers
        $alphv1 = "ALPHV" ascii wide
        $alphv2 = "BlackCat" ascii wide
        $alphv3 = ".onion" ascii

        // Rust runtime indicators
        $rust1 = "rust_panic" ascii
        $rust2 = "rust_begin_unwind" ascii
        $rust3 = "core::panicking" ascii
        $rust4 = "std::sys::windows" ascii

        // Extension patterns
        $ext1 = /\.[a-z0-9]{6,8}$/ ascii
        $ext2 = ".cat" ascii
        $ext3 = ".sykffle" ascii

        // Ransom note
        $note1 = "RECOVER-" ascii
        $note2 = "-FILES.txt" ascii
        $note3 = "access-key" ascii wide
        $note4 = "contact us" ascii wide nocase

        // Propagation
        $prop1 = "PsExec" ascii wide
        $prop2 = "impacket" ascii
        $prop3 = "wmiexec" ascii

        // Configuration
        $config1 = "\"config\"" ascii
        $config2 = "\"public_key\"" ascii
        $config3 = "\"extension\"" ascii

        // File enumeration
        $file1 = "FindFirstFileW" ascii
        $file2 = "FindNextFileW" ascii
        $file3 = "SetFileAttributesW" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            (1 of ($alphv*)) or
            (2 of ($rust*) and 2 of ($file*) and 1 of ($note*)) or
            (2 of ($config*) and 1 of ($prop*)) or
            (1 of ($ext*) and 2 of ($rust*))
        )
}

rule Qilin_Ransomware
{
    meta:
        description = "Detects Qilin ransomware - RaaS used by both cybercriminals and nation-states (Moonstone Sleet)"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://www.darktrace.com/blog/2025-cyber-threat-landscape-darktraces-mid-year-review"
        mitre_attack = "T1486, T1490, T1489"

    strings:
        // Qilin identifiers
        $qilin1 = "Qilin" ascii wide nocase
        $qilin2 = ".qilin" ascii wide
        $qilin3 = "qilin-decryptor" ascii wide

        // Ransom note patterns
        $note1 = "README_" ascii
        $note2 = "_RECOVER_" ascii
        $note3 = "your network has been compromised" ascii wide nocase
        $note4 = "data will be published" ascii wide nocase

        // Go language indicators (Qilin is written in Go)
        $go1 = "runtime.gopanic" ascii
        $go2 = "runtime.main" ascii
        $go3 = "go.buildid" ascii
        $go4 = "main.main" ascii

        // ESXi targeting
        $esxi1 = "esxcli" ascii wide
        $esxi2 = "vim-cmd" ascii wide
        $esxi3 = ".vmdk" ascii wide
        $esxi4 = ".vmx" ascii wide

        // Shadow copy and backup deletion
        $del1 = "vssadmin delete shadows" ascii wide nocase
        $del2 = "wmic shadowcopy" ascii wide
        $del3 = "bcdedit" ascii wide

        // Encryption
        $enc1 = "chacha20" ascii wide nocase
        $enc2 = "crypto/aes" ascii
        $enc3 = "crypto/rsa" ascii

        // Linux targeting
        $linux1 = "/etc/passwd" ascii
        $linux2 = "/var/lib" ascii
        $linux3 = "chmod" ascii

    condition:
        (
            (uint16(0) == 0x5A4D and filesize < 15MB) or
            (uint32(0) == 0x464C457F and filesize < 20MB)
        ) and
        (
            (1 of ($qilin*)) or
            (2 of ($go*) and 1 of ($note*) and 1 of ($del*)) or
            (2 of ($esxi*) and 1 of ($enc*)) or
            (2 of ($linux*) and 1 of ($enc*) and 1 of ($note*))
        )
}

rule RansomHub
{
    meta:
        description = "Detects RansomHub ransomware - emerging RaaS group in 2025"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://www.cyfirma.com/research/tracking-ransomware-february-2025/"
        mitre_attack = "T1486, T1490"

    strings:
        // RansomHub identifiers
        $hub1 = "RansomHub" ascii wide nocase
        $hub2 = ".ransomhub" ascii wide
        $hub3 = "ransomhub.onion" ascii

        // Ransom note
        $note1 = "How_To_Restore" ascii wide
        $note2 = "YOUR_FILES" ascii wide
        $note3 = "decryption tool" ascii wide nocase
        $note4 = "Tor Browser" ascii wide

        // Encryption implementation
        $enc1 = "ECDH" ascii wide
        $enc2 = "curve25519" ascii wide
        $enc3 = "salsa20" ascii wide nocase

        // Anti-recovery
        $anti1 = "delete shadows /all" ascii wide nocase
        $anti2 = "recoveryenabled no" ascii wide nocase
        $anti3 = "wbadmin delete" ascii wide nocase

        // Mutex patterns
        $mutex = /Global\\[A-F0-9]{32}/ ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (1 of ($hub*)) or
            (2 of ($note*) and 1 of ($enc*) and 1 of ($anti*)) or
            ($mutex and 2 of ($enc*))
        )
}

rule Generic_Ransomware_Behavior_2025
{
    meta:
        description = "Detects generic ransomware behaviors common in 2025 variants"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "high"
        mitre_attack = "T1486, T1490, T1489"

    strings:
        // Common encryption library usage
        $crypto1 = "CryptGenKey" ascii
        $crypto2 = "CryptEncrypt" ascii
        $crypto3 = "CryptAcquireContext" ascii
        $crypto4 = "BCryptEncrypt" ascii

        // File extension appending
        $ext_ops1 = "MoveFileExW" ascii
        $ext_ops2 = "SetFileInformationByHandle" ascii
        $ext_ops3 = "RenameFileW" ascii

        // Ransom note creation
        $note_create1 = "WriteFile" ascii
        $note_create2 = "CreateFileW" ascii
        $note_pattern = /README.*\.txt/ ascii wide nocase

        // Shadow copy deletion (multiple methods)
        $shadow1 = "vssadmin" ascii wide nocase
        $shadow2 = "wmic" ascii wide nocase
        $shadow3 = "shadowcopy" ascii wide nocase
        $shadow4 = "bcdedit" ascii wide nocase

        // Service stopping
        $svc_stop1 = "OpenSCManagerW" ascii
        $svc_stop2 = "ControlService" ascii
        $svc_stop3 = "DeleteService" ascii

        // Volume enumeration
        $vol1 = "GetLogicalDriveStringsW" ascii
        $vol2 = "GetDriveTypeW" ascii
        $vol3 = "FindFirstVolumeW" ascii

        // Network share enumeration
        $net1 = "NetShareEnum" ascii
        $net2 = "WNetOpenEnumW" ascii
        $net3 = "\\\\*\\*" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            (2 of ($crypto*) and 1 of ($ext_ops*) and 1 of ($shadow*)) or
            (2 of ($vol*) and 2 of ($crypto*) and 1 of ($note_create*)) or
            (1 of ($net*) and 2 of ($crypto*) and 1 of ($svc_stop*)) or
            ($note_pattern and 1 of ($crypto*) and 1 of ($shadow*))
        )
}
