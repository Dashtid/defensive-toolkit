/*
    YARA Rules for C2 Framework Detection
    Author: Defensive Toolkit
    Date: 2025-11-26
    Description: Detects Command and Control frameworks including Cobalt Strike
                 and Sliver, the most prevalent C2 tools used by threat actors in 2025.
    References:
        - https://attack.mitre.org/software/S0154/
        - https://attack.mitre.org/software/S0633/
        - https://thedfirreport.com/
*/

import "pe"

rule CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon payloads - most common C2 framework"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://attack.mitre.org/software/S0154/"
        mitre_attack = "T1071.001, T1095, T1055"

    strings:
        // Cobalt Strike watermark
        $watermark = { 2E 2F 2E 2F 2E 2E }

        // Beacon configuration
        $config1 = "sleeptime" ascii
        $config2 = "jitter" ascii
        $config3 = "publickey" ascii
        $config4 = "C2Server" ascii

        // Named pipe patterns
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe3 = "\\\\.\\pipe\\postex_" ascii wide
        $pipe4 = "\\\\.\\pipe\\status_" ascii wide
        $pipe5 = "\\\\%s\\pipe\\" ascii

        // HTTP beacon patterns
        $http1 = "Mozilla/5.0" ascii
        $http2 = "Cookie:" ascii
        $http3 = "Accept: */*" ascii
        $http4 = "Accept-Language:" ascii

        // Reflective loading
        $reflect1 = "ReflectiveLoader" ascii
        $reflect2 = { 4D 5A 41 52 55 48 89 E5 }

        // Process injection
        $inject1 = "CreateRemoteThread" ascii
        $inject2 = "VirtualAllocEx" ascii
        $inject3 = "WriteProcessMemory" ascii
        $inject4 = "NtMapViewOfSection" ascii

        // Spawn patterns
        $spawn1 = "spawnto_x86" ascii
        $spawn2 = "spawnto_x64" ascii
        $spawn3 = "rundll32.exe" ascii wide
        $spawn4 = "dllhost.exe" ascii wide

        // BOF (Beacon Object Files)
        $bof1 = "BeaconDataParse" ascii
        $bof2 = "BeaconPrintf" ascii
        $bof3 = "BeaconOutput" ascii

        // Shellcode patterns
        $shell1 = { FC E8 ?? 00 00 00 }
        $shell2 = { E8 ?? ?? ?? ?? EB }
        $shell3 = { 48 31 C9 48 81 E9 }

    condition:
        (
            (uint16(0) == 0x5A4D and filesize < 1MB) or
            (filesize < 500KB)
        ) and
        (
            ($watermark) or
            (2 of ($config*)) or
            (2 of ($pipe*)) or
            (2 of ($spawn*) and 1 of ($inject*)) or
            (2 of ($bof*)) or
            (1 of ($reflect*) and 2 of ($inject*)) or
            (2 of ($shell*) and 1 of ($inject*)) or
            (2 of ($http*) and 1 of ($config*))
        )
}

rule CobaltStrike_Stager
{
    meta:
        description = "Detects Cobalt Strike stager shellcode"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://thedfirreport.com/"
        mitre_attack = "T1071.001"

    strings:
        // HTTP stager pattern
        $stager1 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $stager2 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }

        // HTTPS stager
        $stager3 = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 }
        $stager4 = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 }

        // DNS stager indicators
        $dns1 = "cdn." ascii
        $dns2 = "www6." ascii
        $dns3 = "api." ascii

        // Checksum8 hash
        $hash1 = { 0F B6 4C 0E FF }
        $hash2 = { C1 CF 0D 01 C7 }

    condition:
        filesize < 100KB and
        (
            (1 of ($stager*)) or
            (1 of ($hash*) and 1 of ($dns*))
        )
}

rule Sliver_Implant
{
    meta:
        description = "Detects Sliver C2 implant - open-source alternative to Cobalt Strike"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://attack.mitre.org/software/S0633/"
        mitre_attack = "T1071, T1095, T1055"

    strings:
        // Sliver identifiers
        $sliver1 = "sliver" ascii wide nocase
        $sliver2 = "bishopfox" ascii wide nocase

        // Go runtime indicators
        $go1 = "runtime.main" ascii
        $go2 = "runtime.gopanic" ascii
        $go3 = "runtime.goexit" ascii
        $go4 = "go.buildid" ascii

        // Sliver specific strings
        $func1 = "implant" ascii
        $func2 = "beacon" ascii
        $func3 = "session" ascii
        $func4 = "pivots" ascii

        // C2 protocols
        $proto1 = "mtls" ascii
        $proto2 = "wg" ascii
        $proto3 = "dns" ascii
        $proto4 = "http" ascii
        $proto5 = "https" ascii

        // mTLS patterns
        $mtls1 = "tls.Config" ascii
        $mtls2 = "InsecureSkipVerify" ascii
        $mtls3 = "ClientAuth" ascii
        $mtls4 = "x509" ascii

        // WireGuard indicators
        $wg1 = "wireguard" ascii
        $wg2 = "wgctrl" ascii
        $wg3 = "noise" ascii
        $wg4 = "chacha20poly1305" ascii

        // Process injection (Sliver)
        $inject1 = "shellcode" ascii
        $inject2 = "execute-assembly" ascii
        $inject3 = "sideload" ascii
        $inject4 = "spawndll" ascii

        // Protobuf (Sliver uses protobuf)
        $pb1 = "protobuf" ascii
        $pb2 = "proto3" ascii
        $pb3 = "google.protobuf" ascii

        // File paths indicating Sliver
        $path1 = "github.com/bishopfox/sliver" ascii
        $path2 = "/sliver/" ascii

    condition:
        (
            (uint16(0) == 0x5A4D and filesize < 30MB) or
            (uint32(0) == 0x464C457F and filesize < 30MB)
        ) and
        (
            (1 of ($sliver*)) or
            (1 of ($path*)) or
            (2 of ($go*) and 2 of ($func*)) or
            (2 of ($go*) and 2 of ($proto*) and 1 of ($mtls*)) or
            (2 of ($wg*) and 2 of ($go*)) or
            (2 of ($pb*) and 2 of ($go*) and 1 of ($inject*))
        )
}

rule Sliver_Beacon
{
    meta:
        description = "Detects Sliver beacon mode implants"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://github.com/BishopFox/sliver"
        mitre_attack = "T1071, T1095"

    strings:
        // Beacon-specific patterns
        $beacon1 = "BeaconInterval" ascii
        $beacon2 = "BeaconJitter" ascii
        $beacon3 = "nextCheckin" ascii
        $beacon4 = "reconnectInterval" ascii

        // Task handling
        $task1 = "GetTask" ascii
        $task2 = "TaskResponse" ascii
        $task3 = "TaskError" ascii
        $task4 = "TaskComplete" ascii

        // Go patterns
        $go1 = "main.main" ascii
        $go2 = "runtime." ascii

        // Evasion
        $evade1 = "evasion" ascii
        $evade2 = "AntiVirus" ascii

    condition:
        (
            (uint16(0) == 0x5A4D and filesize < 30MB) or
            (uint32(0) == 0x464C457F and filesize < 30MB)
        ) and
        (
            (2 of ($beacon*) and 1 of ($go*)) or
            (2 of ($task*) and 1 of ($go*)) or
            (1 of ($beacon*) and 1 of ($task*) and 1 of ($evade*))
        )
}

rule BruteRatel_C4
{
    meta:
        description = "Detects Brute Ratel C4 - advanced adversary simulation framework"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "critical"
        reference = "https://bruteratel.com/"
        mitre_attack = "T1071, T1055"

    strings:
        // Brute Ratel identifiers
        $br1 = "BruteRatel" ascii wide nocase
        $br2 = "badger" ascii nocase
        $br3 = "BRc4" ascii

        // Configuration patterns
        $config1 = "brc4.conf" ascii
        $config2 = "badgers" ascii
        $config3 = "listeners" ascii

        // Anti-EDR techniques
        $edr1 = "unhook" ascii
        $edr2 = "syscall" ascii
        $edr3 = "ntdll" ascii
        $edr4 = "kernelbase" ascii

        // Indirect syscalls
        $syscall1 = "NtAllocateVirtualMemory" ascii
        $syscall2 = "NtProtectVirtualMemory" ascii
        $syscall3 = "NtWriteVirtualMemory" ascii
        $syscall4 = "NtCreateThreadEx" ascii

        // Sleep obfuscation
        $sleep1 = "SleepEx" ascii
        $sleep2 = "ekko" ascii
        $sleep3 = "zilean" ascii

        // BOF patterns
        $bof1 = "coffLoader" ascii
        $bof2 = "COFF" ascii
        $bof3 = "ObjectFile" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($br*)) or
            (2 of ($config*)) or
            (2 of ($edr*) and 2 of ($syscall*)) or
            (2 of ($bof*) and 1 of ($edr*)) or
            (1 of ($sleep*) and 2 of ($syscall*))
        )
}

rule Generic_C2_Behavior
{
    meta:
        description = "Detects generic C2 framework behaviors"
        author = "Defensive Toolkit"
        date = "2025-11-26"
        severity = "high"
        mitre_attack = "T1071, T1055"

    strings:
        // Sleep with jitter
        $jitter1 = "jitter" ascii
        $jitter2 = "sleep" ascii nocase
        $jitter3 = "interval" ascii

        // Beaconing patterns
        $beacon1 = "checkin" ascii nocase
        $beacon2 = "heartbeat" ascii nocase
        $beacon3 = "polling" ascii nocase
        $beacon4 = "callback" ascii nocase

        // Task/command patterns
        $task1 = "execute" ascii
        $task2 = "shell" ascii
        $task3 = "download" ascii
        $task4 = "upload" ascii
        $task5 = "screenshot" ascii
        $task6 = "keylog" ascii

        // Process injection APIs
        $inject1 = "VirtualAllocEx" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "CreateRemoteThread" ascii
        $inject4 = "NtCreateThreadEx" ascii

        // Anti-debugging
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "CheckRemoteDebuggerPresent" ascii
        $anti3 = "NtQueryInformationProcess" ascii

        // Encryption
        $enc1 = "AES" ascii
        $enc2 = "ChaCha20" ascii nocase
        $enc3 = "RC4" ascii
        $enc4 = "XOR" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (2 of ($jitter*) and 2 of ($task*)) or
            (2 of ($beacon*) and 2 of ($inject*)) or
            (2 of ($task*) and 2 of ($inject*) and 1 of ($enc*)) or
            (1 of ($anti*) and 2 of ($inject*) and 1 of ($enc*))
        )
}
