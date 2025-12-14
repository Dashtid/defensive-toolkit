/*
   YARA Rules for Suspicious Script Detection
   Author: Defensive Toolkit
   Date: 2025-10-15
   Description: Detects suspicious PowerShell, VBS, and batch scripts
*/

rule Suspicious_PowerShell_Script
{
    meta:
        description = "Detects suspicious PowerShell script patterns"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $encoded = /-[Ee]n?c?o?d?e?d?[Cc]?o?m?m?a?n?d?/ nocase
        $hidden = /-[Ww]indow[Ss]tyle\s+[Hh]idden/ nocase
        $bypass = /-[Ee]x?e?c?u?t?i?o?n?[Pp]?o?l?i?c?y?\s+[Bb]ypass/ nocase
        $noprofile = /-[Nn]o[Pp]rofile/ nocase
        $noninteractive = /-[Nn]on[Ii]nteractive/ nocase
        $download = /[Nn]et\.[Ww]eb[Cc]lient.*[Dd]ownload/ nocase
        $invoke_expression = /[Ii]nvoke-[Ee]xpression|[Ii][Ee][Xx]/ nocase
        $invoke_webrequest = /[Ii]nvoke-[Ww]eb[Rr]equest/ nocase
        $base64 = /[Ss]ystem\.[Cc]onvert\]::[Ff]rom[Bb]ase64[Ss]tring/ nocase
        $reflection = /[Ss]ystem\.[Rr]eflection\.[Aa]ssembly/ nocase
        $process_start = /\[System\.Diagnostics\.Process\]::Start/ nocase

    condition:
        filesize < 1MB and
        (
            ($encoded and ($invoke_expression or $base64)) or
            ($hidden and $bypass) or
            ($download and $invoke_expression) or
            (3 of ($hidden, $bypass, $noprofile, $noninteractive, $reflection, $process_start))
        )
}

rule Suspicious_VBScript
{
    meta:
        description = "Detects suspicious VBScript patterns"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1059/005/"

    strings:
        $wscript = "WScript.Shell" nocase
        $shell_exec = "Shell.Application" nocase
        $xmlhttp = "MSXML2.XMLHTTP" nocase
        $adodb = "ADODB.Stream" nocase
        $run = ".Run" nocase
        $exec = ".Exec" nocase
        $createobject = "CreateObject" nocase
        $download = /\.(Open|Send|ResponseBody)/ nocase
        $write = ".SaveToFile" nocase
        $hidden = "vbHide" nocase

    condition:
        filesize < 500KB and
        $createobject and
        (
            ($wscript and ($run or $exec)) or
            ($xmlhttp and $adodb and $write) or
            ($shell_exec and $exec) or
            ($hidden and $run)
        )
}

rule Suspicious_Batch_Script
{
    meta:
        description = "Detects suspicious batch script patterns"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1059/003/"

    strings:
        $echo_off = "@echo off" nocase
        $powershell_invoke = /powershell.*-c.*/ nocase
        $download = /certutil.*-urlcache/ nocase
        $bitsadmin = /bitsadmin.*\/transfer/ nocase
        $net_use = "net use" nocase
        $schtasks = "schtasks /create" nocase
        $reg_add = "reg add" nocase
        $wmic = "wmic" nocase
        $sc_create = "sc create" nocase
        $vssadmin = "vssadmin delete shadows" nocase
        $bcdedit = "bcdedit /set" nocase
        $disable_fw = "netsh advfirewall set" nocase

    condition:
        filesize < 100KB and
        $echo_off and
        (
            ($powershell_invoke and ($download or $bitsadmin)) or
            ($vssadmin or $bcdedit) or
            ($net_use and 2 of ($schtasks, $reg_add, $sc_create, $wmic, $disable_fw)) or
            (3 of ($schtasks, $reg_add, $sc_create, $wmic, $disable_fw))
        )
}

rule Obfuscated_Script
{
    meta:
        description = "Detects heavily obfuscated scripts"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1027/"

    strings:
        $char_pattern1 = /[\$\^][a-zA-Z0-9_]{1,3}\s*=\s*[\'\"][^\'\"\r\n]{1,2}[\'\"]/ nocase
        $char_pattern2 = /chr\(\d{1,3}\)/i
        $concat = /[\+&\.](\s*[\$\^][a-zA-Z0-9_]{1,3}\s*){5,}/ nocase
        $replace = /\.replace\([^\)]+\)/i
        $split = /\.split\([^\)]+\)/i
        $join = /-join/i
        $format = /-f\s+/i

    condition:
        filesize < 1MB and
        (
            (#char_pattern1 > 20 or #char_pattern2 > 20) or
            ($concat and 2 of ($replace, $split, $join, $format))
        )
}
