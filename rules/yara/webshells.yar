/*
   YARA Rules for Webshell Detection
   Author: Defensive Toolkit
   Date: 2025-10-15
   Description: Detects common webshell patterns and behaviors
*/

rule Generic_PHP_Webshell
{
    meta:
        description = "Detects generic PHP webshell patterns"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1505/003/"

    strings:
        $php_tag = "<?php"
        $eval = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/
        $system = /system\s*\(\s*\$_(GET|POST|REQUEST)/
        $exec = /exec\s*\(\s*\$_(GET|POST|REQUEST)/
        $shell_exec = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/
        $passthru = /passthru\s*\(\s*\$_(GET|POST|REQUEST)/
        $base64_decode = "base64_decode"
        $gzinflate = "gzinflate"
        $str_rot13 = "str_rot13"

    condition:
        filesize < 1MB and
        $php_tag and
        (
            ($eval and $base64_decode) or
            (2 of ($system, $exec, $shell_exec, $passthru)) or
            ($eval and ($gzinflate or $str_rot13))
        )
}

rule Generic_ASPX_Webshell
{
    meta:
        description = "Detects generic ASPX webshell patterns"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1505/003/"

    strings:
        $aspx = "<%@ Page"
        $process_start = "Process.Start"
        $cmd = "cmd.exe"
        $powershell = "powershell.exe"
        $eval = "Eval"
        $request = "Request["
        $response = "Response.Write"
        $execute = /Execute\s*\(/

    condition:
        filesize < 1MB and
        $aspx and
        (
            ($process_start and ($cmd or $powershell)) or
            ($eval and $request) or
            ($execute and $request and $response)
        )
}

rule JSP_Webshell
{
    meta:
        description = "Detects JSP webshell patterns"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1505/003/"

    strings:
        $jsp = "<%@ page"
        $runtime = "Runtime.getRuntime"
        $exec = ".exec("
        $request = "request.getParameter"
        $process_builder = "ProcessBuilder"

    condition:
        filesize < 1MB and
        $jsp and
        (
            ($runtime and $exec and $request) or
            ($process_builder and $request)
        )
}

rule China_Chopper_Webshell
{
    meta:
        description = "Detects China Chopper webshell variants"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "critical"
        reference = "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html"

    strings:
        $php_chopper = /eval\s*\(\s*\$_POST\s*\[\s*['"][^'"]{1,10}['"]\s*\]\s*\)\s*;/
        $asp_chopper = /eval\s*\(\s*Request\s*\(\s*['"][^'"]{1,10}['"]\s*\)\s*,?\s*["'][^'"]*["']\s*\)/

    condition:
        filesize < 100KB and 1 of them
}
