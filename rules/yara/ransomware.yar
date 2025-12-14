/*
   YARA Rules for Ransomware Detection
   Author: Defensive Toolkit
   Date: 2025-10-15
   Description: Detects ransomware patterns and behaviors
*/

rule Generic_Ransomware_Extensions
{
    meta:
        description = "Detects files with common ransomware file extensions"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1486/"

    strings:
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".crypto"
        $ext4 = ".cerber"
        $ext5 = ".locky"
        $ext6 = ".zepto"
        $ext7 = ".odin"
        $ext8 = ".thor"
        $ext9 = ".aesir"
        $ext10 = ".cryptolocker"
        $ransom_note = "DECRYPT" nocase
        $ransom_note2 = "RANSOM" nocase
        $ransom_note3 = "RECOVERY" nocase
        $bitcoin = "bitcoin" nocase
        $payment = "payment" nocase

    condition:
        filesize < 10KB and
        (1 of ($ext*)) and
        (1 of ($ransom_note*) or $bitcoin or $payment)
}

rule Ransomware_Note_Pattern
{
    meta:
        description = "Detects ransomware ransom notes"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "critical"
        reference = "https://attack.mitre.org/techniques/T1486/"

    strings:
        $decrypt1 = "decrypt your files" nocase
        $decrypt2 = "decryption key" nocase
        $encrypt1 = "encrypted your files" nocase
        $encrypt2 = "files have been encrypted" nocase
        $payment1 = "pay the ransom" nocase
        $payment2 = "send bitcoin" nocase
        $payment3 = "cryptocurrency" nocase
        $deadline1 = "time limit" nocase
        $deadline2 = "hours left" nocase
        $warning1 = "do not attempt" nocase
        $warning2 = "files will be lost" nocase
        $contact1 = "contact us at" nocase
        $contact2 = "email us" nocase

    condition:
        filesize < 50KB and
        (
            (1 of ($decrypt*) and 1 of ($encrypt*)) or
            (1 of ($payment*) and 1 of ($deadline*)) or
            (1 of ($encrypt*) and 1 of ($payment*) and 1 of ($warning*)) or
            (1 of ($contact*) and 1 of ($payment*) and 1 of ($encrypt*))
        )
}

rule Suspicious_Crypto_Operations
{
    meta:
        description = "Detects suspicious cryptographic operations common in ransomware"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1486/"

    strings:
        $crypto1 = "CryptEncrypt" wide ascii
        $crypto2 = "CryptAcquireContext" wide ascii
        $crypto3 = "CryptDeriveKey" wide ascii
        $crypto4 = "CryptGenKey" wide ascii
        $file_enum1 = "FindFirstFile" wide ascii
        $file_enum2 = "FindNextFile" wide ascii
        $file_ops1 = "CreateFile" wide ascii
        $file_ops2 = "WriteFile" wide ascii
        $file_ops3 = "DeleteFile" wide ascii
        $ext_pattern = /\.(doc|docx|xls|xlsx|ppt|pptx|pdf|jpg|png|txt|zip|rar)/ nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (2 of ($crypto*)) and
        (2 of ($file_enum*)) and
        (2 of ($file_ops*)) and
        $ext_pattern
}

rule WannaCry_Ransomware_Indicators
{
    meta:
        description = "Detects WannaCry ransomware indicators"
        author = "Defensive Toolkit"
        date = "2025-10-15"
        severity = "critical"
        reference = "https://www.microsoft.com/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/"

    strings:
        $str1 = "WNcry@2ol7" wide ascii
        $str2 = "WANACRY!" wide ascii
        $str3 = "tasksche.exe" wide ascii
        $str4 = "icacls . /grant Everyone:F /T /C /Q" wide ascii
        $str5 = "attrib +h ." wide ascii
        $str6 = "wcry@123" wide ascii
        $msg = "Ooops, your important files are encrypted" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        3 of them
}
