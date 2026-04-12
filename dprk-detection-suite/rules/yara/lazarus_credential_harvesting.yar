/*
    Rule:       Lazarus Credential Harvesting Toolkit
    Author:     Will Welch
    Created:    2026-04-12
    Reference:  CISA AA20-106A, Mandiant HIDDEN COBRA reporting
    ATT&CK:    T1003 (OS Credential Dumping), T1555 (Credentials from Password Stores)
    
    Description:
        Detects Lazarus Group credential harvesting tools observed in campaigns 
        targeting financial institutions and defense contractors (2020-2025). 
        Matches on known string artifacts, PDB paths, and behavioral patterns 
        associated with custom DPRK credential dumpers — distinct from commodity 
        tools like Mimikatz.
        
    Targets:
        - Custom LSASS memory dumpers with DPRK-attributed PDB paths
        - Browser credential extraction modules (Chrome/Firefox/Edge)
        - Windows Credential Manager harvesting utilities
        - Keylogger components observed in Lazarus intrusion sets
*/

rule lazarus_lsass_dumper
{
    meta:
        description = "Lazarus custom LSASS credential dumper"
        author = "Will Welch"
        date = "2026-04-12"
        reference = "CISA AA20-106A"
        mitre_attack = "T1003.001"
        severity = "critical"
        
    strings:
        // PDB paths observed in Lazarus tooling
        $pdb1 = "\\Release\\credman.pdb" ascii
        $pdb2 = "\\Release\\pwdump.pdb" ascii
        $pdb3 = "D:\\DEV\\01\\Release" ascii wide
        
        // LSASS interaction strings
        $lsass1 = "lsass.exe" ascii wide nocase
        $lsass2 = "sekurlsa" ascii wide
        $lsass3 = "MiniDumpWriteDump" ascii
        
        // Custom C2 callback strings seen in Lazarus dumpers
        $c2_1 = "Content-Type: application/x-www-form-urlencoded" ascii
        $c2_2 = "/upload/result" ascii
        $c2_3 = "&pass=" ascii
        $c2_4 = "&user=" ascii
        
        // Anti-analysis checks typical of DPRK tooling
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "CheckRemoteDebuggerPresent" ascii
        $anti3 = "vmtoolsd.exe" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            (any of ($pdb*) and any of ($lsass*)) or
            (2 of ($lsass*) and 2 of ($c2_*)) or
            (any of ($pdb*) and any of ($c2_*) and any of ($anti*))
        )
}

rule lazarus_browser_credential_stealer
{
    meta:
        description = "Lazarus browser credential extraction module"
        author = "Will Welch"
        date = "2026-04-12"
        reference = "CISA AA20-106A"
        mitre_attack = "T1555.003"
        severity = "high"
        
    strings:
        // Chrome credential database targets
        $chrome1 = "Login Data" ascii wide
        $chrome2 = "\\Google\\Chrome\\User Data\\" ascii wide
        $chrome3 = "cookies.sqlite" ascii wide
        
        // Firefox credential targets
        $ff1 = "signons.sqlite" ascii wide
        $ff2 = "logins.json" ascii wide
        $ff3 = "\\Mozilla\\Firefox\\Profiles\\" ascii wide
        
        // Edge credential targets
        $edge1 = "\\Microsoft\\Edge\\User Data\\" ascii wide
        
        // SQLite interaction for credential DB parsing
        $sql1 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide
        $sql2 = "SELECT host, name, value FROM cookies" ascii wide
        $sql3 = "sqlite3_open" ascii
        
        // CryptUnprotectData — used to decrypt Chrome stored creds
        $decrypt1 = "CryptUnprotectData" ascii
        $decrypt2 = "BCryptDecrypt" ascii
        
        // Lazarus-specific exfil patterns
        $exfil1 = "boundary=" ascii
        $exfil2 = "/post/upload" ascii
        $exfil3 = "multipart/form-data" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (2 of ($chrome*) and any of ($sql*) and any of ($decrypt*)) or
            (2 of ($ff*) and any of ($sql*)) or
            (any of ($chrome*, $ff*, $edge*) and any of ($sql*) and any of ($exfil*))
        )
}

rule lazarus_keylogger_component
{
    meta:
        description = "Keylogger module attributed to Lazarus intrusion sets"
        author = "Will Welch"
        date = "2026-04-12"
        reference = "Mandiant HIDDEN COBRA analysis"
        mitre_attack = "T1056.001"
        severity = "high"
        
    strings:
        // Keyboard hook APIs
        $hook1 = "SetWindowsHookExA" ascii
        $hook2 = "GetAsyncKeyState" ascii
        $hook3 = "GetKeyState" ascii
        $hook4 = "GetForegroundWindow" ascii
        $hook5 = "GetWindowTextA" ascii
        
        // Logging patterns observed in Lazarus keyloggers
        $log1 = "[ENTER]" ascii wide
        $log2 = "[TAB]" ascii wide
        $log3 = "[BACKSPACE]" ascii wide
        $log4 = "%04d-%02d-%02d %02d:%02d:%02d" ascii
        
        // File write for local staging
        $stage1 = "~tmp" ascii wide
        $stage2 = ".log" ascii wide
        $stage3 = "\\AppData\\Local\\Temp\\" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        3 of ($hook*) and
        2 of ($log*) and
        any of ($stage*)
}
