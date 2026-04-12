/*
    Rule:       DPRK Supply Chain Compromise Indicators
    Author:     Will Welch
    Created:    2026-04-12
    Reference:  CISA AA20-106A, Mandiant APT45 reporting, 3CX compromise analysis
    ATT&CK:    T1195.002 (Compromise Software Supply Chain)
    
    Description:
        Detects artifacts associated with DPRK supply chain attacks — 
        trojanized software installers, malicious npm/PyPI packages, 
        and backdoored build artifacts. Patterns derived from the 3CX 
        supply chain compromise (attributed to Lazarus) and npm package 
        poisoning campaigns targeting blockchain developers.
*/

rule dprk_trojanized_installer
{
    meta:
        description = "Trojanized software installer with DPRK backdoor characteristics"
        author = "Will Welch"
        date = "2026-04-12"
        reference = "3CX supply chain compromise, CISA analysis"
        mitre_attack = "T1195.002"
        severity = "critical"
        
    strings:
        // Legitimate installer frameworks (MSI/NSIS/Inno) — expected
        $installer1 = "Windows Installer" ascii wide
        $installer2 = "Nullsoft" ascii wide
        $installer3 = "Inno Setup" ascii wide
        
        // Anomalous embedded DLLs — sideloading indicators
        $dll1 = "ffmpeg.dll" ascii wide
        $dll2 = "d3dcompiler_47.dll" ascii wide
        $dll3 = "libcef.dll" ascii wide
        
        // Encrypted payload markers observed in 3CX/Lazarus loaders
        $payload1 = { FE ED FA CE }
        $payload2 = "__guard_dispatch_icall_fptr" ascii
        $payload3 = "ICE_CREAM" ascii wide
        
        // Delayed execution / sleep before payload
        $sleep1 = "Sleep" ascii
        $sleep2 = { 68 ?? ?? ?? 00 FF 15 }
        
        // Icon resource manipulation — replacing legitimate vendor icons
        $icon1 = "RT_GROUP_ICON" ascii wide
        
        // C2 beacon after install
        $beacon1 = "raw.githubusercontent.com" ascii wide
        $beacon2 = "amazonaws.com" ascii wide
        $beacon3 = "azurewebsites.net" ascii wide
        $beacon4 = "/index.html" ascii wide
        $beacon5 = "User-Agent:" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 100MB and
        any of ($installer*) and
        (
            (any of ($dll*) and any of ($payload*) and any of ($beacon*)) or
            (any of ($payload*) and any of ($sleep*) and any of ($beacon*))
        )
}

rule dprk_malicious_npm_package
{
    meta:
        description = "Malicious npm package with DPRK attribution indicators"
        author = "Will Welch"
        date = "2026-04-12"
        reference = "Phylum, Snyk, Socket research on DPRK npm campaigns"
        mitre_attack = "T1195.002"
        severity = "high"
        
    strings:
        // package.json hooks — preinstall/postinstall scripts
        $hook1 = "\"preinstall\"" ascii
        $hook2 = "\"postinstall\"" ascii
        $hook3 = "\"install\"" ascii
        
        // Obfuscated JS execution patterns
        $obf1 = "eval(Buffer.from(" ascii
        $obf2 = "eval(atob(" ascii
        $obf3 = "\\x" ascii
        $obf4 = "String.fromCharCode" ascii
        $obf5 = "require('child_process').exec" ascii
        
        // Targeting developer environments
        $target1 = ".npmrc" ascii
        $target2 = ".env" ascii
        $target3 = ".ssh/id_rsa" ascii
        $target4 = "AWS_SECRET_ACCESS_KEY" ascii
        $target5 = "GITHUB_TOKEN" ascii
        
        // C2 / exfil via DNS or HTTPS
        $exfil1 = "dns.resolve" ascii
        $exfil2 = "https.request" ascii
        $exfil3 = "net.createConnection" ascii
        
        // Typosquatting indicator — similar to legit packages
        $typo1 = "package.json" ascii
        
    condition:
        $typo1 and
        any of ($hook*) and
        (
            (2 of ($obf*) and any of ($target*)) or
            (any of ($obf*) and 2 of ($target*) and any of ($exfil*)) or
            (2 of ($obf*) and any of ($exfil*))
        )
}

rule dprk_backdoored_build_artifact
{
    meta:
        description = "Build artifact with injected backdoor — CI/CD compromise"
        author = "Will Welch"
        date = "2026-04-12"
        reference = "Mandiant APT45 reporting, SolarWinds-pattern analysis"
        mitre_attack = "T1195.002"
        severity = "critical"
        
    strings:
        // Signed binary with unexpected network calls
        $signed1 = "Microsoft Corporation" ascii wide
        $signed2 = "Authenticode" ascii wide
        $signed3 = "SignerInfo" ascii wide
        
        // Injected code patterns — thread injection into signed binary
        $inject1 = "VirtualAlloc" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "CreateRemoteThread" ascii
        $inject4 = "NtMapViewOfSection" ascii
        
        // DNS-based C2 — common in supply chain backdoors
        $dns1 = "DnsQuery_A" ascii
        $dns2 = ".avsvmcloud." ascii wide
        $dns3 = "SRV" ascii wide
        
        // Steganographic payload in resources
        $steg1 = "FindResourceA" ascii
        $steg2 = "LoadResource" ascii
        $steg3 = "LockResource" ascii
        $steg4 = "RT_BITMAP" ascii wide
        
        // Timestomping / anti-forensics
        $anti1 = "SetFileTime" ascii
        $anti2 = "NtSetInformationFile" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        any of ($signed*) and
        (
            (2 of ($inject*) and any of ($dns*)) or
            (3 of ($steg*) and any of ($inject*)) or
            (any of ($inject*) and any of ($dns*) and any of ($anti*))
        )
}
