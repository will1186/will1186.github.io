/*
    Rule:       APT38 Cryptocurrency Theft Tooling
    Author:     Will Welch
    Created:    2026-04-12
    Reference:  CISA AA22-108A (TraderTraitor), FBI PIN 20220516-001
    ATT&CK:    T1496 (Resource Hijacking), T1005 (Data from Local System)
    
    Description:
        Detects APT38/TraderTraitor tooling used in cryptocurrency exchange 
        and DeFi platform targeting. Covers trojanized trading applications, 
        wallet seed phrase extractors, and clipboard hijackers that swap 
        cryptocurrency addresses. Based on IOCs and behavioral patterns 
        from the Ronin Bridge ($620M), Horizon Bridge ($100M), and 
        Atomic Wallet ($35M) compromises.
*/

rule apt38_trojanized_trading_app
{
    meta:
        description = "TraderTraitor — trojanized cryptocurrency trading application"
        author = "Will Welch"
        date = "2026-04-12"
        reference = "CISA AA22-108A"
        mitre_attack = "T1195.002"
        severity = "critical"
        
    strings:
        // Electron/Node.js trading app indicators
        $electron1 = "electron.asar" ascii wide
        $electron2 = "app.asar" ascii wide
        $node1 = "node_modules" ascii wide
        
        // Crypto exchange API interaction
        $api1 = "api.binance.com" ascii wide
        $api2 = "api.kraken.com" ascii wide
        $api3 = "api.coinbase.com" ascii wide
        $api4 = "/api/v3/account" ascii wide
        $api5 = "X-MBX-APIKEY" ascii wide
        
        // Wallet/key extraction strings
        $wallet1 = "wallet.dat" ascii wide
        $wallet2 = "keystore" ascii wide
        $wallet3 = "private_key" ascii wide
        $wallet4 = "mnemonic" ascii wide
        $wallet5 = "seed_phrase" ascii wide
        
        // Suspicious C2 patterns in Electron apps
        $c2_1 = "eval(Buffer.from(" ascii
        $c2_2 = "child_process" ascii
        $c2_3 = "require('http')" ascii
        $c2_4 = ".onion" ascii wide
        
        // TraderTraitor-specific social engineering filenames
        $lure1 = "TradeManager" ascii wide nocase
        $lure2 = "CryptoPortfolio" ascii wide nocase
        $lure3 = "TokenAirdrop" ascii wide nocase
        $lure4 = "DeFiTrading" ascii wide nocase
        
    condition:
        (
            // Trojanized Electron app with wallet access
            (any of ($electron*, $node*) and 2 of ($wallet*) and any of ($c2_*)) or
            // Trading app with embedded C2
            (2 of ($api*) and any of ($c2_*) and any of ($wallet*)) or
            // Lure filename with crypto API access and C2
            (any of ($lure*) and any of ($api*) and any of ($c2_*))
        )
}

rule apt38_clipboard_hijacker
{
    meta:
        description = "Cryptocurrency clipboard hijacker — swaps wallet addresses"
        author = "Will Welch"
        date = "2026-04-12"
        reference = "FBI PIN 20220516-001"
        mitre_attack = "T1115"
        severity = "high"
        
    strings:
        // Clipboard monitoring APIs
        $clip1 = "OpenClipboard" ascii
        $clip2 = "GetClipboardData" ascii
        $clip3 = "SetClipboardData" ascii
        $clip4 = "AddClipboardFormatListener" ascii
        
        // Crypto address regex patterns compiled into binary
        // Bitcoin: 1/3/bc1 prefix
        $btc_regex = "^(1|3|bc1)[a-zA-Z0-9]{25,}" ascii wide
        // Ethereum: 0x prefix
        $eth_regex = "^0x[a-fA-F0-9]{40}" ascii wide
        // Solana
        $sol_regex = "[1-9A-HJ-NP-Za-km-z]{32,44}" ascii wide
        
        // Hardcoded attacker wallet addresses (obfuscated but present)
        $addr_xor = { 48 8B ?? 48 33 ?? 48 89 ?? 48 8D }
        
        // Persistence mechanisms
        $persist1 = "\\CurrentVersion\\Run\\" ascii wide
        $persist2 = "schtasks" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        3 of ($clip*) and
        any of ($btc_regex, $eth_regex, $sol_regex) and
        any of ($persist*)
}

rule apt38_wallet_seed_extractor
{
    meta:
        description = "Wallet seed phrase and private key extraction tool"
        author = "Will Welch"
        date = "2026-04-12"
        reference = "CISA AA22-108A, Mandiant APT38 reporting"
        mitre_attack = "T1005"
        severity = "critical"
        
    strings:
        // BIP-39 wordlist fragments (seed phrase validation)
        $bip39_1 = "abandon" ascii wide
        $bip39_2 = "ability" ascii wide
        $bip39_3 = "abstract" ascii wide
        $bip39_4 = "zoo" ascii wide
        
        // Wallet file paths targeted across platforms
        $path1 = ".ethereum/keystore" ascii wide
        $path2 = "Ethereum/keystore" ascii wide
        $path3 = "Bitcoin/wallets" ascii wide
        $path4 = "Exodus/exodus.wallet" ascii wide
        $path5 = "Atomic/Local Storage" ascii wide
        $path6 = "metamask" ascii wide nocase
        $path7 = "phantom" ascii wide nocase
        
        // Crypto libraries used for key derivation
        $lib1 = "secp256k1" ascii wide
        $lib2 = "ed25519" ascii wide
        $lib3 = "pbkdf2" ascii wide
        $lib4 = "bip32" ascii wide
        $lib5 = "hdkey" ascii wide
        
        // Exfiltration
        $exfil1 = "POST" ascii
        $exfil2 = "multipart" ascii
        $exfil3 = "/collect" ascii
        $exfil4 = "/upload" ascii
        
    condition:
        filesize < 10MB and
        (
            (3 of ($bip39_*) and 2 of ($path*)) or
            (2 of ($path*) and any of ($lib*) and any of ($exfil*)) or
            (any of ($bip39_*) and any of ($lib*) and any of ($exfil*))
        )
}
