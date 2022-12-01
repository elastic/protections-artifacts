rule Windows_Trojan_RedLineStealer_17ee6a17 {
    meta:
        author = "Elastic Security"
        id = "17ee6a17-161e-454a-baf1-2734995c82cd"
        fingerprint = "a1f75937e83f72f61e027a1045374d3bd17cd387b223a6909b9aed52d2bc2580"
        creation_date = "2021-06-12"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "497bc53c1c75003fe4ae3199b0ff656c085f21dffa71d00d7a3a33abce1a3382"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "RedLine.Logic.SQLite" ascii fullword
        $a2 = "RedLine.Reburn.Data.Browsers.Gecko" ascii fullword
        $a3 = "RedLine.Client.Models.Gecko" ascii fullword
        $b1 = "SELECT * FROM Win32_Process Where SessionId='{0}'" wide fullword
        $b2 = "get_encryptedUsername" ascii fullword
        $b3 = "https://icanhazip.com" wide fullword
        $b4 = "GetPrivate3Key" ascii fullword
        $b5 = "get_GrabTelegram" ascii fullword
        $b6 = "<GrabUserAgent>k__BackingField" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

rule Windows_Trojan_RedLineStealer_f54632eb {
    meta:
        author = "Elastic Security"
        id = "f54632eb-2c66-4aff-802d-ad1c076e5a5e"
        fingerprint = "6a9d45969c4d58181fca50d58647511b68c1e6ee1eeac2a1838292529505a6a0"
        creation_date = "2021-06-12"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "d82ad08ebf2c6fac951aaa6d96bdb481aa4eab3cd725ea6358b39b1045789a25"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "ttp://checkip.amazonaws.com/logins.json" wide fullword
        $a2 = "https://ipinfo.io/ip%appdata%\\" wide fullword
        $a3 = "Software\\Valve\\SteamLogin Data" wide fullword
        $a4 = "get_ScannedWallets" ascii fullword
        $a5 = "get_ScanTelegram" ascii fullword
        $a6 = "get_ScanGeckoBrowsersPaths" ascii fullword
        $a7 = "<Processes>k__BackingField" ascii fullword
        $a8 = "<GetWindowsVersion>g__HKLM_GetString|11_0" ascii fullword
        $a9 = "<ScanFTP>k__BackingField" ascii fullword
        $a10 = "DataManager.Data.Credentials" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_RedLineStealer_d25e974b {
    meta:
        author = "Elastic Security"
        id = "d25e974b-7cf0-4c0e-bf57-056cbb90d77e"
        fingerprint = "f936511802dcce39dfed9ec898f3ab0c4b822fd38bac4e84d60966c7b791688c"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 43 3F FF 48 42 3F FF 48 42 3F FF 48 42 3E FF 48 42 3E FF }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_ed346e4c {
    meta:
        author = "Elastic Security"
        id = "ed346e4c-7890-41ee-8648-f512682fe20e"
        fingerprint = "834c13b2e0497787e552bb1318664496d286e7cf57b4661e5e07bf1cffe61b82"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_3d9371fd {
    meta:
        author = "Elastic Security"
        id = "3d9371fd-c094-40fc-baf8-f0e9e9a54ff9"
        fingerprint = "2d7ff7894b267ba37a2d376b022bae45c4948ef3a70b1af986e7492949b5ae23"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "0ec522dfd9307772bf8b600a8b91fd6facd0bf4090c2b386afd20e955b25206a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "get_encrypted_key" ascii fullword
        $a2 = "get_PassedPaths" ascii fullword
        $a3 = "ChromeGetLocalName" ascii fullword
        $a4 = "GetBrowsers" ascii fullword
        $a5 = "Software\\Valve\\SteamLogin Data" wide fullword
        $a6 = "%appdata%\\" wide fullword
        $a7 = "ScanPasswords" ascii fullword
    condition:
        all of them
}

