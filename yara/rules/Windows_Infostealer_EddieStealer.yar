rule Windows_Infostealer_EddieStealer_12a21c75 {
    meta:
        author = "Elastic Security"
        id = "12a21c75-554e-47df-b9c2-2523296af8f3"
        fingerprint = "4700f0ebc9f6feca8b6dd6685b60d8d3b4ef1089d6996ceccb6951d2e046a7f0"
        creation_date = "2025-04-16"
        last_modified = "2025-05-23"
        threat_name = "Windows.Infostealer.EddieStealer"
        reference_sample = "47409e09afa05fcc9c9eff2c08baca3084d923c8d82159005dbae2029e1959d0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 8B 8C 24 ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? E8 }
        $b = { 48 ?? AA AA 00 00 AA AA AA AA 4? 89 ?? 04 4? 89 ?? 0C 66 [1-2] AA AA }
        $c = { 4? 89 [1-2] 0F 28 05 ?? ?? ?? ?? 0F 11 ?? 08 0F 11 ?? 18 0F 11 ?? 23 0F 57 C0 }
        $d = { 4? 8B 14 ?? 48 33 14 08 48 89 94 0C ?? ?? ?? ?? 48 83 C1 08 EB }
        $e = { 48 83 EC 38 48 8B 09 48 8B 01 48 83 21 00 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 30 48 ?? ?? ?? ?? ?? ?? 48 8D 54 24 28 48 89 02 48 8B 0A C7 ?? ?? ?? ?? ?? 48 8D 7C 24 28 8B 17 E8 }
        $f = { E8 ?? ?? ?? ?? 4? 83 ?? ( 30 | 38 | C8 | D0 ) 4? 83 ?? ( 30 | 38 | C8 | D0 ) 4? 89 ?? EB }
    condition:
        4 of them
}

