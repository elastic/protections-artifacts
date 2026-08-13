rule Windows_Trojan_Remus_7a39fb15 {
    meta:
        author = "Elastic Security"
        id = "7a39fb15-e7d0-47a6-a817-f79dcdb82ed5"
        fingerprint = "4d7cec94236113c06a6a1e65882363bb930ce0a8ac2d2c687499e87df2f20d5a"
        creation_date = "2026-04-08"
        last_modified = "2026-08-06"
        threat_name = "Windows.Trojan.Remus"
        reference_sample = "0a8f734f10400f7ae8fef591147e78dab6350089683be84c1cb6c82113cb1319"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "# REMUS LOG" ascii fullword
        $b1 = { 48 83 EC 10 4C 89 14 24 4C 89 5C 24 08 4D 31 DB 4C 8D 54 24 18 49 29 C2 4D 0F 42 DA 65 4C 8B 1C 25 10 00 00 00 4D 39 DA 73 ?? 66 ?? ?? ?? ?? ?? 4D 8D 9B 00 F0 FF FF 45 84 1B 4D 39 DA }
        $b2 = { 81 3C D1 7C 65 E0 52 74 ?? 48 FF C2 48 39 D0 75 EF }
        $b3 = { 41 89 D0 41 83 E0 55 41 83 F0 55 41 89 D1 41 81 E1 AA }
        $b4 = { 69 D2 00 00 00 49 C1 EA 18 30 D1 }
    condition:
        2 of them
}

