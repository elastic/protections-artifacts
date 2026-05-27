rule Windows_Trojan_CastleStealer_325fd29f {
    meta:
        author = "Elastic Security"
        id = "325fd29f-7bff-4f0a-a0f1-345670f34ac5"
        fingerprint = "9697cecc90f98d3a330f6636f16f6cf95d7b1e3e4649a687f88e0b9d845c2e7e"
        creation_date = "2026-05-03"
        last_modified = "2026-05-26"
        threat_name = "Windows.Trojan.CastleStealer"
        reference_sample = "45794cfc4ab8da215a112916ae6063c20f64fd3dad8378e72386c2896241e815"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { EF BE AD DE EF BE AD DE [16] EF BE AD DE }
        $a2 = { 11 0B 1A 64 19 5F 13 09 02 17 28 }
        $a3 = { 61 13 0B 11 0B 1F 0F 5F 17 }
        $a4 = { 5F 13 04 06 09 11 04 9C 11 06 11 04 1F 49 58 61 09 17 58 1F 53 5A 58 25 1D 64 61 }
        $a5 = { 02 03 17 62 17 58 6F ?? ?? ?? ?? 94 1A 62 60 2A }
        $a6 = { 1F F7 11 05 58 45 05 00 00 00 36 00 00 }
        $a7 = { 00 09 1F 53 60 2D 05 38 93 00 00 00 00 1F 6E 0C 38 8A 00 00 00 }
        $a8 = { 02 16 91 20 87 00 00 00 61 13 0B 11 0B 1F 0F 5F 18 40 59 01 00 00 }
        $a9 = "SELECT MUILanguages FROM Win32_OperatingSystem" wide fullword
    condition:
        3 of them
}

