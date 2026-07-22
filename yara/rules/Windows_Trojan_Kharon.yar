rule Windows_Trojan_Kharon_51bcd790 {
    meta:
        author = "Elastic Security"
        id = "51bcd790-aa72-4d97-8df7-47eb4cf5f930"
        fingerprint = "c560acde5f15d2187a7fd879a1ee8386f74699db37bf05aeb5d497267962dc35"
        creation_date = "2026-06-30"
        last_modified = "2026-07-20"
        threat_name = "Windows.Trojan.Kharon"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 8B 86 78 05 00 00 48 8B 4E 30 48 89 41 18 48 8B 86 80 05 00 00 48 89 41 48 48 8B 86 D0 05 00 00 48 89 81 D8 00 00 00 48 8B 86 E0 05 00 00 }
        $a2 = { 41 8D 6E E0 41 80 FE 61 45 0F B6 F6 40 0F B6 ED 41 0F 42 EE 40 0F B6 ED 31 DD }
        $a3 = { 4D 89 5A 08 49 89 72 10 49 89 42 18 49 89 42 20 48 8B 01 }
        $a4 = { 44 0F B7 F3 44 21 DB 41 8D AE E0 00 00 00 66 83 FB 61 41 0F 42 EE 44 21 DD }
    condition:
        2 of them
}

