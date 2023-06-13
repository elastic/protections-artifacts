rule Windows_Trojan_Grandoreiro_51236ba2 {
    meta:
        author = "Elastic Security"
        id = "51236ba2-fdbc-4c46-b57b-27fc1e135486"
        fingerprint = "c3082cc865fc177d8cbabcfcf9fb67317af5f2d28e8eeb95eb04108a558d80d4"
        creation_date = "2022-08-23"
        last_modified = "2023-06-13"
        description = "Grandoreiro rule, target loader and payload"
        threat_name = "Windows.Trojan.Grandoreiro"
        reference_sample = "1bdf381e7080d9bed3f52f4b3db1991a80d3e58120a5790c3d1609617d1f439e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $antivm0 = { B8 68 58 4D 56 BB 12 F7 6C 3C B9 0A 00 00 00 66 BA 58 56 ED B8 01 00 00 00 }
        $antivm1 = { B9 [4] 89 E5 53 51 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 BB 00 00 00 00 B8 01 00 00 00 0F 3F 07 0B }
        $xor0 = { 0F B7 44 70 ?? 33 D8 8D 45 ?? 50 89 5D ?? }
        $xor1 = { 8B 45 ?? 0F B7 44 70 ?? 33 C3 89 45 ?? }
    condition:
        all of them
}

