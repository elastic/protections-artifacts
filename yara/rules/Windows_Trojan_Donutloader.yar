rule Windows_Trojan_Donutloader_f40e3759 {
    meta:
        author = "Elastic Security"
        id = "f40e3759-2531-4e21-946a-fb55104814c0"
        fingerprint = "6400b34f762cebb4f91a8d24c5fce647e069a971fb3ec923a63aa98c8cfffab7"
        creation_date = "2021-09-15"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Donutloader"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $x64 = { 06 B8 03 40 00 80 C3 4C 8B 49 10 49 }
        $x86 = { 04 75 EE 89 31 F0 FF 46 04 33 C0 EB }
    condition:
        any of them
}

rule Windows_Trojan_Donutloader_5c38878d {
    meta:
        author = "Elastic Security"
        id = "5c38878d-ca94-4fd9-a36e-1ae5fe713ca2"
        fingerprint = "3b55ec6c37891880b53633b936d10f94d2b806db1723875e4ac95f8a34d97150"
        creation_date = "2021-09-15"
        last_modified = "2021-01-13"
        threat_name = "Windows.Trojan.Donutloader"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 48 03 C2 48 89 44 24 28 41 8A 00 84 C0 74 14 33 D2 FF C1 }
    condition:
        any of them
}

