rule Linux_Trojan_XZBackdoor_74e87a9d {
    meta:
        author = "Elastic Security"
        id = "74e87a9d-11c1-4e86-bb3c-63a3c51c50df"
        fingerprint = "f1982d1db5aacd2d6b0b4c879f9f75d4413e0d43e58ea7de2b7dff66ec0f93ab"
        creation_date = "2024-03-30"
        last_modified = "2024-03-31"
        threat_name = "Linux.Trojan.XZBackdoor"
        reference_sample = "5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "yolAbejyiejuvnup=Evjtgvsh5okmkAvj"
        $a2 = { F3 0F 1E FA 55 48 89 F5 4C 89 CE 53 89 FB 81 E7 00 00 00 80 48 83 EC 28 48 89 54 24 18 48 89 4C 24 10 }
        $b1 = { 48 8D 7C 24 08 F3 AB 48 8D 44 24 08 48 89 D1 4C 89 C7 48 89 C2 E8 ?? ?? ?? ?? 89 C2 }
        $b2 = { 31 C0 49 89 FF B9 16 00 00 00 4D 89 C5 48 8D 7C 24 48 4D 89 CE F3 AB 48 8D 44 24 48 }
        $b3 = { 4D 8B 6C 24 08 45 8B 3C 24 4C 8B 63 10 89 85 78 F1 FF FF 31 C0 83 BD 78 F1 FF FF 00 F3 AB 79 07 }
    condition:
        1 of ($a*) or all of ($b*)
}

