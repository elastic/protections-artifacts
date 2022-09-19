rule Windows_Trojan_Emotet_18379a8d {
    meta:
        author = "Elastic Security"
        id = "18379a8d-f1f2-49cc-8edf-58a3ba77efe7"
        fingerprint = "b7650b902a1a02029e28c88dd7ff91d841136005b0246ef4a08aaf70e57df9cc"
        creation_date = "2021-11-17"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Emotet"
        reference_sample = "eeb13cd51faa7c23d9a40241d03beb239626fbf3efe1dbbfa3994fc10dea0827"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 04 33 CB 88 0A 8B C1 C1 E8 08 8D 52 04 C1 E9 10 88 42 FD 88 }
    condition:
        all of them
}

rule Windows_Trojan_Emotet_5528b3b0 {
    meta:
        author = "Elastic Security"
        id = "5528b3b0-d4cb-485e-bc0c-96415ec3a795"
        fingerprint = "717ed656d1bd4ba0e4dae8e47268e2c068dad3e3e883ff6da2f951d61f1be642"
        creation_date = "2021-11-17"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Emotet"
        reference_sample = "eeb13cd51faa7c23d9a40241d03beb239626fbf3efe1dbbfa3994fc10dea0827"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 20 89 44 24 10 83 C2 02 01 74 24 10 01 7C 24 10 29 5C 24 10 66 }
    condition:
        all of them
}

rule Windows_Trojan_Emotet_1943bbf2 {
    meta:
        author = "Elastic Security"
        id = "1943bbf2-56c0-443e-9208-cd8fc3b02d79"
        fingerprint = "df8b73d83a50a58ed8332b7580c970c2994aa31d2ac1756cff8e0cd1777fb8fa"
        creation_date = "2021-11-18"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Emotet"
        reference_sample = "5abec3cd6aa066b1ddc0149a911645049ea1da66b656c563f9a384e821c5db38"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 66 83 38 5C 74 0A 83 C0 02 66 39 30 75 F2 EB 06 33 C9 66 89 }
    condition:
        all of them
}

rule Windows_Trojan_Emotet_db7d33fa {
    meta:
        author = "Elastic Security"
        id = "db7d33fa-e50c-4c59-ab92-edb74aac87c9"
        fingerprint = "eac196154ab1ad636654c966e860dcd5763c50d7b8221dbbc7769c879daf02fd"
        creation_date = "2022-05-09"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Emotet"
        reference_sample = "08c23400ff546db41f9ddbbb19fa75519826744dde3b3afb38f3985266577afc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $chunk_0 = { 4C 8D 9C 24 ?? ?? ?? ?? 8B C3 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 5D C3 }
        $chunk_1 = { 8B C7 41 0F B7 4C 45 ?? 41 8B 1C 8C 48 03 DD 48 3B DE 72 ?? }
        $chunk_2 = { 48 8B C4 48 89 48 ?? 48 89 50 ?? 4C 89 40 ?? 4C 89 48 ?? C3 }
        $chunk_3 = { 48 8B 45 ?? BB 01 00 00 00 48 89 07 8B 45 ?? 89 47 ?? 4C 8D 9C 24 ?? ?? ?? ?? 8B C3 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 5D C3 }
        $chunk_4 = { 48 39 3B 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 5B ?? 49 8B 73 ?? 40 0F 95 C7 8B C7 49 8B 7B ?? 49 8B E3 5D C3 }
        $chunk_5 = { BE 02 00 00 00 4C 8D 9C 24 ?? ?? ?? ?? 8B C6 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 49 8B E3 41 5F 41 5E 41 5D 41 5C 5D C3 }
        $chunk_6 = { 43 8B 84 FE ?? ?? ?? ?? 48 03 C6 48 3B D8 73 ?? }
        $chunk_7 = { 88 02 48 FF C2 48 FF C3 8A 03 84 C0 75 ?? EB ?? }
    condition:
        4 of them
}

rule Windows_Trojan_Emotet_d6ac1ea4 {
    meta:
        author = "Elastic Security"
        id = "d6ac1ea4-b0a8-4023-b712-9f4f2c7146a3"
        fingerprint = "7e6224c58c283765b5e819eb46814c556ae6b7b5931cd1e3e19ca3ec8fa31aa2"
        creation_date = "2022-05-24"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Emotet"
        reference_sample = "2c6709d5d2e891d1ce26fdb4021599ac10fea93c7773f5c00bea8e5e90404b71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $calc1 = { C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? }
        $pre = { 48 83 EC ( 18 | 28 ) C7 44 24 ?? ?? ?? ?? ?? }
        $setup = { 48 8D 05 ?? ?? ?? ?? 48 89 81 ?? ?? ?? ?? }
        $post = { 8B 44 24 ?? 89 44 24 ?? 48 83 C4 18 C3 }
    condition:
        #calc1 >= 10 and #pre >= 5 and #setup >= 5 and #post >= 5
}

