rule Windows_Trojan_OddDancer_3793364e {
    meta:
        author = "Elastic Security"
        id = "3793364e-a73c-4cf0-855c-fdcdb2b88386"
        fingerprint = "b4620f360093284ae6f2296b4239227099f58f8f0cfe9f70298c84d6cbe7fa29"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.OddDancer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 83 65 FC 00 53 56 57 BF 00 20 00 00 57 6A 40 FF 15 }
        $a2 = { 55 8B EC 81 EC 80 00 00 00 53 56 57 33 FF 8D 45 80 6A 64 57 50 89 7D E4 89 7D EC 89 7D F0 89 7D }
    condition:
        all of them
}

rule Windows_Trojan_OddDancer_e510798d {
    meta:
        author = "Elastic Security"
        id = "e510798d-a938-47ba-92e3-0c1bcd3ce9a9"
        fingerprint = "151519156e4c6b5395c03f70c77601681f17f86a08db96a622b9489a3df682d6"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.OddDancer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 83 EC 54 53 8B 5D 08 56 57 33 FF 89 55 F4 89 4D F0 BE 00 00 00 02 89 7D F8 89 7D FC 85 DB }
        $a2 = { 55 8B EC 83 EC 0C 56 57 33 C0 8D 7D F4 AB 8D 4D F4 AB AB E8 42 10 00 00 8B 7D F4 33 F6 85 FF 74 03 8B 77 08 }
    condition:
        any of them
}

rule Windows_Trojan_OddDancer_63084eea {
    meta:
        author = "Elastic Security"
        id = "63084eea-358b-4fb0-9668-3f40f0aae9e7"
        fingerprint = "3f6ef0425b846b2126263c590d984bc618ad61de91a9141160c2b804c585ff6d"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.OddDancer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 83 EC 38 53 56 57 8B 75 08 8D 7D F0 33 C0 33 DB AB 89 5D C8 89 5D D0 89 5D D4 AB 89 5D }
    condition:
        all of them
}

rule Windows_Trojan_OddDancer_c2d80609 {
    meta:
        author = "Elastic Security"
        id = "c2d80609-9a66-4fbb-b594-17d16372cb14"
        fingerprint = "8815e42ef85ae5a8915cd26b573cd7411c041778cdf4bc99efd45526e3699642"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.OddDancer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 83 EC 30 53 56 57 33 C0 8D 7D F0 AB 33 DB 68 02 80 00 00 6A 40 89 5D FC AB AB FF 15 28 }
    condition:
        all of them
}

