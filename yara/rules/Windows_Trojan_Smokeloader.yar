rule Windows_Trojan_Smokeloader_4e31426e {
    meta:
        author = "Elastic Security"
        id = "4e31426e-d62e-4b6d-911b-4223e1f6adef"
        fingerprint = "cf6d8615643198bc53527cb9581e217f8a39760c2e695980f808269ebe791277"
        creation_date = "2021-07-21"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "1ce643981821b185b8ad73b798ab5c71c6c40e1f547b8e5b19afdaa4ca2a5174"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 5B 81 EB 34 10 00 00 6A 30 58 64 8B 00 8B 40 0C 8B 40 1C 8B 40 08 89 85 C0 }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_4ee15b92 {
    meta:
        author = "Elastic Security"
        id = "4ee15b92-c62f-42d2-bbba-1dac2fa5644f"
        fingerprint = "5d2ed385c76dbb4c1c755ae88b68306086a199a25a29317ae132bc874b253580"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "09b9283286463b35ea2d5abfa869110eb124eb8c1788eb2630480d058e82abf2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 34 30 33 33 8B 45 F4 5F 5E 5B C9 C2 10 00 55 89 E5 83 EC }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_ea14b2a5 {
    meta:
        author = "Elastic Security"
        id = "ea14b2a5-ea0d-4da2-8190-dbfcda7330d9"
        fingerprint = "950ce9826fdff209b6e03c70a4f78b812d211a2a9de84bec0e5efe336323001b"
        creation_date = "2023-05-03"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "15fe237276b9c2c6ceae405c0739479d165b406321891c8a31883023e7b15d54"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { AC 41 80 01 AC 41 80 00 AC 41 80 00 AC 41 C0 00 AC 41 80 01 }
        $a2 = { AC 41 80 00 AC 41 80 07 AC 41 80 00 AC 41 80 00 AC 41 80 00 }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_de52ed44 {
    meta:
        author = "Elastic Security"
        id = "de52ed44-062c-4b0d-9a41-1bfc31a8daa9"
        fingerprint = "950db8f87a81ef05cc2ecbfa174432ab31a3060c464836f3b38448bd8e5801be"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "c689a384f626616005d37a94e6a5a713b9eead1b819a238e4e586452871f6718"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 08 31 FF 89 7D CC 66 8C E8 66 85 C0 74 03 FF 45 CC FF 53 48 }
        $a2 = { B0 8F 45 C8 8D 45 B8 89 38 8D 4D C8 6A 04 57 6A 01 51 57 57 }
    condition:
        all of them
}

