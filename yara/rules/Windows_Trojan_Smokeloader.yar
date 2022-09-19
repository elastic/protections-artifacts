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

rule Windows_Trojan_Smokeloader_3687686f {
    meta:
        author = "Elastic Security"
        id = "3687686f-8fbf-4f09-9afa-612ee65dc86c"
        fingerprint = "0f483f9f79ae29b944825c1987366d7b450312f475845e2242a07674580918bc"
        creation_date = "2021-07-21"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "8b3014ecd962a335b246f6c70fc820247e8bdaef98136e464b1fdb824031eef7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 0C 8B 45 F0 89 45 C8 8B 45 C8 8B 40 3C 8B 4D F0 8D 44 01 04 89 }
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

