rule MacOS_Trojan_Mackeeper_deeb80ec {
    meta:
        id = "deeb80ec-1789-49dc-abf5-55d4fa29f46c"
        fingerprint = "3e26ff2d385eb030f4047047317191423d773178a8267bedf9eff1e8c895c0d1"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Mackeeper"
        reference_sample = "78a49bd58ee1b694e7b7b72caa7c5efe88d4f0293b024706baefa3a640a5adad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 46 74 AE FC 63 16 F3 3C 2F D4 88 F7 E5 90 66 C9 77 9A 9A 5E BA 15 31 E0 FA 27 }
    condition:
        all of them
}

rule MacOS_Trojan_Mackeeper_1a65c456 {
    meta:
        id = "1a65c456-dd4b-46e0-aeb6-a0a78fb34d2f"
        fingerprint = "3e1fa8ca471019ffd5aea646dd64722fc271d74c2298348a3447faa889d1dd4d"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Mackeeper"
        reference_sample = "97bf4a37f4ae991927ba570757f211362d24ed61077704c1af6507ae9764ad0e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 65 64 52 6F 77 49 6E 64 65 78 65 73 46 72 6F 6D 44 69 63 74 69 6F 6E 61 72 79 }
    condition:
        all of them
}

rule MacOS_Trojan_Mackeeper_b88f92c1 {
    meta:
        id = "b88f92c1-4eeb-4f23-aea2-5df7c144c550"
        fingerprint = "1d3670bd9208556c9a463a04bc77210f85a07f230121def562bf088a78b2f8da"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Mackeeper"
        reference_sample = "e9bc75f86f696fcb1425299b3dc634d549e911176c6f23708184cbb11e0a54f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { B6 79 35 47 1C 86 96 D9 D1 93 31 64 2C 86 75 53 3A 08 83 77 54 A7 A6 5D EF AD }
    condition:
        all of them
}

rule MacOS_Trojan_Mackeeper_90d56403 {
    meta:
        id = "90d56403-138a-4db0-8564-d98ce87b06bc"
        fingerprint = "9ed2a39a49cc2c4f94cde46d7da66427161bf25881b4f74a746b04f60d560dfc"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Mackeeper"
        reference_sample = "86117af4b9b01e2c897ded6ec1084496a4370fd3ad7e18187c306e7a8595863a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 4E CF 96 0B A4 C0 52 9B 52 B3 EA 80 97 AF C1 4B 06 9A 46 D3 5D 14 1C A0 1E 5B }
    condition:
        all of them
}

rule MacOS_Trojan_Mackeeper_20fd2933 {
    meta:
        id = "20fd2933-a896-4997-ac62-3921db103cdf"
        fingerprint = "5905e09c97924bc7f96e15a302588b4cb232785302a174ced2046e6decc56d3d"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Mackeeper"
        reference_sample = "0cebec8e4367f715208b52fc4048dc83d334069515765d5bd8a4bc412acda143"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 46 6F 6E 74 53 63 61 6C 65 55 70 44 6F 77 6E 4B 65 79 00 5F 6B 5A }
    condition:
        all of them
}

rule MacOS_Trojan_Mackeeper_8088dc7c {
    meta:
        id = "8088dc7c-eff8-43f6-8a0c-1eb79489fe3c"
        fingerprint = "1fcb5c2a6c524f4ca6904650df92dc1c2888e93856d8a1004bbfe2c268d82643"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Mackeeper"
        reference_sample = "f41a616a1bf90b7f2b61c5bd015bb0ac64391aad515ce52bf62fc92f05fe3a07"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 6B 5A 42 55 46 6F 6E 74 53 63 61 6C 65 55 70 44 6F 77 6E 4B 65 79 00 5F 6B 5A }
    condition:
        all of them
}

