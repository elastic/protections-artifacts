rule Linux_Generic_Threat_a658b75f {
    meta:
        author = "Elastic Security"
        id = "a658b75f-3520-4ec6-b3d4-674bc22380b3"
        fingerprint = "112be9d42b300ce4c2e0d50c9e853d3bdab5d030a12d87aa9bae9affc67cd6cd"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "df430ab9f5084a3e62a6c97c6c6279f2461618f038832305057c51b441c648d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 6D 61 69 6E 2E 45 6E 63 72 79 70 74 46 69 6C 65 52 65 61 64 57 72 69 74 65 }
        $a2 = { 6D 61 69 6E 2E 53 63 61 6E 57 61 6C 6B 65 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_ea5ade9a {
    meta:
        author = "Elastic Security"
        id = "ea5ade9a-101e-49df-b0e8-45a04320950b"
        fingerprint = "fedf3b94c22a1dab3916b7bc6a1b88768c0debd6d628b78d8a6610b636f3c652"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "d75189d883b739d9fe558637b1fab7f41e414937a8bae7a9d58347c223a1fcaa"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 89 E5 53 8B 5D 08 B8 0D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 B8 2D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 8B 4D 0C B8 6C 00 00 00 CD 80 8B 5D FC 89 EC }
    condition:
        all of them
}

rule Linux_Generic_Threat_80aea077 {
    meta:
        author = "Elastic Security"
        id = "80aea077-c94f-4c95-83a5-967cc16df2a8"
        fingerprint = "702953af345afb999691906807066d58b9ec055d814fc6fe351e59ac5193e31f"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "002827c41bc93772cd2832bc08dfc413302b1a29008adbb6822343861b9818f0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 38 49 89 FE 0F B6 0E 48 C1 E1 18 0F B6 6E 01 48 C1 E5 10 48 09 E9 0F B6 6E 03 48 09 E9 0F B6 6E 02 48 C1 E5 08 48 09 CD 0F B6 56 04 48 C1 E2 18 44 0F B6 7E 05 49 C1 E7 10 4C 09 FA 44 }
    condition:
        all of them
}

rule Linux_Generic_Threat_2e214a04 {
    meta:
        author = "Elastic Security"
        id = "2e214a04-43a4-4c26-8737-e089fbf6eecd"
        fingerprint = "0937f7c5bcfd6f2b327981367684cff5a53d35c87eaa360e90afc9fce1aec070"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cad65816cc1a83c131fad63a545a4bd0bdaa45ea8cf039cbc6191e3c9f19dead"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 49 6E 73 65 72 74 20 76 69 63 74 69 6D 20 49 50 3A 20 }
        $a2 = { 49 6E 73 65 72 74 20 75 6E 75 73 65 64 20 49 50 3A 20 }
    condition:
        all of them
}

rule Linux_Generic_Threat_0b770605 {
    meta:
        author = "Elastic Security"
        id = "0b770605-db33-4028-b186-b1284da3e3fe"
        fingerprint = "d771f9329fec5e70b515512b58d77bb82b3c472cd0608901a6e6f606762d2d7e"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "99418cbe1496d5cd4177a341e6121411bc1fab600d192a3c9772e8e6cd3c4e88"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 68 65 79 20 73 63 61 6E 20 72 65 74 61 72 64 }
        $a2 = { 5B 62 6F 74 70 6B 74 5D 20 43 6F 6D 6D 69 74 74 69 6E 67 20 53 75 69 63 69 64 65 }
    condition:
        all of them
}

rule Linux_Generic_Threat_92064b27 {
    meta:
        author = "Elastic Security"
        id = "92064b27-f1c7-4b86-afc9-3dcfab69fe0d"
        fingerprint = "7a465615646184f5ab30d9b9b286f6e8a95cfbfa0ee780915983ec1200fd2553"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "8e5cfcda52656a98105a48783b9362bad22f61bcb6a12a27207a08de826432d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 89 E5 53 8B 4D 10 8B 5D 08 85 C9 74 0D 8A 55 0C 31 C0 88 14 18 40 39 C1 75 F8 5B 5D C3 90 90 55 89 E5 8B 4D 08 8B 55 0C 85 C9 74 0F 85 D2 74 0B 31 C0 C6 04 08 00 40 39 C2 75 F7 5D C3 90 90 }
    condition:
        all of them
}

rule Linux_Generic_Threat_de6be095 {
    meta:
        author = "Elastic Security"
        id = "de6be095-93b6-45da-b9e2-682cea7a6488"
        fingerprint = "8f2d682401b4941615ecdc8483ff461c86a12c585483e00d025a1b898321a585"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "2431239d6e60ca24a5440e6c92da62b723a7e35c805f04db6b80f96c8cf9fee6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2D 2D 66 61 72 6D 2D 66 61 69 6C 6F 76 65 72 }
        $a2 = { 2D 2D 73 74 72 61 74 75 6D 2D 66 61 69 6C 6F 76 65 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_898d9308 {
    meta:
        author = "Elastic Security"
        id = "898d9308-86d1-4b73-ae6c-c24716466f60"
        fingerprint = "fe860a6283aff8581b73440f9afbd807bb03b86dd9387b0b4ee5842a39ed7b03"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "ce89863a16787a6f39c25fd15ee48c4d196223668a264217f5d1cea31f8dc8ef"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 65 63 66 61 66 65 61 62 36 65 65 37 64 36 34 32 }
        $a2 = { 3D 3D 3D 3D 65 6E 64 20 64 75 6D 70 20 70 6C 75 67 69 6E 20 69 6E 66 6F 3D 3D 3D 3D }
    condition:
        all of them
}

rule Linux_Generic_Threat_23d54a0e {
    meta:
        author = "Elastic Security"
        id = "23d54a0e-f2e2-443e-832c-d57146350eb6"
        fingerprint = "4ff521192e2061af868b9403479680fd77d1dc71f181877a36329f63e91b7c66"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 29 2B 2F 30 31 3C 3D 43 4C 4D 50 53 5A 5B }
        $a2 = { 61 64 78 61 65 73 61 76 78 62 69 6E 63 67 6F 64 69 72 64 6E 73 65 6E 64 66 69 6E 66 6D 61 66 74 70 67 63 20 67 70 20 69 6E 20 69 6E 74 6D 61 70 6E 69 6C 6F 62 6A 70 63 3D 70 74 72 73 65 74 73 68 61 73 73 68 74 63 70 75 64 70 }
    condition:
        all of them
}

rule Linux_Generic_Threat_d7802b0a {
    meta:
        author = "Elastic Security"
        id = "d7802b0a-2286-48c8-a0b5-96af896b384e"
        fingerprint = "105112354dea4db98d295965d4816c219b049fe7b8b714f8dc3d428058a41a32"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 81 EC 88 00 00 00 48 89 AC 24 80 00 00 00 48 8D AC 24 80 00 00 00 49 C7 C5 00 00 00 00 4C 89 6C 24 78 88 8C 24 A8 00 00 00 48 89 9C 24 A0 00 00 00 48 89 84 24 98 00 00 00 C6 44 24 27 00 90 }
    condition:
        all of them
}

rule Linux_Generic_Threat_08e4ee8c {
    meta:
        author = "Elastic Security"
        id = "08e4ee8c-4dfd-4bb8-9406-dce6fb7bc9ee"
        fingerprint = "5e71d8515def09e95866a08951dd06bb84d327489f000e1c2326448faad15753"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "35eeba173fb481ac30c40c1659ccc129eae2d4d922e27cf071047698e8d95aea"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 78 63 72 79 70 74 6F 67 72 61 70 68 79 2D 32 2E 31 2E 34 2D 70 79 32 2E 37 2E 65 67 67 2D 69 6E 66 6F 2F 50 4B 47 2D 49 4E 46 4F }
    condition:
        all of them
}

rule Linux_Generic_Threat_d60e5924 {
    meta:
        author = "Elastic Security"
        id = "d60e5924-c216-4780-ba61-101abfd94b9d"
        fingerprint = "e5c5833e193c93191783b6b5c7687f5606b1bbe2e7892086246ed883e57c5d15"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "fdcc2366033541053a7c2994e1789f049e9e6579226478e2b420ebe8a7cebcd3"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2E 2F 6F 76 6C 63 61 70 2F 6D 65 72 67 65 2F 6D 61 67 69 63 }
        $a2 = { 65 78 65 63 6C 20 2F 62 69 6E 2F 62 61 73 68 }
    condition:
        all of them
}

rule Linux_Generic_Threat_6bed4416 {
    meta:
        author = "Elastic Security"
        id = "6bed4416-18fe-4416-a6ee-89d269922347"
        fingerprint = "f9d39e6aa9f8b005ff156923c68d215dabf2db79bd7d4a3dccb9ead8f1a28d88"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 61 64 78 61 65 73 61 76 78 62 69 6E 63 67 6F 64 69 72 64 6E 73 65 6E 64 66 69 6E 66 6D 61 66 74 70 67 63 20 67 70 20 69 6E 20 69 6E 74 6D 61 70 6E 69 6C 6F 62 6A 70 63 3D 70 74 72 73 65 74 73 68 61 73 73 68 74 63 70 75 64 70 }
    condition:
        all of them
}

rule Linux_Generic_Threat_fc5b5b86 {
    meta:
        author = "Elastic Security"
        id = "fc5b5b86-fa68-428d-ba31-67057380a10b"
        fingerprint = "bae66e297c19cf9c278eaefcd3cc8b3c972381effd160ee99e6f04f4ac74389d"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "134b063d9b5faed11c6db6848f800b63748ca81aeca46caa0a7c447d07a9cd9b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 14 8B 44 24 18 8B 08 89 0C 24 89 44 24 04 C6 44 24 08 00 E8 74 1D 00 00 8B 44 24 0C 89 44 24 10 8B 4C 24 18 8B 09 89 04 24 8B 54 24 1C 89 54 24 04 89 4C 24 08 E8 92 98 05 00 8B 44 24 }
    condition:
        all of them
}

rule Linux_Generic_Threat_2c8d824c {
    meta:
        author = "Elastic Security"
        id = "2c8d824c-4791-46a6-ba4d-5dcc09fdc638"
        fingerprint = "8e54bf3f6b7b563d773a1f5de0b37b8bec455c44f8af57fde9a9b684bb6f5044"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "9106bdd27e67d6eebfaec5b1482069285949de10afb28a538804ce64add88890"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 38 48 89 5C 24 50 48 89 7C 24 60 48 89 4C 24 58 48 8B 10 48 8B 40 08 48 8B 52 28 FF D2 48 89 44 24 28 48 89 5C 24 18 48 8B 4C 24 50 31 D2 90 EB 03 48 FF C2 48 39 D3 7E 6C 48 8B 34 D0 }
    condition:
        all of them
}

rule Linux_Generic_Threat_936b24d5 {
    meta:
        author = "Elastic Security"
        id = "936b24d5-f8d7-44f1-a541-94c30a514a11"
        fingerprint = "087f31195b3eaf51cd03167a877e54a5ba3ca9941145d8125c823100ba6401c4"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "fb8eb0c876148a4199cc873b84fd9c1c6abc1341e02d118f72ffb0dae37592a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 66 73 65 65 6B 6F 28 6F 70 74 2E 64 69 63 74 2C 20 30 4C 2C 20 53 45 45 4B 5F 45 4E 44 29 20 21 3D 20 2D 31 }
    condition:
        all of them
}

rule Linux_Generic_Threat_98bbca63 {
    meta:
        author = "Elastic Security"
        id = "98bbca63-68c4-4b32-8cb6-50f9dad0a8f2"
        fingerprint = "d10317a1a09e86b55eb7b00a87cb010e0d2f11ade2dccc896aaeba9819bd6ca5"
        creation_date = "2024-01-22"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "1d4d3d8e089dcca348bb4a5115ee2991575c70584dce674da13b738dd0d6ff98"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 64 65 73 63 72 69 70 74 69 6F 6E 3D 4C 4B 4D 20 72 6F 6F 74 6B 69 74 }
        $a2 = { 61 75 74 68 6F 72 3D 6D 30 6E 61 64 }
    condition:
        all of them
}

rule Linux_Generic_Threat_9aaf894f {
    meta:
        author = "Elastic Security"
        id = "9aaf894f-d3f0-460d-82f8-831fecdf8b09"
        fingerprint = "15518c7e99ed1f39db2fe21578c08aadf8553fdb9cb44e4342bf117e613c6c12"
        creation_date = "2024-01-22"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "467ac05956eec6c74217112721b3008186b2802af2cafed6d2038c79621bcb08"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2F 62 69 6E 2F 63 70 20 2F 74 6D 70 2F 70 61 6E 77 74 65 73 74 20 2F 75 73 72 2F 62 69 6E 2F 70 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_ba3a047d {
    meta:
        author = "Elastic Security"
        id = "ba3a047d-effc-444b-85b7-d31815e61dfb"
        fingerprint = "3f43a4e73a857d07c3623cf0278eecf26ef51f4a75b7913a72472ba6738adeac"
        creation_date = "2024-01-22"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "3064e89f3585f7f5b69852f1502e34a8423edf5b7da89b93fb8bd0bef0a28b8b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 52 65 61 64 69 6E 67 20 61 74 20 6D 61 6C 69 63 69 6F 75 73 5F 78 20 3D 20 25 70 2E 2E 2E 20 }
        $a2 = { 28 73 65 63 6F 6E 64 20 62 65 73 74 3A 20 30 78 25 30 32 58 20 73 63 6F 72 65 3D 25 64 29 }
    condition:
        all of them
}

rule Linux_Generic_Threat_902cfdc5 {
    meta:
        author = "Elastic Security"
        id = "902cfdc5-7f71-4661-af17-9f3dd9b21daa"
        fingerprint = "d692401d70f20648e9bb063fc8f0e750349671e56a53c33991672d29eededcb4"
        creation_date = "2024-01-23"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 54 65 67 73 6B 54 47 66 42 7A 4C 35 5A 58 56 65 41 54 4A 5A 2F 4B 67 34 67 47 77 5A 4E 48 76 69 5A 49 4E 50 49 56 70 36 4B 2F 2D 61 77 33 78 34 61 6D 4F 57 33 66 65 79 54 6F 6D 6C 71 37 2F 57 58 6B 4F 4A 50 68 41 68 56 50 74 67 6B 70 47 74 6C 68 48 }
    condition:
        all of them
}

rule Linux_Generic_Threat_094c1238 {
    meta:
        author = "Elastic Security"
        id = "094c1238-32e7-43b8-bf5e-187cf3a28c9f"
        fingerprint = "1b36f7415f215c6e39e9702ae6793fffd7c7ecce1884767b5c24a1e086101faf"
        creation_date = "2024-01-23"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "2bfe7d51d59901af345ef06dafd8f0e950dcf8461922999670182bfc7082befd"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 81 EC 18 01 00 00 48 89 D3 41 89 F6 49 89 FF 64 48 8B 04 25 28 00 00 00 48 89 84 24 10 01 00 00 49 89 E4 4C 89 E7 E8 FD 08 00 00 48 89 DF E8 75 08 00 00 4C 89 E7 48 89 DE 89 C2 E8 F8 08 00 }
    condition:
        all of them
}

rule Linux_Generic_Threat_a8faf785 {
    meta:
        author = "Elastic Security"
        id = "a8faf785-997d-4be8-9d10-c6e7050c257b"
        fingerprint = "c393af7d7fb92446019eed23bbf216d941a9598dd52ccb610432985d0da5ce04"
        creation_date = "2024-01-23"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "6028562baf0a7dd27329c8926585007ba3e0648da25088204ebab2ac8f723e70"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 89 E5 53 57 56 83 E4 F0 83 EC 10 E8 00 00 00 00 5B 81 C3 53 50 00 00 8B 45 0C 8B 4D 10 8B 55 08 65 8B 35 14 00 00 00 89 74 24 08 8D 75 14 89 74 24 04 8B 3A 56 51 50 52 FF 97 CC 01 00 00 83 }
    condition:
        all of them
}

rule Linux_Generic_Threat_04e8e4a5 {
    meta:
        author = "Elastic Security"
        id = "04e8e4a5-a1e1-4850-914a-d7e583d052a3"
        fingerprint = "08e48ddeffa8617e7848731b54a17983104240249cddccc5372c16b5d74a1ce4"
        creation_date = "2024-01-23"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "248f010f18962c8d1cc4587e6c8b683a120a1e838d091284ba141566a8a01b92"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 81 EC F8 01 00 00 48 8D 7C 24 10 E8 60 13 00 00 48 8D 7C 24 10 E8 12 07 00 00 85 ED 74 30 48 8B 3B 48 8D 54 24 02 48 B8 5B 6B 77 6F 72 6B 65 72 BE 0D 00 00 00 48 89 44 24 02 C7 44 24 0A 2F }
    condition:
        all of them
}

rule Linux_Generic_Threat_47b147ec {
    meta:
        author = "Elastic Security"
        id = "47b147ec-bcd2-423a-bc67-a85712d135eb"
        fingerprint = "38f55b825bbd1fa837b2b9903d01141a071539502fe21b874948dbc5ac215ae8"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cc7734a10998a4878b8f0c362971243ea051ce6c1689444ba6e71aea297fb70d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 50 41 54 48 3D 2F 62 69 6E 3A 2F 73 62 69 6E 3A 2F 75 73 72 2F 73 62 69 6E 3A 2F 75 73 72 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 73 62 69 6E }
    condition:
        all of them
}

rule Linux_Generic_Threat_887671e9 {
    meta:
        author = "Elastic Security"
        id = "887671e9-1e93-42d9-afb8-a96d1a87c572"
        fingerprint = "55cbfbd761e2000492059909199d16faf6839d3d893e29987b73087942c9de78"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "701c7c75ed6a7aaf59f5a1f04192a1f7d49d73c1bd36453aed703ad5560606dc"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 89 E5 57 56 53 83 E4 F0 83 EC 40 8B 45 0C E8 DC 04 00 00 81 C3 AC F7 0B 00 89 44 24 04 8B 45 08 89 04 24 E8 A7 67 00 00 85 C0 0F 88 40 04 00 00 C7 04 24 00 00 00 00 E8 03 F5 FF FF 8B 93 34 }
    condition:
        all of them
}

rule Linux_Generic_Threat_9cf10f10 {
    meta:
        author = "Elastic Security"
        id = "9cf10f10-9a5b-46b5-ae25-7239b8f1434a"
        fingerprint = "88b3122e747e685187a7b7268e22d12fbd16a24c7c2edb6f7e09c86327fc2f0e"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "d07c9be37dc37f43a54c8249fe887dbc4058708f238ff3d95ed21f874cbb84e8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 14 8B 44 24 18 8B 08 89 0C 24 89 44 24 04 C6 44 24 08 00 E8 84 1E 00 00 8B 44 24 0C 89 44 24 10 8B 4C 24 18 8B 09 89 04 24 8B 54 24 1C 89 54 24 04 89 4C 24 08 E8 52 C7 05 00 8B 44 24 }
    condition:
        all of them
}

rule Linux_Generic_Threat_75813ab2 {
    meta:
        author = "Elastic Security"
        id = "75813ab2-47f5-40ad-b512-9aa081abdc03"
        fingerprint = "e5b985f588cf6d1580b8e5dc85350fd0e1ca22ca810b1eca8d2bed774237c930"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5819eb73254fd2a698eb71bd738cf3df7beb65e8fb5e866151e8135865e3fd9a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 5B 2B 5D 20 6D 6D 61 70 3A 20 30 78 25 6C 78 20 2E 2E 20 30 78 25 6C 78 }
        $a2 = { 5B 2B 5D 20 70 61 67 65 3A 20 30 78 25 6C 78 }
    condition:
        all of them
}

rule Linux_Generic_Threat_11041685 {
    meta:
        author = "Elastic Security"
        id = "11041685-8c0d-4de0-ba43-b8f676882857"
        fingerprint = "d446fd63eb9a036a722d76183866114ab0c11c245d1f47f8949b0241d5a79e40"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "296440107afb1c8c03e5efaf862f2e8cc6b5d2cf979f2c73ccac859d4b78865a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 72 65 73 6F 6C 76 65 64 20 73 79 6D 62 6F 6C 20 25 73 20 74 6F 20 25 70 }
        $a2 = { 73 79 6D 62 6F 6C 20 74 61 62 6C 65 20 6E 6F 74 20 61 76 61 69 6C 61 62 6C 65 2C 20 61 62 6F 72 74 69 6E 67 21 }
    condition:
        all of them
}

rule Linux_Generic_Threat_0d22f19c {
    meta:
        author = "Elastic Security"
        id = "0d22f19c-5724-480b-95de-ef2609896c52"
        fingerprint = "c1899febb7bf6717bc330577a4baae4b4e81d69c4b3660944a6d8f708652d230"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "da5a204af600e73184455d44aa6e01d82be8b480aa787b28a1df88bb281eb4db"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 49 44 20 25 64 2C 20 45 55 49 44 3A 25 64 20 47 49 44 3A 25 64 2C 20 45 47 49 44 3A 25 64 }
        $a2 = { 50 54 52 41 43 45 5F 50 4F 4B 45 55 53 45 52 20 66 61 75 6C 74 }
    condition:
        all of them
}

rule Linux_Generic_Threat_4a46b0e1 {
    meta:
        author = "Elastic Security"
        id = "4a46b0e1-b0d4-423c-9600-f594d3a48a33"
        fingerprint = "2ae70fc399a228284a3827137db2a5b65180811caa809288df44e5b484eb1966"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "3ba47ba830ab8deebd9bb906ea45c7df1f7a281277b44d43c588c55c11eba34a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 20 28 76 69 61 20 53 79 73 74 65 6D 2E 6D 61 70 29 }
        $a2 = { 20 5B 2B 5D 20 52 65 73 6F 6C 76 65 64 20 25 73 20 74 6F 20 25 70 25 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_0a02156c {
    meta:
        author = "Elastic Security"
        id = "0a02156c-2958-44c5-9dbd-a70d528e507d"
        fingerprint = "aa7a34e72e03b70f2f73ae319e2cc9866fbf2eddd4e6a8a2835f9b7c400831cd"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "f23d4b1fd10e3cdd5499a12f426e72cdf0a098617e6b178401441f249836371e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 72 65 71 75 69 72 65 73 5F 6E 75 6C 6C 5F 70 61 67 65 }
        $a2 = { 67 65 74 5F 65 78 70 6C 6F 69 74 5F 73 74 61 74 65 5F 70 74 72 }
    condition:
        all of them
}

