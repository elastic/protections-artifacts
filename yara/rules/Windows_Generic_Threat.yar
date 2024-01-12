rule Windows_Generic_Threat_bc6ae28d {
    meta:
        author = "Elastic Security"
        id = "bc6ae28d-050b-43d9-ba57-82fb37a2bc91"
        fingerprint = "40a45e5b109a9b48cecd95899ff6350af5d28deb1c6f3aa4f0363ed3abf62bf7"
        creation_date = "2023-12-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ce00873eb423c0259c18157a07bf7fd9b07333e528a5b9d48be79194310c9d97"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 83 79 08 00 75 19 DD 01 8D 45 DC 50 51 51 DD 1C 24 E8 DB FC FF FF 85 C0 74 05 8B 45 F0 C9 C3 83 C8 FF C9 C3 55 8B EC 83 EC 24 83 79 08 00 75 19 DD 01 8D 45 DC 50 51 51 DD 1C }
    condition:
        all of them
}

rule Windows_Generic_Threat_ce98c4bc {
    meta:
        author = "Elastic Security"
        id = "ce98c4bc-22bb-4c2b-bced-8fc36bd3a2f0"
        fingerprint = "d0849208c71c1845a6319052474549dba8514ecf7efe6185c1af22ad151bdce7"
        creation_date = "2023-12-17"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "950e8a29f516ef3cf1a81501e97fbbbedb289ad9fb93352edb563f749378da35"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4D 65 73 73 61 67 65 50 61 63 6B 4C 69 62 2E 4D 65 73 73 61 67 65 50 61 63 6B }
        $a2 = { 43 6C 69 65 6E 74 2E 41 6C 67 6F 72 69 74 68 6D }
    condition:
        all of them
}

rule Windows_Generic_Threat_0cc1481e {
    meta:
        author = "Elastic Security"
        id = "0cc1481e-d666-4443-852c-679ef59e4ee4"
        fingerprint = "3dac71f8cbe7cb12066e91ffb6da6524891654fda249fa5934946fd5a2120360"
        creation_date = "2023-12-17"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6ec7781e472a6827c1406a53ed4699407659bd57c33dd4ab51cabfe8ece6f23f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 A8 53 56 57 8B FA 8B D8 8B 43 28 3B 78 10 0F 84 B4 00 00 00 8B F0 85 FF 75 15 83 7E 04 01 75 0F 8B 46 10 E8 03 A7 FF FF 33 C0 89 46 10 EB 7C 8B C3 E8 B5 F3 FF FF 8B C3 E8 BE F3 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2507c37c {
    meta:
        author = "Elastic Security"
        id = "2507c37c-a0ef-47e0-a02a-3e28f4655715"
        fingerprint = "b20b76f19d21730b6e32d1468f0e14ee9d6f9f07b9692fb6dec76605d9b967e2"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "04296258f054a958f0fd013b3c6a3435280b28e9a27541463e6fc9afe30363cc"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 45 14 56 57 33 FF 3B C7 74 47 39 7D 08 75 1B E8 B2 2B 00 00 6A 16 5E 89 30 57 57 57 57 57 E8 3B 2B 00 00 83 C4 14 8B C6 EB 29 39 7D 10 74 E0 39 45 0C 73 0E E8 8D 2B 00 00 6A 22 59 }
    condition:
        all of them
}

rule Windows_Generic_Threat_e052d248 {
    meta:
        author = "Elastic Security"
        id = "e052d248-32f2-4d51-b42d-468a09e06daa"
        fingerprint = "ccfbcb9271b1ce99b814cf9e3a4776e9501035166824beaf39d4b8cd03446ef3"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ed2bbc0d120665044aacb089d8c99d7c946b54d1b08a078aebbb3b91f593da6e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 64 A1 00 00 00 00 6A FF 68 4F 5A 54 00 50 64 89 25 00 00 00 00 6A 02 68 24 D0 58 00 E8 FF 65 10 00 C7 45 FC FF FF FF FF 68 10 52 55 00 E8 F7 72 10 00 8B 4D F4 83 C4 0C 64 89 0D 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2bb7fbe3 {
    meta:
        author = "Elastic Security"
        id = "2bb7fbe3-2add-4ae9-adbf-5f043475d879"
        fingerprint = "e20c20c61768bd936cc18df56d7ec12d92745b6534ac8149bf367d6ad62fa8bd"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "65cc8704c0e431589d196eadb0ac8a19151631c8d4ab7375d7cb18f7b763ba7b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 14 68 B6 32 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 30 53 56 57 89 65 EC C7 45 F0 C0 15 40 00 33 F6 89 75 F4 89 75 F8 89 75 E0 89 75 DC 89 75 D8 6A 01 FF 15 AC 10 }
    condition:
        all of them
}

rule Windows_Generic_Threat_994f2330 {
    meta:
        author = "Elastic Security"
        id = "994f2330-ce61-4c23-b100-7df3feaeb078"
        fingerprint = "4749717da2870a3942d7a3aa7e2809c4b9dc783a484bfcd2ce7416ae67164a26"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0a30cb09c480a2659b6f989ac9fe1bfba1802ae3aad98fa5db7cdd146fee3916"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 0C 8B 55 08 85 D2 0F 84 C7 00 00 00 8B 42 3C 83 7C 10 74 10 8D 44 10 18 0F 82 B5 00 00 00 83 78 64 00 0F 84 AB 00 00 00 8B 4D 0C 8B 40 60 C1 E9 10 03 C2 66 85 C9 75 14 0F B7 4D }
    condition:
        all of them
}

rule Windows_Generic_Threat_bf7aae24 {
    meta:
        author = "Elastic Security"
        id = "bf7aae24-f89a-4cc6-9a15-fc29aa80af98"
        fingerprint = "9304e9069424d43613ef9a5484214d0e3620245ef9ae64bae7d825f5f69d90c0"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6dfc63894f15fc137e27516f2d2a56514c51f25b41b00583123142cf50645e4e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 33 F6 44 8B EE 48 89 74 24 20 8B EE 48 89 B4 24 A8 00 00 00 44 8B F6 48 89 74 24 28 44 8B E6 E8 BF FF FF FF 4C 8B F8 8D 5E 01 B8 4D 5A 00 00 66 41 39 07 75 1B 49 63 57 3C 48 8D 4A }
    condition:
        all of them
}

rule Windows_Generic_Threat_d542e5a5 {
    meta:
        author = "Elastic Security"
        id = "d542e5a5-0648-40de-8b70-9f78f9bd1443"
        fingerprint = "62d3edc282cedd5a6464b92725a3916e3bdc75e8eb39db457d783cb27afa3aec"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3fc4ae7115e0bfa3fc6b75dcff867e7bf9ade9c7f558f31916359d37d001901b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 56 FF 75 08 8B F1 E8 B6 FF FF FF C7 06 AC 67 41 00 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 FF 75 08 8B F1 E8 99 FF FF FF C7 06 B8 67 41 00 8B C6 5E 5D C2 04 00 B8 EF 5B 40 00 A3 E8 5A }
    condition:
        all of them
}

rule Windows_Generic_Threat_8d10790b {
    meta:
        author = "Elastic Security"
        id = "8d10790b-6f26-46bf-826e-1371565763f0"
        fingerprint = "7cc33c6684318373e45f5e7440f0a416dd5833a56bc31eb8198a3c36b15dd25e"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "911535923a5451c10239e20e7130d371e8ee37172e0f14fc8cf224d41f7f4c0f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 81 EC 04 00 00 00 8B 5D 08 8B 1B 83 C3 04 89 5D FC 8B 45 0C 8B 5D FC 89 03 8B E5 5D C2 08 00 55 8B EC 81 EC 0C 00 00 00 C7 45 FC 00 00 00 00 68 00 00 00 00 BB C4 02 00 00 E8 0D 05 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_347f9f54 {
    meta:
        author = "Elastic Security"
        id = "347f9f54-b9a6-4d40-9627-d3cef78f13eb"
        fingerprint = "860f951db43fa3389c5057f7329b5d13d9347b6e04e1363dd0a8060d5a131991"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "45a051651ce1edddd33ecef09bb0fbb978adec9044e64f786b13ed81cabf6a3f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 10 FF 75 0C 80 65 FC 00 8D 45 F0 C6 45 F0 43 50 C6 45 F1 6F FF 75 08 C6 45 F2 6E C6 45 F3 6E C6 45 F4 65 C6 45 F5 63 C6 45 F6 74 C6 45 F7 47 C6 45 F8 72 C6 45 F9 6F C6 45 FA 75 }
    condition:
        all of them
}

rule Windows_Generic_Threat_20469956 {
    meta:
        author = "Elastic Security"
        id = "20469956-1be6-48e8-b3c4-5706f9630971"
        fingerprint = "67cec754102e3675b4e72ff4826c40614e4856b9cbf12489de3406318990fc85"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "a1f2923f68f5963499a64bfd0affe0a729f5e7bd6bcccfb9bed1d62831a93c47"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E4 F8 83 EC 5C 53 56 33 C0 C7 44 24 18 6B 00 6C 00 57 8D 4C 24 1C C7 44 24 20 69 00 66 00 C7 44 24 24 2E 00 73 00 C7 44 24 28 79 00 73 00 66 89 44 24 2C C7 44 24 0C 6B 00 6C 00 C7 }
    condition:
        all of them
}

rule Windows_Generic_Threat_742e8a70 {
    meta:
        author = "Elastic Security"
        id = "742e8a70-c150-4903-a551-9123587dd473"
        fingerprint = "733b3563275da0a1b4781b9c0aa07e6e968133ae099eddef9cad3793334b9aa5"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "94f7678be47651aa457256375f3e4d362ae681a9524388c97dc9ed34ba881090"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC E8 96 FF FF FF E8 85 0D 00 00 83 7D 08 00 A3 A4 E9 43 00 74 05 E8 0C 0D 00 00 DB E2 5D C3 8B FF 55 8B EC 83 3D B0 E9 43 00 02 74 05 E8 BA 12 00 00 FF 75 08 E8 07 11 00 00 68 FF 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_79174b5c {
    meta:
        author = "Elastic Security"
        id = "79174b5c-bc1d-40b2-b2e9-f3ddd3ba226c"
        fingerprint = "1e709e5cb8302ea19f9ee93e88f7f910f4271cf1ea2a6c92946fa26f68c63f4d"
        creation_date = "2023-12-18"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c15118230059e85e7a6b65fe1c0ceee8997a3d4e9f1966c8340017a41e0c254c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 48 56 57 6A 0F 33 C0 59 8D 7D B9 F3 AB 8B 75 0C 6A 38 66 AB 8B 4E 14 AA 8B 46 10 89 4D FC 89 45 F8 59 C1 E8 03 83 E0 3F C6 45 B8 80 3B C1 72 03 6A 78 59 2B C8 8D 45 B8 51 50 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_232b71a9 {
    meta:
        author = "Elastic Security"
        id = "232b71a9-add2-492d-8b9a-ad2881826ecf"
        fingerprint = "908e2a968e544dfb08a6667f78c92df656c7f2c5cf329dbba6cfdb5ea7b51a57"
        creation_date = "2023-12-20"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1e8b34da2d675af96b34041d4e493e34139fc8779f806dbcf62a6c9c4d9980fe"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 61 61 62 63 64 65 65 66 67 68 69 69 6A 6B 6C 6D 6E 6F 6F 70 71 72 73 74 75 75 76 77 78 79 7A 61 55 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d331d190 {
    meta:
        author = "Elastic Security"
        id = "d331d190-2b66-499e-be08-fed81e5bb5f1"
        fingerprint = "504c204dd82689bacf3875b9fd56a6a865426f3dc76de1d6d6e40c275b069d66"
        creation_date = "2023-12-20"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6d869d320d977f83aa3f0e7719967c7e54c1bdae9ae3729668d755ee3397a96f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 83 FA 03 74 04 85 D2 75 05 E8 EE 08 00 00 B8 01 00 00 00 48 83 C4 28 C3 CC CC CC CC 56 57 48 83 EC 38 48 89 CE 8B 01 FF C8 83 F8 05 77 12 48 98 48 8D 0D D1 49 00 00 48 63 3C 81 48 }
    condition:
        all of them
}

rule Windows_Generic_Threat_24191082 {
    meta:
        author = "Elastic Security"
        id = "24191082-58a7-4d1e-88d2-b4935ba5a868"
        fingerprint = "6bf991b391b79e897fe7964499e7e86b7b8fe4f40cf17abba85cb861e840e082"
        creation_date = "2023-12-20"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "4d20878c16d2b401e76d8e7c288cf8ef5aa3c8d4865f440ee6b44d9f3d0cbf33"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 45 0C 48 F7 D0 23 45 08 5D C3 55 8B EC 51 8B 45 0C 48 23 45 08 74 15 FF 75 0C FF 75 08 E8 DA FF FF FF 59 59 03 45 0C 89 45 FC EB 06 8B 45 08 89 45 FC 8B 45 FC 8B E5 5D C3 55 8B EC }
    condition:
        all of them
}

rule Windows_Generic_Threat_efdb9e81 {
    meta:
        author = "Elastic Security"
        id = "efdb9e81-9004-426e-b599-331560b7f0ff"
        fingerprint = "ce1499c8adaad552c127ae80dad90a39eb15e1e461afe3266e8cd6961d3fde79"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1c3302b14324c9f4e07829f41cd767ec654db18ff330933c6544c46bd19e89dd"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4D 61 78 69 6D 75 6D 43 68 65 63 6B 42 6F 78 53 69 7A 65 }
        $a2 = { 56 69 73 75 61 6C 50 6C 75 73 2E 4E 61 74 69 76 65 }
    condition:
        all of them
}

rule Windows_Generic_Threat_34622a35 {
    meta:
        author = "Elastic Security"
        id = "34622a35-9ddf-4091-8b0c-c9430ecea57c"
        fingerprint = "427762237cd1040bad58e9d9f7ad36c09134d899c5105e977f94933827c5d5e0"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c021c6adca0ddf38563a13066a652e4d97726175983854674b8dae2f6e59c83f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 81 EC 88 00 00 00 C7 45 FC 00 00 00 00 C7 45 F8 00 00 00 00 68 4C 00 00 00 E8 A3 42 00 00 83 C4 04 89 45 F4 8B D8 8B F8 33 C0 B9 13 00 00 00 F3 AB 83 C3 38 53 68 10 00 00 00 E8 82 42 }
    condition:
        all of them
}

rule Windows_Generic_Threat_0ff403df {
    meta:
        author = "Elastic Security"
        id = "0ff403df-cf94-43f3-b8b0-b94068f333f1"
        fingerprint = "3e16fe70b069579a146682d2bbeeeead63c432166b269a6d3464463ccd2bd2f8"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b3119dc4cea05bef51d1f373b87d69bcff514f6575d4c92da4b1c557f8d8db8f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 81 EC 00 02 00 00 56 8B F1 57 C6 85 00 FF 63 C7 06 0C 22 41 00 0C 66 69 B6 66 01 7C 06 02 77 03 96 66 69 B6 7B 14 04 F2 05 6B 06 69 96 66 69 6F 07 C5 08 30 66 69 96 66 09 01 0A 67 0B }
    condition:
        all of them
}

rule Windows_Generic_Threat_b1f6f662 {
    meta:
        author = "Elastic Security"
        id = "b1f6f662-ea77-4049-a58a-ed8a97d7738e"
        fingerprint = "f2cd22e34b4694f707ee9042805f5498ce66d35743950096271aaa170f44a2ee"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1b7eaef3cf1bb8021a00df092c829932cccac333990db1c5dac6558a5d906400"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
        $a2 = { 73 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
        $a3 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 31 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2c80562d {
    meta:
        author = "Elastic Security"
        id = "2c80562d-2377-43b2-864f-0f122530b85d"
        fingerprint = "30965c0d6ac30cfb10674b2600e5a1e7b14380072738dd7993bd3eb57c825f24"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ee8decf1e8e5a927e3a6c10e88093bb4b7708c3fd542d98d43f1a882c6b0198e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 50 6F 6C 79 6D 6F 64 58 54 2E 65 78 65 }
        $a2 = { 50 6F 6C 79 6D 6F 64 58 54 20 76 31 2E 33 }
        $a3 = { 50 6F 6C 79 6D 6F 64 20 49 6E 63 2E }
    condition:
        all of them
}

rule Windows_Generic_Threat_e96f9e97 {
    meta:
        author = "Elastic Security"
        id = "e96f9e97-cb44-42e5-a06b-98775cbb1f2f"
        fingerprint = "2277fb0b58f923d394f5d4049b6049e66f99aff4ac874849bdc1877b9c6a0d3e"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "bfbab69e9fc517bc46ae88afd0603a498a4c77409e83466d05db2797234ea7fc"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 7A 47 4D 5E 5A 4D 5D 4B 7D 6D 4A 41 57 4B 54 49 5F 4C 67 6D 54 52 5B 51 46 43 6F 71 40 46 45 53 67 7C 5D 6F }
    condition:
        all of them
}

rule Windows_Generic_Threat_005fd471 {
    meta:
        author = "Elastic Security"
        id = "005fd471-d968-4ece-a61d-91beac4c1e34"
        fingerprint = "30afbb04c257c20ccd2cff15f893715187b7e7b66a9c9f09d076d21466e25a57"
        creation_date = "2024-01-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "502814ed565a923da15626d46fde8cc7fd422790e32b3cad973ed8ec8602b228"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 5F 3F 44 4B 4B 66 25 37 2A 5E 70 42 70 }
        $a2 = { 71 5A 3E 7D 6F 5D 6E 2D 74 48 5E 55 55 22 3C }
        $a3 = { 3E 2D 21 47 45 6A 3C 33 23 47 5B 51 }
    condition:
        all of them
}

rule Windows_Generic_Threat_54b0ec47 {
    meta:
        author = "Elastic Security"
        id = "54b0ec47-79f3-4187-8253-805e7ad102ce"
        fingerprint = "2c3890010aad3c2b54cba08a62b5af6a678849a6b823627bf9e26c8693a89c60"
        creation_date = "2024-01-03"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9c14203069ff6003e7f408bed71e75394de7a6c1451266c59c5639360bf5718c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 2D 2D 2D 2D 3D 5F 25 73 5F 25 2E 33 75 5F 25 2E 34 75 5F 25 2E 38 58 2E 25 2E 38 58 }
        $a2 = { 25 73 2C 20 25 75 20 25 73 20 25 75 20 25 2E 32 75 3A 25 2E 32 75 3A 25 2E 32 75 20 25 63 25 2E 32 75 25 2E 32 75 }
    condition:
        all of them
}

rule Windows_Generic_Threat_acf6222b {
    meta:
        author = "Elastic Security"
        id = "acf6222b-5859-4b18-a770-04f8fc7f48fd"
        fingerprint = "1046de07f9594a6352a33d892da1b4dc227fdf52a8caf38e8f1532076232c7fc"
        creation_date = "2024-01-03"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ce0def96be08193ab96817ce1279e8406746a76cfcf4bf44e394920d7acbcaa6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 7D 10 00 75 04 33 C0 5D C3 8B 4D 08 8B 55 0C FF 4D 10 74 0E 8A 01 84 C0 74 08 3A 02 75 04 41 42 EB ED 0F B6 01 0F B6 0A 2B C1 5D C3 55 8B EC 83 EC 24 56 57 8B 7D 08 33 F6 89 75 F8 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5e718a0c {
    meta:
        author = "Elastic Security"
        id = "5e718a0c-3c46-46f7-adfd-b0c3c75b865f"
        fingerprint = "b6f9b85f4438c3097b430495dee6ceef1a88bd5cece823656d9dd325e8d9d4a1"
        creation_date = "2024-01-03"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "430b9369b779208bd3976bd2adc3e63d3f71e5edfea30490e6e93040c1b3bac6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 44 3A 28 41 3B 3B 30 78 30 30 31 46 30 30 30 33 3B 3B 3B 42 41 29 28 41 3B 3B 30 78 30 30 31 30 30 30 30 33 3B 3B 3B 41 55 29 }
    condition:
        all of them
}

rule Windows_Generic_Threat_fac6d993 {
    meta:
        author = "Elastic Security"
        id = "fac6d993-a9c5-4218-829d-d0f3a3b9a5a0"
        fingerprint = "7502d32cf94496b73e476c7521b84a40426676b335a86bdf1bce7146934efcee"
        creation_date = "2024-01-03"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f3e7c88e72cf0c1f4cbee588972fc1434065f7cc9bd95d52379bade1b8520278"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E4 F8 81 EC 4C 04 00 00 53 8B D9 8B 4D 2C 33 C0 89 01 8B 4D 30 56 0F B6 B3 85 00 00 00 89 01 8B 4D 34 57 0F B6 BB 84 00 00 00 89 01 8B 4D 38 89 54 24 10 89 01 8D 44 24 48 50 FF 15 }
    condition:
        all of them
}

rule Windows_Generic_Threat_e7eaa4ca {
    meta:
        author = "Elastic Security"
        id = "e7eaa4ca-45ee-42ea-9604-d9d569eed0aa"
        fingerprint = "ede23e801a67bc43178eea87a83eb0ef32a74d48476a8273a25a7732af6f22a6"
        creation_date = "2024-01-04"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { C8 F7 C6 A8 13 F7 01 E9 2C 99 08 00 4C 03 D1 E9 }
    condition:
        all of them
}

rule Windows_Generic_Threat_97703189 {
    meta:
        author = "Elastic Security"
        id = "97703189-bcac-4b6c-b0d4-9167f5e8085d"
        fingerprint = "9126c3aeaa4ed136424c20aa8e7a487131adc1ae22eb8ab4f514b4687855816f"
        creation_date = "2024-01-04"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "968ba3112c54f3437b9abb6137f633d919d75137d790af074df40a346891cfb5"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 5D E9 2A 1C 00 00 8B FF 55 8B EC 8B 45 08 56 8B F1 C6 46 0C 00 85 C0 75 63 E8 6F 29 00 00 89 46 08 8B 48 6C 89 0E 8B 48 68 89 4E 04 8B 0E 3B 0D 98 06 49 00 74 12 8B 0D B4 05 49 00 85 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ca0686e1 {
    meta:
        author = "Elastic Security"
        id = "ca0686e1-001f-44d2-ae2f-51c473769723"
        fingerprint = "4663eefedb6f3f502adfb4f64278d1c535ba3a719d007a280e9943914121cd81"
        creation_date = "2024-01-05"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "15c7ce1bc55549efc86dea74a90f42fb4665fe15b14f760037897c772159a5b5"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 8B 5D 08 56 57 8B F9 8B 77 10 8B C6 2B C3 89 75 FC 3B 45 0C 72 03 8B 45 0C 83 7F 14 10 72 02 8B 0F 8D 14 19 2B F0 8B CE 03 C2 2B CB 41 51 50 52 E8 62 1A 00 00 83 C4 0C 8B CF 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_97c1a260 {
    meta:
        author = "Elastic Security"
        id = "97c1a260-9b43-458e-a9ac-2391aee1bcb8"
        fingerprint = "9cd93a8def2d2fac61a5b37d82b97c18ce8bf3410aa6ec7531ec28378f5c98cc"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2cc85ebb1ef07948b1ddf1a793809b76ee61d78c07b8bf6e702c9b17346a20f1"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 56 57 E8 14 31 00 00 8B F0 85 F6 0F 84 39 01 00 00 8B 16 33 DB 8B CA 8D 82 90 00 00 00 3B D0 74 0E 8B 7D 08 39 39 74 09 83 C1 0C 3B C8 75 F5 8B CB 85 C9 0F 84 11 01 00 00 8B 79 }
    condition:
        all of them
}

rule Windows_Generic_Threat_a440f624 {
    meta:
        author = "Elastic Security"
        id = "a440f624-c7ec-4f26-bfb5-982bae5f6887"
        fingerprint = "0f538f8f4eb2e71fb74d8305a179fc2ad880ab5a4cfd37bd35b5da2629ed892c"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3564fec3d47dfafc7e9c662654865aed74aedeac7371af8a77e573ea92cbd072"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 73 6B 20 3D 20 25 64 }
        $a2 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 4C 65 6E 20 3D 20 25 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b577c086 {
    meta:
        author = "Elastic Security"
        id = "b577c086-37bd-4227-8cde-f15e2ce0d0ae"
        fingerprint = "0de3cab973de067f2c10252bf761ced353de57c03c4b2e95db05ee3ca30259ea"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "27dd61d4d9997738e63e813f8b8ea9d5cf1291eb02d20d1a2ad75ac8aa99459c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 EC 24 83 7D 08 00 75 0A B8 9A FF FF FF E9 65 02 00 00 8B 45 08 89 45 FC 8B 4D FC 83 79 18 00 75 0A B8 9A FF FF FF E9 4C 02 00 00 8B 55 FC 83 7A 7C 00 74 0C 8B 45 08 50 E8 5F 06 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_62e1f5fc {
    meta:
        author = "Elastic Security"
        id = "62e1f5fc-325b-46e0-8c03-1a73e873ab16"
        fingerprint = "64839df90109a0c706c0a3626ba6c4c2eaa5dcd564f0e9889ab9ad4f12e150fe"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "4a692e244a389af0339de8c2d429b541d6d763afb0a2b1bb20bee879330f2f42"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 43 6C 69 65 6E 74 2E 48 61 6E 64 6C 65 5F 50 61 63 6B 65 74 }
        $a2 = { 67 65 74 5F 73 45 78 70 59 65 61 72 }
        $a3 = { 73 65 74 5F 73 45 78 70 59 65 61 72 }
    condition:
        all of them
}

rule Windows_Generic_Threat_55d6a1ab {
    meta:
        author = "Elastic Security"
        id = "55d6a1ab-2041-44a5-ae0e-23671fa2b001"
        fingerprint = "cd81b61929b18d59630814718443c4b158f9dcc89c7d03a46a531ffc5843f585"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1ca6ed610479b5aaaf193a2afed8f2ca1e32c0c5550a195d88f689caab60c6fb"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 51 51 31 33 37 32 33 39 32 34 38 20 }
        $a2 = { 74 65 6E 63 65 6E 74 3A 2F 2F 6D 65 73 73 61 67 65 2F 3F 75 69 6E 3D 31 33 37 32 33 39 32 34 38 26 53 69 74 65 3D 63 66 }
    condition:
        all of them
}

rule Windows_Generic_Threat_f7d3cdfd {
    meta:
        author = "Elastic Security"
        id = "f7d3cdfd-72eb-4298-b3ff-432f5c4347c9"
        fingerprint = "db703a2ddcec989a81b99a67e61f4be34a2b0e55285c2bdec91cd2f7fc7e52f3"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f9df83d0b0e06884cdb4a02cd2091ee1fadeabb2ea16ca34cbfef4129ede251f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 51 56 57 E8 A3 D0 FF FF 83 78 68 00 74 21 FF 75 24 FF 75 20 FF 75 18 FF 75 14 FF 75 10 FF 75 0C FF 75 08 E8 E5 8C FF FF 83 C4 1C 85 C0 75 73 8B 7D 1C 8D 45 F8 50 8D 45 FC 50 57 FF }
    condition:
        all of them
}

rule Windows_Generic_Threat_0350ed31 {
    meta:
        author = "Elastic Security"
        id = "0350ed31-ed07-4e9a-8488-3765c990f25c"
        fingerprint = "aac41abf60a16c02c6250c0468c6f707f9771b48da9e78633de7141d09ca23c8"
        creation_date = "2024-01-07"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "008f9352765d1b3360726363e3e179b527a566bc59acecea06bd16eb16b66c5d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 35 6A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 3F }
    condition:
        all of them
}

rule Windows_Generic_Threat_a1cef0cd {
    meta:
        author = "Elastic Security"
        id = "a1cef0cd-a811-4d7b-b24e-7935c0418c7a"
        fingerprint = "9285f0ea8ed0ceded2f3876ef197b67e8087f7de82a72e0cd9899b05015eee79"
        creation_date = "2024-01-08"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "71f519c6bd598e17e1298d247a4ad37b78685ca6fd423d560d397d34d16b7db8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 53 8B DA 89 45 FC 8B 45 FC E8 76 00 00 00 33 C0 55 68 F0 A0 41 00 64 FF 30 64 89 20 8B 45 FC 80 78 20 01 74 10 8B 45 FC 8B 40 04 8B D3 E8 CE FC FF FF 40 75 0F 8B 45 FC 8B 40 04 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_e5f4703f {
    meta:
        author = "Elastic Security"
        id = "e5f4703f-e834-4904-9036-a8c5996058c8"
        fingerprint = "3072ea028b0716e88820782a2658d1f424d57bd988ccfcc1581991649cf52b19"
        creation_date = "2024-01-09"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "362bda1fad3fefce7d173617909d3c1a0a8e234e22caf3215ee7c6cef6b2743b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 E4 F8 83 EC 08 83 79 14 08 56 57 8B F1 72 02 8B 31 8B 41 10 8B CE 8D 3C 46 8B D7 E8 AC FA FF FF 8B 75 08 2B F8 D1 FF 0F 57 C0 57 50 0F 11 06 8B CE C7 46 10 00 00 00 00 C7 46 14 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_8b790aba {
    meta:
        author = "Elastic Security"
        id = "8b790aba-02b4-4c71-a51e-3a56ea5728ec"
        fingerprint = "8581397f15b9985bafa5248f0e7f044bf80c82e441d2216dc0976c806f658d2e"
        creation_date = "2024-01-09"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ec98bfff01d384bdff6bbbc5e17620b31fa57c662516157fd476ef587b8d239e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 7A 66 62 50 4A 64 73 72 78 77 7B 7B 79 55 36 46 42 50 4A 3F 20 2E 6E 3E 36 65 73 7A }
        $a2 = { 50 36 7B 77 64 71 79 64 46 4A 73 64 79 62 45 7A 77 63 62 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_76a7579f {
    meta:
        author = "Elastic Security"
        id = "76a7579f-4a9b-4dae-935c-14d829d3c416"
        fingerprint = "ba5bfc0e012a22172f138c498560a606e6754efa0fa145799f00725e130ad90f"
        creation_date = "2024-01-09"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "76c73934bcff7e4ee08b068d1e02b8f5c22161262d127de2b4ac2e81d09d84f6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 8B 55 10 8B 45 08 8B C8 85 D2 74 09 C6 01 00 41 83 EA 01 75 F7 5D C3 55 8B EC 64 A1 30 00 00 00 83 EC 18 8B 40 0C 53 56 57 8B 78 0C E9 A7 00 00 00 8B 47 30 33 F6 8B 5F 2C 8B 3F 89 45 }
    condition:
        all of them
}

rule Windows_Generic_Threat_3f060b9c {
    meta:
        author = "Elastic Security"
        id = "3f060b9c-8c35-4f0f-9dfd-10be6355bea9"
        fingerprint = "5bc1d19faa8fc07ef669f6f63baceee5fe452c0e2d54d6154bcc01e11606ae6f"
        creation_date = "2024-01-10"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "32e7a40b13ddbf9fc73bd12c234336b1ae11e2f39476de99ebacd7bbfd22fba0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 51 51 53 56 8B F1 E8 4B BE FF FF 8D 45 FC 8B CE 50 FF 75 10 FF 75 0C E8 69 FE FF FF 8B D8 8B CE 53 E8 4B FD FF FF 85 C0 0F 84 C6 00 00 00 8B 46 40 83 F8 02 0F 84 B3 00 00 00 83 F8 05 }
    condition:
        all of them
}

rule Windows_Generic_Threat_dbae6542 {
    meta:
        author = "Elastic Security"
        id = "dbae6542-b343-4320-884c-c0ce97a431f1"
        fingerprint = "880aafd423494eccab31342bdfec392fdf4a7b4d98614a0c3b5302d62bcf5ba8"
        creation_date = "2024-01-10"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c73f533f96ed894b9ff717da195083a594673e218ee9a269e360353b9c9a0283"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 20 B8 0B 00 00 20 10 27 00 00 6F 29 00 00 0A 28 1F 00 00 0A 7E 0F 00 00 04 2D 0A 28 27 00 00 06 28 19 00 00 06 7E 15 00 00 04 6F 2A 00 00 0A 26 17 2D C8 2A EE 16 80 0F 00 00 04 14 }
    condition:
        all of them
}

rule Windows_Generic_Threat_808f680e {
    meta:
        author = "Elastic Security"
        id = "808f680e-db35-488f-b942-79213890b336"
        fingerprint = "4b4b3b244d0168b11a8df4805f9043c6e4039ced332a7ba9c9d0d962ad6f6a0e"
        creation_date = "2024-01-10"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "df6955522532e365239b94e9d834ff5eeeb354eec3e3672c48be88725849ac1c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 20 00 00 00 00 FE 01 2A 13 30 02 00 6C 00 00 00 01 00 00 11 20 00 00 00 00 FE 0E 00 00 38 54 00 00 00 00 FE 0C 00 00 20 01 00 00 00 FE 01 39 12 00 00 00 FE 09 01 00 FE 09 02 00 51 }
    condition:
        all of them
}

rule Windows_Generic_Threat_073909cf {
    meta:
        author = "Elastic Security"
        id = "073909cf-7e0d-48fa-a631-e1b641040570"
        fingerprint = "717da3b409c002ff6c6428690faf6e6018daedfaf9ec95b6fb9884cacc27dc20"
        creation_date = "2024-01-10"
        last_modified = "2024-01-12"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "89a6dc518c119b39252889632bd18d9dfdae687f7621310fb14b684d2f85dad8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 F0 53 56 89 55 FC 8B F0 8B 45 FC E8 CF E5 FF FF 33 C0 55 68 F2 39 40 00 64 FF 30 64 89 20 33 DB 68 04 3A 40 00 68 0C 3A 40 00 E8 70 FC FF FF 50 E8 82 FC FF FF 89 45 F8 68 18 3A }
    condition:
        all of them
}

