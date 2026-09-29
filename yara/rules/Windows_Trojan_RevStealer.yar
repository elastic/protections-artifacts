rule Windows_Trojan_RevStealer_efc8ff20 {
    meta:
        author = "Elastic Security"
        id = "efc8ff20-a7b8-4a16-95c1-ca8f0c5fc8e9"
        fingerprint = "5b402c9497e33d0f6fa40daa889d07fe2c51752a4c6e70d0b904ce54490c1063"
        creation_date = "2026-08-21"
        last_modified = "2026-09-01"
        threat_name = "Windows.Trojan.RevStealer"
        reference_sample = "127f135246aa0246a8b4d0415538aacdf27f509ff75756556ce18999326f1048"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_str_decrypt = { 48 FF C0 48 89 44 24 ?? ?? ?? FF FF FF 33 C0 48 8B 4C 24 30 48 8B 54 24 38 66 89 44 51 FE 48 83 C4 28 C3 }
        $seq_cred_mgr = { 44 8A 1C 11 41 8D 43 E0 3C 5E 77 }
        $seq_cred_mgr_2 = { 46 8A 1C 01 41 8D 43 E0 3C 5E 77 }
        $seq_parse_module_name = { 48 8B C2 48 2B C1 48 3D FF 00 00 00 7D ?? 0F B6 02 4? ?? ?? ?? ?? ?? 66 41 89 00 }
        $seq_parse_c2 = { 80 FA 39 77 ?? 41 8B 04 24 ?? ?? ?? 8D 0C 80 0F B6 C2 8D 04 48 83 C0 ?? 41 89 04 24 8A 17 80 FA }
        $seq_veh = { 41 B8 A0 00 00 00 4D 8D 0C 12 48 2B CA 4D 2B C2 42 8A 04 09 41 88 01 49 FF C1 49 83 E8 01 }
    condition:
        3 of ($seq*)
}

rule Windows_Trojan_RevStealer_0640dc83 {
    meta:
        author = "Elastic Security"
        id = "0640dc83-c415-44ee-8497-c454141a823d"
        fingerprint = "070d18894ff398d117e530087ba0b057c2d1f7b5c15a4eb2b142d61bc1a374c9"
        creation_date = "2026-08-28"
        last_modified = "2026-09-01"
        description = "Identifies ProManager module"
        threat_name = "Windows.Trojan.RevStealer"
        reference_sample = "13d7237d7289e67c2d806a65d52580b453ce4987acbe2c4c4d04833f55ebccfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 8B 04 24 B9 8B 2F 00 00 0F B7 D0 0F AF D1 0F B7 4C 24 30 0F B7 C2 66 03 C8 66 89 4C 24 38 48 8B 04 24 41 0F B7 04 41 66 89 44 24 28 0F B7 4C 24 28 0F B7 44 24 28 C1 E9 05 66 C1 E0 0B 66 0B C1 }
        $b = { 48 8D 04 11 44 8B 58 1C 8B 58 24 4C 03 D9 8B 78 20 48 03 D9 48 03 F9 8B 48 18 }
    condition:
        any of them
}

rule Windows_Trojan_RevStealer_61539fdb {
    meta:
        author = "Elastic Security"
        id = "61539fdb-99cc-48ed-94b8-7f6efa7741bc"
        fingerprint = "ce1a4023b95794dc91eb184df87e2ff640f086accd5b7d7bc5ff965b4499a00d"
        creation_date = "2026-08-28"
        last_modified = "2026-09-01"
        description = "Identifies SoftManager module"
        threat_name = "Windows.Trojan.RevStealer"
        reference_sample = "14b2ac356ed75d10ef40bbaaa48e7dd9fff7de9719c2a43ad123fe843dd4e4e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { B9 F0 00 00 00 88 18 48 FF C0 48 83 E9 01 75 F5 48 8D 44 24 48 48 8B CD 88 18 48 FF C0 48 83 E9 01 }
        $b = { 40 88 30 48 FF C0 48 83 ED 01 75 ?? 49 8B CF 48 8B D7 }
    condition:
        any of them
}

rule Windows_Trojan_RevStealer_295fca7e {
    meta:
        author = "Elastic Security"
        id = "295fca7e-4478-4b27-916c-9c6659fe25ea"
        fingerprint = "cd6163fc572cfd89a15cc36d9147b534e2af83ab0fdc49e22479b1a4d84c843a"
        creation_date = "2026-08-28"
        last_modified = "2026-09-01"
        description = "Identifies WinUpdate module"
        threat_name = "Windows.Trojan.RevStealer"
        reference_sample = "7c08cf409194056a8517865e5d3433d1499bb8262263b55b49b8b07d9d182fcb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 49 8B D3 49 8B C8 49 2B D0 48 8B FB 8A 04 0A 88 01 48 FF C1 48 83 EF 01 }
        $b = { 41 0F B7 04 09 FF C2 66 89 01 49 FF C3 48 83 C1 02 4D 3B DA }
    condition:
        any of them
}

rule Windows_Trojan_RevStealer_bbf066be {
    meta:
        author = "Elastic Security"
        id = "bbf066be-39a7-4a2f-bc79-fab728c66052"
        fingerprint = "c7a6a9c9c9bf4881e214b9e3d86785b8ce66efd8fa78d1716c745226f55a05bb"
        creation_date = "2026-09-08"
        last_modified = "2026-09-25"
        description = "Identifies LockAppHost module"
        threat_name = "Windows.Trojan.RevStealer"
        reference_sample = "10d2e914f92729f8f12bf871a2e238aecd28e57dc8be60a2aa58f3aad464b675"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 41 FE C1 45 0F B6 C1 42 8A 14 04 44 02 D2 41 0F B6 CA 8A 04 0C 42 88 04 04 88 14 0C 49 83 EB 01 }
        $b = { 48 FF C0 48 89 44 24 ?? ?? ?? FF FF FF 33 C0 48 8B 4C 24 40 48 8B 54 24 48 66 89 44 51 FE 48 83 C4 38 C3 }
    condition:
        all of them
}

