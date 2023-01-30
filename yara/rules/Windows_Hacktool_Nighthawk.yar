rule Windows_Hacktool_Nighthawk_9f3a5abb {
    meta:
        author = "Elastic Security"
        id = "9f3a5abb-b329-44db-af71-d72eae2737ac"
        fingerprint = "ba21edf160113951444dacf7549f288a41ec0bae64064431e8defd8e34f173db"
        creation_date = "2022-11-24"
        last_modified = "2023-01-11"
        threat_name = "Windows.Hacktool.Nighthawk"
        reference_sample = "b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $loader_build_iat0 = { B9 BF BF D1 D5 E8 ?? ?? ?? ?? BA 7C 75 84 91 [3-12] E8 ?? ?? ?? ?? BA 47 FB EB 2B [3-12] E8 ?? ?? ?? ?? BA 42 24 3D 39 [3-12] E8 ?? ?? ?? ?? BA E7 E9 EF EE [3-12] E8 ?? ?? ?? ?? BA 47 FD 36 2E [3-12] E8 ?? ?? ?? ?? BA 39 DE 19 3D [3-12] E8 ?? ?? ?? ?? BA 20 DF DB F7 [3-12] E8 ?? ?? ?? ?? BA 45 34 2A 41 [3-12] E8 ?? ?? ?? ?? BA 7D 1C 44 2E [3-12] E8 ?? ?? ?? ?? BA 7D 28 44 2E [3-12] E8 ?? ?? ?? ?? BA 94 36 65 8D [3-12] E8 ?? ?? ?? ?? }
        $loader_syscall_func = { 65 48 8B 04 25 30 00 00 00 48 8B 80 10 01 00 00 48 89 44 24 F0 65 48 8B 04 25 30 00 00 00 8B 40 68 49 89 CA FF 64 24 F0 }
    condition:
        $loader_build_iat0 and $loader_syscall_func
}

rule Windows_Hacktool_Nighthawk_2a2e3b9d {
    meta:
        author = "Elastic Security"
        id = "2a2e3b9d-e85f-43b6-9754-1aa7c9f6f978"
        fingerprint = "40912e8d6bd09754046598b1311080e0ec6e040cb1b9ca93003c6314725d4d45"
        creation_date = "2022-11-24"
        last_modified = "2023-01-11"
        threat_name = "Windows.Hacktool.Nighthawk"
        reference_sample = "38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $payload_bytes1 = { 66 C1 E0 05 66 33 D0 66 C1 E2 0A 66 0B D1 0F B7 D2 8B CA 0F B7 C2 C1 E9 02 33 CA 66 D1 E8 D1 E9 33 CA C1 E9 02 33 CA C1 E2 0F 83 E1 01 }
        $payload_bytes2 = { 48 8B D9 44 8B C2 41 C1 E0 0F 8B C2 F7 D0 48 8B F2 44 03 C0 41 8B C0 C1 E8 0C 41 33 C0 8D 04 80 8B C8 C1 E9 04 33 C8 44 69 C1 09 08 00 00 41 8B C0 C1 E8 10 44 33 C0 B8 85 1C A7 AA }
    condition:
        any of them
}

