rule Windows_Trojan_BruteRatel_1916686d {
    meta:
        author = "Elastic Security"
        id = "1916686d-4821-4e5a-8290-58336d01997f"
        fingerprint = "86304082d3eda2f160465f0af0a3feae1aa9695727520e51f139d951e50d6efc"
        creation_date = "2022-06-23"
        last_modified = "2022-12-01"
        threat_name = "Windows.Trojan.BruteRatel"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[+] Spoofed PPID => %lu" wide fullword
        $a2 = "[-] Child process not set" wide fullword
        $a3 = "[+] Crisis Monitor: Already Running" wide fullword
        $a4 = "[+] Screenshot downloaded: %S" wide fullword
        $a5 = "s[-] Duplicate listener: %S" wide fullword
        $a6 = "%02d%02d%d_%02d%02d%2d%02d.png" wide fullword
        $a7 = "[+] Added Socks Profile" wide fullword
        $a8 = "[+] Dump Size: %d Mb" wide fullword
        $a9 = "[+] Enumerating PID: %lu [%ls]" wide fullword
        $a10 = "[+] Dump Size: %d Mb" wide fullword
        $a11 = "[+] SAM key: " wide fullword
        $a12 = "[+] Token removed: '%ls'" wide fullword
        $a13 = "[Tasks] %02d => 0x%02X 0x%02X" wide fullword
        $b1 = { 48 83 EC ?? 48 8D 35 ?? ?? ?? ?? 4C 63 E2 31 D2 48 8D 7C 24 ?? 48 89 CB 4D 89 E0 4C 89 E5 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 31 F6 BF ?? ?? ?? ?? 39 F5 7E ?? E8 ?? ?? ?? ?? 99 F7 FF 48 63 D2 8A 44 14 ?? 88 04 33 48 FF C6 EB ?? }
    condition:
        4 of ($a*) or 1 of ($b*)
}

rule Windows_Trojan_BruteRatel_9b267f96 {
    meta:
        author = "Elastic Security"
        id = "9b267f96-11b3-48e6-9d38-ecfd72cb7e3e"
        fingerprint = "f20cbaf39dc68460a2612298a5df9efdf5bdb152159d38f4696aedf35862bbb6"
        creation_date = "2022-06-23"
        last_modified = "2022-07-18"
        threat_name = "Windows.Trojan.BruteRatel"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "calAllocPH" ascii fullword
        $a2 = "lizeCritPH" ascii fullword
        $a3 = "BadgerPH" ascii fullword
        $a4 = "VirtualPPH" ascii fullword
        $a5 = "TerminatPH" ascii fullword
        $a6 = "ickCountPH" ascii fullword
        $a7 = "SeDebugPH" ascii fullword
        $b1 = { 50 48 B8 E2 6A 15 64 56 22 0D 7E 50 48 B8 18 2C 05 7F BB 78 D7 27 50 48 B8 C9 EC BC 3D 84 54 9A 62 50 48 B8 A1 E1 3C 4E AF 2B F6 B1 50 48 B8 2E E6 7B A0 94 CA 9D F0 50 48 B8 61 52 80 AA 1A B6 4B 0E 50 48 B8 B2 13 11 5A 28 81 ED 60 50 48 B8 20 DE A9 34 89 08 C8 32 50 48 B8 9B DC C1 FF 79 CE 5B F5 50 48 B8 FD 57 3F 4C C7 D3 7A 21 50 48 B8 70 B8 63 0F AB 19 BF 1C 50 48 B8 48 F2 1B 72 1E 2A C6 8A 50 48 B8 E3 FA 38 E9 1D 76 E0 6F 50 48 B8 97 AD 75 }
    condition:
        3 of ($a*) or 1 of ($b*)
}

rule Windows_Trojan_BruteRatel_684a39f2 {
    meta:
        author = "Elastic Security"
        id = "684a39f2-a110-4553-8d29-9f742e0ca3dc"
        fingerprint = "fef288db141810b01f248a476368946c478a395b1709a982e2f740dd011c6328"
        creation_date = "2023-01-24"
        last_modified = "2023-02-01"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "5f4782a34368bb661f413f33e2d1fb9f237b7f9637f2c0c21dc752316b02350c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { 39 DA 0F 82 61 02 00 00 45 8D 48 14 44 39 CA 0F 82 54 02 00 00 41 8D 40 07 46 0F B6 0C 09 44 0F B6 1C 01 42 0F B6 04 11 41 C1 E3 08 41 09 C3 }
        $seq2 = { 45 8A 44 13 F0 44 32 04 01 48 FF C0 45 88 04 13 48 FF C2 48 83 F8 04 75 E7 49 83 C2 04 48 83 C6 04 49 81 FA B0 00 00 00 75 AA 48 83 C4 38 5B 5E C3 }
        $seq3 = { 48 83 EC 18 8A 01 88 04 24 8A 41 05 88 44 24 01 8A 41 0A 88 44 24 02 8A 41 0F 88 44 24 03 8A 41 04 88 44 24 04 8A 41 09 88 44 24 05 8A 41 0E 88 44 24 06 8A 41 03 88 44 24 07 }
        $seq4 = { 42 8A 0C 22 8D 42 ?? 80 F9 ?? 75 ?? 48 98 4C 89 E9 48 29 C1 42 8A 14 20 80 FA ?? 74 ?? 88 14 01 48 FF C0 EB ?? }
        $cfg1 = { 22 00 2C 00 22 00 61 00 72 00 63 00 68 00 22 00 3A 00 22 00 78 00 36 00 34 00 22 00 2C 00 22 00 62 00 6C 00 64 00 22 00 3A 00 22 00 }
        $cfg2 = { 22 00 2C 00 22 00 77 00 76 00 65 00 72 00 22 00 3A 00 22 00 }
        $cfg3 = { 22 00 2C 00 22 00 70 00 69 00 64 00 22 00 3A 00 22 00 }
        $cfg4 = { 22 00 7D 00 2C 00 22 00 6D 00 74 00 64 00 74 00 22 00 3A 00 7B 00 22 00 68 00 5F 00 6E 00 61 00 6D 00 65 00 22 00 3A 00 22 00 }
    condition:
        any of ($seq*) and all of ($cfg*)
}

rule Windows_Trojan_BruteRatel_ade6c9d5 {
    meta:
        author = "Elastic Security"
        id = "ade6c9d5-e9b5-4ef8-bacd-2f050c25f7f6"
        fingerprint = "9a4c5660eeb9158652561cf120e91ea5887841ed71f69e7cf4bfe4cfb11fe74a"
        creation_date = "2023-01-24"
        last_modified = "2023-02-01"
        description = "Targets API hashes used by BruteRatel"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "dc9757c9aa3aff76d86f9f23a3d20a817e48ca3d7294307cc67477177af5c0d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c1_NtReadVirtualMemory = { AA A5 EF 3A }
        $c2_NtQuerySystemInformation = { D6 CA E1 E4 }
        $c3_NtCreateFile = { 9D 8F 88 03 }
        $c4_RtlSetCurrentTranscation = { 90 85 A3 99 }
        $c5_LoadLibrary = { 8E 4E 0E EC }
    condition:
        all of them
}

