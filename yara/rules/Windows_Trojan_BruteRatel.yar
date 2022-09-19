rule Windows_Trojan_BruteRatel_1916686d {
    meta:
        author = "Elastic Security"
        id = "1916686d-4821-4e5a-8290-58336d01997f"
        fingerprint = "a9924347d324c3455d4e50cbbae940c5af36b41bcd2d9f28dd6b3af6d6489484"
        creation_date = "2022-06-23"
        last_modified = "2022-07-18"
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

