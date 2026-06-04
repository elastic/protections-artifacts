rule Linux_Rootkit_Flipswitch_821f3c9e {
    meta:
        author = "Elastic Security"
        id = "821f3c9e-ffce-4df1-903c-4ad898009388"
        fingerprint = "40c10edaeed31be37f5b90e7838926174fbb9970fd809fe1ad80210cea338ce6"
        creation_date = "2025-09-05"
        last_modified = "2026-05-22"
        description = "Yara rule to detect the FlipSwitch rootkit PoC"
        threat_name = "Linux.Rootkit.Flipswitch"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $all_a = { FF FF 48 89 45 E8 F0 80 [3] 31 C0 48 89 45 F0 48 8B 45 E8 0F 22 C0 }
        $all_b = { FF FF 48 89 04 24 F0 80 [3] 31 C0 48 89 44 24 08 48 8B 04 24 0F 22 C0 }
        $obf_b_1 = { BA AA 00 00 00 BE 0D 00 00 00 48 C7 [5] 49 89 C4 E8 }
        $obf_b_2 = { BA AA 00 00 00 BE 0D 00 00 00 48 C7 [5] 48 89 C5 E8 [4] 48 89 C7 E8 [4] 48 85 ED 74 32 }
        $obf_c = { BA AA 00 00 00 BE 15 00 00 00 48 89 C3 E8 [4] 48 89 DF 48 89 43 30 E8 [4] 85 C0 74 0D 48 89 DF E8 }
        $main_b = { 41 54 53 E8 [4] 48 C7 C7 [4] 49 89 C4 E8 [4] 4D 85 E4 74 2D 48 89 C3 48 85 }
        $main_c = { 48 85 C0 74 1F 48 C7 [6] 48 89 C7 48 89 C3 E8 [4] 85 C0 74 0D 48 89 DF E8 [4] 45 31 E4 EB 14 }
        $main_d = { 48 85 ED 74 32 48 89 C3 48 85 C0 74 2A E8 [4] 48 89 C7 48 85 C0 74 1D 31 C0 48 89 47 08 48 89 47 10 48 89 47 18 48 89 47 20 }
        $debug_b = { 48 89 E5 41 54 53 48 85 C0 0F 84 ?? ?? 00 00 48 C7 }
        $debug_c = { 48 85 C0 74 45 48 C7 [6] 48 89 C7 48 89 C3 E8 [4] 85 C0 75 26 48 89 DF 4C 8B 63 28 E8 [4] 48 89 DF E8 }
        $debug_d = { 55 53 48 85 C0 0F 84 [4] 48 C7 C7 00 00 00 00 E8 [4] 48 89 C3 48 [4] 00 00 48 85 C0 }
    condition:
        (#all_a >= 2 or #all_b >= 2) and (1 of ($obf_*) or 1 of ($main_*) or 1 of ($debug_*))
}

