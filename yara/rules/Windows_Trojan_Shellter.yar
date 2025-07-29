rule Windows_Trojan_Shellter_89e693fc {
    meta:
        author = "Elastic Security"
        id = "89e693fc-cdfd-48ac-8583-0754e716bb9f"
        fingerprint = "2ba7f2d4d580433d8ba9817047b92757a22fb930bf94cb14e7bb9f936d7bb87f"
        creation_date = "2025-06-30"
        last_modified = "2025-07-23"
        threat_name = "Windows.Trojan.Shellter"
        reference_sample = "c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_api_hashing = { 48 8B 44 24 ?? 0F BE 00 85 C0 74 ?? 48 8B 44 24 ?? 0F BE 00 89 44 24 ?? 48 8B 44 24 ?? 48 FF C0 48 89 44 24 ?? 8B 04 24 C1 E8 ?? 8B 0C 24 C1 E1 ?? 0B C1 }
        $seq_debug = { 48 8B 49 30 8B 49 70 8B 40 74 0B C1 25 70 00 00 40 85 C0 75 22 B8 D4 02 00 00 48 05 00 00 FE 7F }
        $seq_mem_marker = { 44 89 44 24 ?? 89 54 24 ?? 48 89 4C 24 ?? 33 C0 83 F8 ?? 74 ?? 48 8B 44 24 ?? 8B 4C 24 ?? 39 08 75 ?? EB ?? 48 63 44 24 ?? 48 8B 4C 24 }
        $seq_check_jmp_rcx = { 48 89 4C 24 ?? B8 01 00 00 00 48 6B C0 00 48 8B 4C 24 ?? 0F B6 04 01 3D FF 00 00 00 75 ?? B8 01 00 00 00 48 6B C0 01 48 8B 4C 24 ?? 0F B6 04 01 3D E1 00 00 00 75 ?? B8 01 00 00 00 }
        $seq_syscall_stub = { C6 84 24 98 00 00 00 4C C6 84 24 99 00 00 00 8B C6 84 24 9A 00 00 00 D1 C6 84 24 9B 00 00 00 B8 C6 84 24 9C 00 00 00 00 C6 84 24 9D 00 00 00 00 C6 84 24 9E 00 00 00 00 }
        $seq_mem_xor = { 48 8B 4C 24 ?? 0F B6 04 01 0F B6 4C 24 ?? 3B C1 74 ?? 8B 44 24 ?? 0F B6 4C 24 ?? 48 8B 54 24 ?? 0F B6 04 02 33 C1 8B 4C 24 ?? 48 8B 54 24 ?? 88 04 0A }
        $seq_excep_handler = { 48 89 4C 24 08 48 83 EC 18 48 B8 E8 E7 E6 E5 E4 E3 E2 E1 48 89 04 24 48 8B 44 24 20 48 8B 00 81 38 05 00 00 C0 }
    condition:
        3 of them
}

