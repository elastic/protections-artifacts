rule Windows_Trojan_WarmCookie_7d32fa90 {
    meta:
        author = "Elastic Security"
        id = "7d32fa90-c6e0-4a4b-bc21-51d82c57721e"
        fingerprint = "ae6c81fc7b0ba16567fefa714d043556afa44bfd698f6478c21d6e6428b14858"
        creation_date = "2024-04-29"
        last_modified = "2024-05-08"
        threat_name = "Windows.Trojan.WarmCookie"
        reference_sample = "ccde1ded028948f5cd3277d2d4af6b22fa33f53abde84ea2aa01f1872fad1d13"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_checksum = { 45 8D 5D ?? 45 33 C0 41 83 E3 ?? 49 8D 4E ?? 44 03 DB 41 8D 53 ?? }
        $seq_string_decrypt = { 8B 69 04 48 8D 79 08 8B 31 89 6C 24 ?? 48 8D 4E ?? E8 }
        $seq_filesearch = { 48 81 EC 58 02 00 00 48 8B 05 82 0A 02 00 48 33 C4 48 89 84 24 40 02 00 00 45 33 C9 48 8D 44 24 30 45 33 C0 48 89 44 24 20 33 C9 41 8D 51 1A FF 15 83 4D 01 00 85 C0 78 22 48 8D 4C 24 30 E8 1D }
        $seq_registry = { 48 81 EC 80 02 00 00 48 8B 05 F7 09 02 00 48 33 C4 48 89 84 24 70 02 00 00 4C 89 B4 24 98 02 00 00 48 8D 0D 4D CA 01 00 45 33 F6 41 8B FE E8 02 4F 00 00 48 8B E8 41 B9 08 01 00 00 48 8D 44 24 }
        $plain_str1 = "release.dll" ascii fullword
        $plain_str2 = "\"Main Invoked.\"" ascii fullword
        $plain_str3 = "\"Main Returned.\"" ascii fullword
        $decrypt_str1 = "ERROR: Cannot write file" wide fullword
        $decrypt_str2 = "OK (No output data)" wide fullword
        $decrypt_str3 = "OK (See 'Files' tab)" wide fullword
        $decrypt_str4 = "cmd.exe /c %ls" wide fullword
        $decrypt_str5 = "Cookie:" wide fullword
        $decrypt_str6 = "%ls\\*.*" wide fullword
    condition:
        (3 of ($plain*)) or (2 of ($seq*)) or 4 of ($decrypt*)
}

