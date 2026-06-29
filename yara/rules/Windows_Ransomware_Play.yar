rule Windows_Ransomware_Play_dd5e294a {
    meta:
        author = "Elastic Security"
        id = "dd5e294a-6bdf-4d77-a7f4-053a31a58371"
        fingerprint = "7a2c6c09de0f01e0b8788a81e6df76f4badd3f21e665aaea6ec50d11dd3b3fe8"
        creation_date = "2026-05-06"
        last_modified = "2026-06-26"
        threat_name = "Windows.Ransomware.Play"
        reference_sample = "ed7aa56a0e6c6c599b902634c518f513fe95c4b7c2c9d7b1d048336b991231d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 99 03 85 28 FF FF FF BA 02 00 00 00 D1 E2 66 89 44 15 DC B8 02 00 00 00 6B C8 00 0F B7 54 0D 88 B8 01 00 00 00 C1 E0 00 }
        $a2 = { 8B 8D 10 FF FF FF 2B C8 8B 85 14 FF FF FF 1B C2 89 8D 10 FF FF FF 89 85 14 FF FF FF B9 01 00 00 00 D1 E1 }
        $a3 = { C7 85 0C FF FF FF 00 00 00 00 C7 85 38 FF FF FF 01 00 00 00 C7 85 40 FF FF FF 01 00 00 00 C7 85 44 FF FF FF 4A 09 }
        $a4 = ".PLAY" wide fullword
    condition:
        2 of them
}

