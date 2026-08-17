rule Windows_VulnDriver_BattlEye_8378b1d6 {
    meta:
        author = "Elastic Security"
        id = "8378b1d6-4085-4fd4-91ff-f7ac95c2d958"
        fingerprint = "b24caa3d6e7d367f35d628c5bf1fbeea8a8e8bac6b9289dae60eb63b51530c18"
        creation_date = "2026-07-25"
        last_modified = "2026-08-11"
        description = "Subject: BattlEye Innovations e.K."
        threat_name = "Windows.VulnDriver.BattlEye"
        reference_sample = "2b120de80a5462f8395cfb7153c86dfd44f29f0776ea156ec4a34fa64e5c4797"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 61 74 74 6C 45 79 65 20 49 6E 6E 6F 76 61 74 69 6F 6E 73 20 65 2E 4B 2E }
        $serial = { 06 03 23 C3 20 4D F4 50 1E A1 5B 73 39 0D D8 56 }
        $seq1 = { 44 89 0C 24 41 81 F9 90 65 00 00 7D 1B 33 C9 0F 01 D0 48 C1 E2 20 48 0B D0 48 8B C2 48 C1 EA 20 0F 01 D1 41 FF C1 EB D8 49 8B 0A 49 2B C8 48 B8 0B D7 A3 70 3D 0A D7 A3 48 F7 E9 48 03 D1 48 C1 FA 06 48 8B C2 48 C1 E8 3F 48 03 C2 EB 02 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $serial and $seq1
}

