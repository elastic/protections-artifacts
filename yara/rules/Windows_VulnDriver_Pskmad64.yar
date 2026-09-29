rule Windows_VulnDriver_Pskmad64_bd9fa565 {
    meta:
        author = "Elastic Security"
        id = "bd9fa565-e06d-44c4-834f-5075ccc98f80"
        fingerprint = "64d37374dfe12f6dd860b14b344981f1ec5319fe5a3aa303b49e10c847dceaa3"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Panda Security S.L., Version: <= 1.0.0.17"
        threat_name = "Windows.VulnDriver.Pskmad64"
        reference_sample = "7f9a397038732678c52a73e5e2238ab3619e3c1fcb2ce41efc8e5bd38d77f83e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 6E 64 61 20 53 65 63 75 72 69 74 79 20 53 2E 4C 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 53 00 4B 00 4D 00 41 00 44 00 5F 00 36 00 34 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x10][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x11-\x11][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "pskmad.pdb"
        $str2 = "Panda Technologies" wide
        $str3 = "Panda Kernel Memory Access Driver (x64)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

