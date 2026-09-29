rule Windows_VulnDriver_Xkpsm_60db27b6 {
    meta:
        author = "Elastic Security"
        id = "60db27b6-b4f9-457c-9c0a-164bbc70cd92"
        fingerprint = "3557be69f88f4f52a4e77cf3b15368c2c6615a1964fc08830811a6557f73856b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: JiranJikyosoft co., ltd., Version: <= 3.0.0.1"
        threat_name = "Windows.VulnDriver.Xkpsm"
        reference_sample = "28c5bb735f9fc38e0ebd366978898f0cfcd455e4ff8bf1a321768b09e01ee84d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 69 72 61 6E 4A 69 6B 79 6F 73 6F 66 74 20 63 6F 2E 2C 20 6C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 78 00 6B 00 70 00 73 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "xkpsm.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_Xkpsm_57f15dd2 {
    meta:
        author = "Elastic Security"
        id = "57f15dd2-9672-48b5-86df-02f86ec6a142"
        fingerprint = "8fa6dbfe206f83fb7f4ef9626cace25d2fb6b8201e8bc4094a4c2ea06196fab2"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Microsoft Windows, Version: <= 3.0.0.1"
        threat_name = "Windows.VulnDriver.Xkpsm"
        reference_sample = "b122b982ca271a4ff15c756b3ceb1c18facee2a9d5a34483b490746a124a935f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 78 00 6B 00 70 00 73 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "xkpsm.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

