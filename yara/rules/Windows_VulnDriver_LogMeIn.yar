rule Windows_VulnDriver_LogMeIn_8fe0a521 {
    meta:
        author = "Elastic Security"
        id = "8fe0a521-fb21-4489-ae00-9a4453f15e50"
        fingerprint = "3a70937b2f0b56e7d24b7c02056185fa35190c210e65c665cbbda7977e8a905b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: LogMeIn, Inc., Version: <= 11.1.0.3220"
        threat_name = "Windows.VulnDriver.LogMeIn"
        reference_sample = "453be8f63cc6b116e2049659e081d896491cf1a426e3d5f029f98146a3f44233"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 6F 67 4D 65 49 6E 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 4D 00 49 00 69 00 6E 00 66 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x0b-\x0b][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0b]|[\x00-\x93][\x0c-\x0c])[\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x0b-\x0b][\x00-\x00][\x94-\x94][\x0c-\x0c][\x00-\x00][\x00-\x00])/
        $str1 = "lmiinfo.pdb"
        $str2 = "LogMeIn Kernel Information Provider" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

