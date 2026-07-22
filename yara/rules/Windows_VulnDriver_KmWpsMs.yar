rule Windows_VulnDriver_KmWpsMs_c9c3b5d8 {
    meta:
        author = "Elastic Security"
        id = "c9c3b5d8-7810-4554-a239-97a3e9f2f495"
        fingerprint = "39d502b4e31c2879deb8587ec13747115d0eb654174f2e367289681cf278efb6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NComputing Global, Inc., Version: <= 12.1.0.0"
        threat_name = "Windows.VulnDriver.KmWpsMs"
        reference_sample = "b045c00f3b921da2e9a5c7977e51c8beceff4a89ec9c4e365f3e4d41f8129e98"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 43 6F 6D 70 75 74 69 6E 67 20 47 6C 6F 62 61 6C 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 6D 00 57 00 70 00 73 00 4D 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x0c-\x0c][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "NcWpsMs.pdb"
        $str2 = "NComputing Station MU driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

