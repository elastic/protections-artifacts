rule Windows_VulnDriver_Antiy_6be1f9f5 {
    meta:
        author = "Elastic Security"
        id = "6be1f9f5-9ff5-4b57-a8a1-f437f864a788"
        fingerprint = "dce403f90a213ad32ca4260a6e5cb76290bef587844260bbe998ba70f94483a9"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: Antiy Labs, Version: <= 2.0.20.307"
        threat_name = "Windows.VulnDriver.Antiy"
        reference_sample = "b2925c2d8e739e248f343d1a8b3bafcff09cf8ba8629b9a797c127491c841dea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 6E 74 69 79 20 4C 61 62 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 74 00 6F 00 6F 00 6C 00 73 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x32][\x01-\x01])[\x14-\x14][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x33-\x33][\x01-\x01][\x14-\x14][\x00-\x00])/
        $str1 = "AToolsKrnl64.pdb"
        $str2 = "Kernel Call Services" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

