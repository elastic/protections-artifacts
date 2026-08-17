rule Windows_VulnDriver_MyPortIO_37c35201 {
    meta:
        author = "Elastic Security"
        id = "37c35201-a074-4a82-bbc7-10c3a116ffe3"
        fingerprint = "8ea4d241b1f8be1c9c5bcd3a3ab83bda103624bcc0bc1bead3881bd3b88a1c99"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: Nuvoton Technology Corporation, Version: <= 2.0.2008.128"
        threat_name = "Windows.VulnDriver.MyPortIO"
        reference_sample = "18bf6cf0224a41058ba3944ff0df9e12fa256c7c353d6fa6132a464cd5db5709"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 75 76 6F 74 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4D 00 79 00 50 00 6F 00 72 00 74 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xd7][\x07-\x07])|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x7f][\x00-\x00][\xd8-\xd8][\x07-\x07]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x80-\x80][\x00-\x00][\xd8-\xd8][\x07-\x07])/
        $str1 = "MyPortIO.pdb"
        $str2 = "Nuvoton Port I/O Driver" wide
        $str3 = "Port I/O Driver for Win32/64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_MyPortIO_bab77af0 {
    meta:
        author = "Elastic Security"
        id = "bab77af0-3adc-45d8-96c1-30be378a779c"
        fingerprint = "a8a5eab31061466aabf43b23489727e1e82d0149ea1d7a422d95ae49be53a81c"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Nuvoton Technology Corporation, Version: <= 2.0.2008.128"
        threat_name = "Windows.VulnDriver.MyPortIO"
        reference_sample = "30d5e07d9e88722a5e0eec17d0437b859f782d1c15fc80b5381f3e3eb4221bc7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 75 76 6F 74 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4D 00 79 00 50 00 6F 00 72 00 74 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xd7][\x07-\x07])|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x7f][\x00-\x00][\xd8-\xd8][\x07-\x07]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x80-\x80][\x00-\x00][\xd8-\xd8][\x07-\x07])/
        $str1 = "MyPortIO.pdb"
        $str2 = "Nuvoton Port I/O Driver" wide
        $str3 = "Port I/O Driver for Win32/64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

