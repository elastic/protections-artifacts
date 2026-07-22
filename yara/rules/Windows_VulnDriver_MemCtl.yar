rule Windows_VulnDriver_MemCtl_82f6fefc {
    meta:
        author = "Elastic Security"
        id = "82f6fefc-0f41-4732-8c04-e97ad9dfe417"
        fingerprint = "edcbac0cb3586b9615352f459ee3ac90750124117e46a9d8958f54b7df66ecc3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: DFI INC., Version: <= 1.4.2011.2"
        threat_name = "Windows.VulnDriver.MemCtl"
        reference_sample = "fe9323ede771de8ff389ba161ad8696cd6cd788dbf7dd382b6b79011544eed73"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 46 49 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4D 00 65 00 6D 00 43 00 74 00 6C 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xda][\x07-\x07])|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\xdb-\xdb][\x07-\x07]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\xdb-\xdb][\x07-\x07])/
        $str1 = "MemCtl.pdb"
        $str2 = " Memory Access Driver" wide
        $str3 = "Memory Access Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

