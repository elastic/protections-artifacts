rule Windows_VulnDriver_SysDrv3S_a3bb49e6 {
    meta:
        author = "Elastic Security"
        id = "a3bb49e6-d234-4da9-83a8-52342fcc7c3c"
        fingerprint = "22341d70b8577e965af2fd657f1e02e6b25f19f1db5e81505441265c840dba9e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: SysDrv3S.sys, Version: <= 3.5.6.0"
        threat_name = "Windows.VulnDriver.SysDrv3S"
        reference_sample = "161a50482380727ffa0dd94e193a023f4445dddd3a05340fe2db07fc3ec5b5f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 44 00 72 00 76 00 33 00 53 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x05-\x05][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "SysDrv3S.pdb"
        $str2 = "\\Device\\SysDrv3Sxx"
        $str3 = "\\DosDevices\\SysDrv3Sxx"
        $str4 = "SysDrv3S" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_SysDrv3S_72a96cc7 {
    meta:
        author = "Elastic Security"
        id = "72a96cc7-b4dc-438d-863c-80f1f20d32f2"
        fingerprint = "48dc8c243bb83696f1ba7d7023928b25143b64a686483c6f715c0c7c5bf51ecb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: SysDrv3S.sys, Version: <= 3.0.2.1"
        threat_name = "Windows.VulnDriver.SysDrv3S"
        reference_sample = "cf4efec43474c5aacf4b0971d44eaf8dd6357e594cdb1390085a5070a0df51d4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 44 00 72 00 76 00 33 00 53 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "\\Device\\SysDrv3Sxx"
        $str2 = "\\DosDevices\\SysDrv3Sxx"
        $str3 = "SysDrv3S" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2 and $str3
}

