rule Windows_VulnDriver_Rtport_11dcce7e {
    meta:
        author = "Elastic Security"
        id = "11dcce7e-a883-4daa-b68d-586f8b3fbc07"
        fingerprint = "acbb0b3766eff13300a5a9e26928368c3cdf835d035f4acc70004dda02a0dd5f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: rtport.sys, Version: <= 5.0.2195.1620"
        threat_name = "Windows.VulnDriver.Rtport"
        reference_sample = "6f806a9de79ac2886613c20758546f7e9597db5a20744f7dd82d310b7d6457d0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 70 00 6F 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x92][\x08-\x08])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\x53][\x06-\x06])[\x93-\x93][\x08-\x08]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x54-\x54][\x06-\x06][\x93-\x93][\x08-\x08])/
        $str1 = "rtport.pdb"
        $str2 = "Windows (R) 2000 DDK driver" wide
        $str3 = "Generic Port I/O" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Rtport_73b6b15a {
    meta:
        author = "Elastic Security"
        id = "73b6b15a-ca21-42ee-a754-6133955e919b"
        fingerprint = "b8f53830ae6ad76ec01c5acb77515223fd4951555edbdcb367ca78529cf48658"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: rtport.sys, Version: <= 5.0.2195.1711"
        threat_name = "Windows.VulnDriver.Rtport"
        reference_sample = "8fe429c46fedbab8f06e5396056adabbb84a31efef7f9523eb745fc60144db65"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 70 00 6F 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x92][\x08-\x08])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\xae][\x06-\x06])[\x93-\x93][\x08-\x08]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\xaf-\xaf][\x06-\x06][\x93-\x93][\x08-\x08])/
        $str1 = "rtport.pdb"
        $str2 = "Windows (R) 2003 DDK 3790 provider" wide
        $str3 = "Generic Port I/O for Win64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

