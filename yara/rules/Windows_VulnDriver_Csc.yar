rule Windows_VulnDriver_Csc_856c8393 {
    meta:
        author = "Elastic Security"
        id = "856c8393-f7ad-412b-98a5-ad6f98635578"
        fingerprint = "276e5e891955255daf4237fe6b5f4fbda72f1195cd41b9c678584067f37606df"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: CSC.Sys, Version: <= 10.0.22621.1"
        threat_name = "Windows.VulnDriver.Csc"
        reference_sample = "828c54cfecb2a08863319544ac716aee3898dfe78a87d7757a0e92f1b1f1daf1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 53 00 43 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x57]|[\x00-\x5c][\x58-\x58])|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x5d-\x5d][\x58-\x58]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x01-\x01][\x00-\x00][\x5d-\x5d][\x58-\x58])/
        $str1 = "csc.pdb"
        $str2 = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6D 00 }
        $str3 = "Windows Client Side Caching Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

