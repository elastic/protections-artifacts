rule Windows_VulnDriver_HpSwToolsDriver_bec9be61 {
    meta:
        author = "Elastic Security"
        id = "bec9be61-a115-4fcd-bb58-b7b7461ecaf8"
        fingerprint = "3e76471a43e893a96968ecd9e67e6225a46f4ab24ee92e0152052380e4ac2d10"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.5.0.0"
        threat_name = "Windows.VulnDriver.HpSwToolsDriver"
        reference_sample = "bf07c46effde8b6b0fd3c9586a5a9636800fb37418c1e8e606c67cb613cbf832"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 50 00 20 00 53 00 57 00 20 00 54 00 4F 00 4F 00 4C 00 53 00 20 00 44 00 52 00 49 00 56 00 45 00 52 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "swtoolsdriver.pdb"
        $str2 = "HP SW TOOLS DRIVER" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

