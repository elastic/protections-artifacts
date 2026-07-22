rule Windows_VulnDriver_IUForceDelete_f85ffa26 {
    meta:
        author = "Elastic Security"
        id = "f85ffa26-f15e-4648-8d1b-8d9e4a7ffc54"
        fingerprint = "2f9f05ded542678bb34e33584efc52dc777befcd8c4b7136acfc0cd31d722166"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.0.6.20"
        threat_name = "Windows.VulnDriver.IUForceDelete"
        reference_sample = "30f5d03e37d22c7dece8bb8240edc8566f2be7fe76d3c7f97eeceb60d889ee06"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 55 00 46 00 6F 00 72 00 63 00 65 00 44 00 65 00 6C 00 65 00 74 00 65 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x13][\x00-\x00][\x06-\x06][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x14-\x14][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "IUForceDelete.pdb"
        $str2 = "Uninstaller" wide
        $str3 = "IUForceDelete" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

