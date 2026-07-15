rule Windows_VulnDriver_Ge_7f5a182e {
    meta:
        author = "Elastic Security"
        id = "7f5a182e-02df-4724-96e6-a174a6a3aa91"
        fingerprint = "3727c6e1acff9776b780b16037f2a33bf82f89c29655d53380b444f8f26400e3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: GE , Version: <= 7.0.0.5517"
        threat_name = "Windows.VulnDriver.Ge"
        reference_sample = "cac5dc7c3da69b682097144f12a816530091d4708ca432a7ce39f6abe6616461"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 45 20 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 45 00 44 00 65 00 76 00 44 00 72 00 76 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x14]|[\x00-\x8c][\x15-\x15])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x8d-\x8d][\x15-\x15][\x00-\x00][\x00-\x00])/
        $str1 = "GEDevDrv.pdb"
        $str2 = "Proficy Machine Edition" wide
        $str3 = "GE Device Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

