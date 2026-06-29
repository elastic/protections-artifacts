rule Windows_VulnDriver_Amdi2c_3a48edc9 {
    meta:
        author = "Elastic Security"
        id = "3a48edc9-e5b6-407c-9935-68d3cd10ccb7"
        fingerprint = "f2a4433ba6125298abb52a97f5a93b11571672a47c09dc7780f3612be20e0176"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.2.0.124"
        threat_name = "Windows.VulnDriver.Amdi2c"
        reference_sample = "15e84d040c2756b2d1b6c3f99d5a1079dc8854844d3c24d740fafd8c668e5fb9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 6D 00 64 00 69 00 32 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x7b][\x00-\x00][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x7c-\x7c][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "TfSysMon.pdb"
        $str2 = "AMD I2C Controller Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

