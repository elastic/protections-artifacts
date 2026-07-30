rule Windows_VulnDriver_ProxyDrv_262c87e7 {
    meta:
        author = "Elastic Security"
        id = "262c87e7-e94c-4827-86c3-ef6c8645dbf1"
        fingerprint = "1fcc825a64c423101ad3f300f34e1063f8ea6912e79f71daa926385269aa3cbf"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: 雷神（武汉）信息技术有限公司, Version: <= 1.9.5.3"
        threat_name = "Windows.VulnDriver.ProxyDrv"
        reference_sample = "0b205838a8271daea89656b1ec7c5bb7244c42a8b8000d7697e92095da6b9b94"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 9B B7 E7 A5 9E EF BC 88 E6 AD A6 E6 B1 89 EF BC 89 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 72 00 6F 00 78 00 79 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x05-\x05][\x00-\x00]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x05-\x05][\x00-\x00])/
        $str1 = "proxydriver.pdb"
        $str2 = { F7 96 5E 79 4E 00 4E 00 A0 52 1F 90 68 56 2D 00 71 9A A8 52 0B 7A 8F 5E 87 65 F6 4E }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

