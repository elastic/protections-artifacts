rule Windows_VulnDriver_Pxitrig64_3b3fb746 {
    meta:
        author = "Elastic Security"
        id = "3b3fb746-49bb-4560-a46d-7a6470e5d08c"
        fingerprint = "5b48313826d9b18999b0eb2ee504ea7b826cd669b9ccbc5de1f9732f44e1352d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 3.9.301.2023"
        threat_name = "Windows.VulnDriver.Pxitrig64"
        reference_sample = "56ece6b6b1d2da18458c9d8edc586bd2b9f7c4b092a9745fbed659238b2b3157"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 78 00 69 00 74 00 72 00 69 00 67 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\x2c][\x01-\x01])|[\x09-\x09][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe6][\x07-\x07])[\x2d-\x2d][\x01-\x01]|[\x09-\x09][\x00-\x00][\x03-\x03][\x00-\x00][\xe7-\xe7][\x07-\x07][\x2d-\x2d][\x01-\x01])/
        $str1 = "pxitrig64.pdb"
        $str2 = "PXI Trigger IO for Windows X64" wide
        $str3 = "pxitrigio DeviceDriver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

