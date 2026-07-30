rule Windows_VulnDriver_WinTapix_59416f86 {
    meta:
        author = "Elastic Security"
        id = "59416f86-7fd2-47f9-99b8-e7f6c0e9cb60"
        fingerprint = "ed8dc493f94acdb11412574458038d31fcecc45b0f3b59b13b436fcbaeb08e74"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing JoinHope Image Technology Ltd., Version: <= 6.3.9600.16384"
        threat_name = "Windows.VulnDriver.WinTapix"
        reference_sample = "1485c0ed3e875cbdfc6786a5bd26d18ea9d31727deb8df290a1c00c780419a4e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 4A 6F 69 6E 48 6F 70 65 20 49 6D 61 67 65 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 6E 00 54 00 61 00 70 00 69 00 78 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x24]|[\x00-\x7f][\x25-\x25])|[\x03-\x03][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3e]|[\x00-\xff][\x3f-\x3f])[\x80-\x80][\x25-\x25]|[\x03-\x03][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x40-\x40][\x80-\x80][\x25-\x25])/
        $str1 = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6D 00 }
        $str2 = "Windows Kernel Executive Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

