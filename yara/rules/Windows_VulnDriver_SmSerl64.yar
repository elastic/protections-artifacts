rule Windows_VulnDriver_SmSerl64_00319890 {
    meta:
        author = "Elastic Security"
        id = "00319890-3c60-4e8b-b315-05897c55d1fc"
        fingerprint = "0b5f34d7a1c48d21220f2da553cc83efe27897ecc3c3c511516d63cfef5a22ec"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: SmSerl64.sys, Version: <= 6.12.23.0"
        threat_name = "Windows.VulnDriver.SmSerl64"
        reference_sample = "e599200c44eca5eb06475f90f67a58723b30c3c2887bd12ed7c31ff1042382ea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 6D 00 53 00 65 00 72 00 6C 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0b][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0c-\x0c][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x16][\x00-\x00]|[\x0c-\x0c][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00])/
        $str1 = "SmSerl64.pdb"
        $str2 = "Motorola SM56 Modem" wide
        $str3 = "Motorola SM56 Modem WDM Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

