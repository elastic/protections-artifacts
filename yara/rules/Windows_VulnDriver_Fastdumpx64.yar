rule Windows_VulnDriver_Fastdumpx64_7b3c7211 {
    meta:
        author = "Elastic Security"
        id = "7b3c7211-e284-4cba-a1e5-3279e1b14052"
        fingerprint = "cc32da27c2803ae6c4fcf50a4123174d84d5cdcdf9f27d6380061e138029ed61"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CounterTack, Inc., Version: <= 2.3.0.97"
        threat_name = "Windows.VulnDriver.Fastdumpx64"
        reference_sample = "9cb90643674a941bca2ff0823618e4790a737b9bdcfe882b3af6926591b84d80"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 6F 75 6E 74 65 72 54 61 63 6B 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 66 00 61 00 73 00 74 00 64 00 75 00 6D 00 70 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x60][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x61-\x61][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "fastdump.pdb"
        $str2 = "Fastdump" wide
        $str3 = "fastdumpx64.sys (AMD64) Kernel Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

