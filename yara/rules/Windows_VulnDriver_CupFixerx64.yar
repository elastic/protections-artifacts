rule Windows_VulnDriver_CupFixerx64_fb265a30 {
    meta:
        author = "Elastic Security"
        id = "fb265a30-d9b2-4bb7-8478-5e44b01adf3e"
        fingerprint = "bc001b778ac189584adc43d11add2f7062f653159f7cc24943b76853a39dd9d9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Xinyi Electronic Technology (Shanghai) Co., Ltd., Version: <= 32.0.10011.13337"
        threat_name = "Windows.VulnDriver.CupFixerx64"
        reference_sample = "8c748ae5dcc10614cc134064c99367d28f3131d1f1dda0c9c29e99279dc1bdd9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 58 69 6E 79 69 20 45 6C 65 63 74 72 6F 6E 69 63 20 54 65 63 68 6E 6F 6C 6F 67 79 20 28 53 68 61 6E 67 68 61 69 29 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 75 00 70 00 46 00 69 00 78 00 65 00 72 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x1f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x20-\x20][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x26]|[\x00-\x1a][\x27-\x27])|[\x00-\x00][\x00-\x00][\x20-\x20][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x33]|[\x00-\x18][\x34-\x34])[\x1b-\x1b][\x27-\x27]|[\x00-\x00][\x00-\x00][\x20-\x20][\x00-\x00][\x19-\x19][\x34-\x34][\x1b-\x1b][\x27-\x27])/
        $str1 = "amifldrv64.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "Sincey Cup Fixer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

