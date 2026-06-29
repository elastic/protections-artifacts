rule Windows_VulnDriver_Aquantia_9894a73f {
    meta:
        author = "Elastic Security"
        id = "9894a73f-67ee-495d-93e8-411dfc24a465"
        fingerprint = "6c0bf450e761ea292425c6c1151090b603fbd096a4a516c880a392eff6ccd318"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Aquantia Corp., Version: <= 6.1.7600.16385"
        threat_name = "Windows.VulnDriver.Aquantia"
        reference_sample = "0b57569aaa0f4789d9642dd2189b0a82466b80ad32ff35f88127210ed105fe57"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 71 75 61 6E 74 69 61 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 74 00 6C 00 41 00 63 00 63 00 65 00 73 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x1c]|[\x00-\xaf][\x1d-\x1d])|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3f]|[\x00-\x00][\x40-\x40])[\xb0-\xb0][\x1d-\x1d]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x40-\x40][\xb0-\xb0][\x1d-\x1d])/
        $str1 = "atlAccess.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "Simple PCI access driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

