rule Windows_VulnDriver_PanIOx64_660fd6b0 {
    meta:
        author = "Elastic Security"
        id = "660fd6b0-619d-4ad9-a716-b520fef4f19c"
        fingerprint = "d98c3ca661406950223eba85dec4997258f5a132e4eec608018392adf4445cc6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PAN YAZILIM BILISIM TEKNOLOJILERI TICARET LTD. STI., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.PanIOx64"
        reference_sample = "6b830ea0db6546a044c9900d3f335e7820c2a80e147b0751641899d1a5aa8f74"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 41 4E 20 59 41 5A 49 4C 49 4D 20 42 49 4C 49 53 49 4D 20 54 45 4B 4E 4F 4C 4F 4A 49 4C 45 52 49 20 54 49 43 41 52 45 54 20 4C 54 44 2E 20 53 54 49 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 61 00 6E 00 49 00 4F 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "PanIOx64.pdb"
        $str2 = "PanIO Library" wide
        $str3 = "Temperature and system information driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

