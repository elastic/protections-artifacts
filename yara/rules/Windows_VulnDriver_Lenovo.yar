rule Windows_VulnDriver_Lenovo_1058a5b1 {
    meta:
        author = "Elastic Security"
        id = "1058a5b1-ee79-462d-9954-6d10c36e6970"
        fingerprint = "e7135991f41c265ce5d284fafce2a36c51dfcc50ce72b067b7e8e18aa26c2aee"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Lenovo Information Products (Shenzhen) Co.,Ltd, Version: <= 6.1.7600.16385"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "05f7419335418b1eb5c983860a8a68e73147508b31e7cb1341a9dbeeb81f96b4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 65 6E 6F 76 6F 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 50 72 6F 64 75 63 74 73 20 28 53 68 65 6E 7A 68 65 6E 29 20 43 6F 2E 2C 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 44 00 69 00 61 00 67 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x1c]|[\x00-\xaf][\x1d-\x1d])|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3f]|[\x00-\x00][\x40-\x40])[\xb0-\xb0][\x1d-\x1d]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x40-\x40][\xb0-\xb0][\x1d-\x1d])/
        $str1 = "ldiagio.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Lenovo_d6ba2871 {
    meta:
        author = "Elastic Security"
        id = "d6ba2871-c8ab-452f-aa56-d8b9369dbb15"
        fingerprint = "9ab1762be67151bb2ff7f3148a200ca13867d81c4917ffb6665022324cea880f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: LENOVO, Version: <= 2.5.30.11281"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "5ab36c116767eaae53a466fbc2dae7cfd608ed77721f65e83312037fbd57c946"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 45 4E 4F 56 4F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 6F 00 6F 00 74 00 52 00 65 00 70 00 61 00 69 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x1d][\x00-\x00]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x2b]|[\x00-\x10][\x2c-\x2c])[\x1e-\x1e][\x00-\x00]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x11-\x11][\x2c-\x2c][\x1e-\x1e][\x00-\x00])/
        $str1 = "BootRepair.pdb"
        $str2 = "BootRepair" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Lenovo_26b2c815 {
    meta:
        author = "Elastic Security"
        id = "26b2c815-f3cc-4e8a-b596-3cc4ef3c67f2"
        fingerprint = "0d524fb0bf5da518f8e4bdd8f7ba3c6540389aa2f1355ae114303075668a2e76"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: LnvMSRIO.sys, Version: <= 3.1.0.36"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "8936738fd34337ad70b1f4a38a0d45a4f1dac1091461b7a41e245b8322e32fc5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 6E 00 76 00 4D 00 53 00 52 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x23][\x00-\x00][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x24-\x24][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "LnvMSRIO.pdb"
        $str2 = "Lenovo filter driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Lenovo_88fa0718 {
    meta:
        author = "Elastic Security"
        id = "88fa0718-88a2-4d32-a9e6-1257d53c9ead"
        fingerprint = "4707590a1d0226ecc81a3fa0ef9c0330112a8c04da96b865346840eef161201a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Lenovo, Version: <= 1.0.35221.0"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "9093340be0ab932fa49edd81e9da50914af3e095059908137c49dee991283b81"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 65 6E 6F 76 6F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 6E 00 52 00 69 00 6E 00 67 00 30 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x88]|[\x00-\x94][\x89-\x89])|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x95-\x95][\x89-\x89])/
        $str1 = "WinRing0.pdb"
        $str2 = "Lenovo Display Control Center" wide
        $str3 = "WinRing0" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Lenovo_ed6235a3 {
    meta:
        author = "Elastic Security"
        id = "ed6235a3-1ae6-4680-8234-9e902027e77a"
        fingerprint = "09911ecad47fff861c55be7396c487f56f7d7a4ceddd1e4abf4024ec3ec89e10"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Lenovo"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "ff0892697771f1a9968423793faa34008cfa0041fee48d5b52b25314f7a6a7b4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 65 6E 6F 76 6F }
        $str1 = "NetworkLocker_x64.pdb"
        $str2 = "IOCTL_WORKLOCK_NTLKD"
        $str3 = "IOCTL_WORKLOCK_NTLKE"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Lenovo_e92bb145 {
    meta:
        author = "Elastic Security"
        id = "e92bb145-057e-4457-aa01-189308f32b82"
        fingerprint = "582e01816d6f1f764d429768d3e92161e9c7415395a051e0505e6f6bc300679b"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 3.1.0.0"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "dc5bae2e403e639ef2ebab4c85b827f75853ed6cfbd122a847784f3d49a79e51"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 65 00 6E 00 6F 00 76 00 6F 00 44 00 69 00 61 00 67 00 6E 00 6F 00 73 00 74 00 69 00 63 00 73 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Lenovo Diagnostics" wide
        $str2 = "Lenovo Diagnostics Driver for Windows 10 and later." wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

