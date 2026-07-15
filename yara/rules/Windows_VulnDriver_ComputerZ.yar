rule Windows_VulnDriver_ComputerZ_154a8ae4 {
    meta:
        author = "Elastic Security"
        id = "154a8ae4-6471-4ccb-8fef-fd645c8b0ed9"
        fingerprint = "aa1483bc3d84fe3d01b11e6c088e72a9613df780fcb9842012c28b9c21bac514"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Qihoo 360 Software (Beijing) Company Limited, Version: <= 1.6.16.1015"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "03680068ec41bbe725e1ed2042b63b82391f792e8e21e45dc114618641611d5d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 51 69 68 6F 6F 20 33 36 30 20 53 6F 66 74 77 61 72 65 20 28 42 65 69 6A 69 6E 67 29 20 43 6F 6D 70 61 6E 79 20 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0f][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xf6][\x03-\x03])[\x10-\x10][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\xf7-\xf7][\x03-\x03][\x10-\x10][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ComputerZ_b116b7cc {
    meta:
        author = "Elastic Security"
        id = "b116b7cc-c06a-4a19-9e90-d2419534b5e9"
        fingerprint = "66bedbec61c553bf9822354eb0e5a123808e9201926f149c364e1d8586b80e4a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: ComputerZ.Sys, Version: <= 1.6.11.415"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "39134750f909987f6ebb46cf37519bb80707be0ca2017f3735018bac795a3f8d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x9e][\x01-\x01])[\x0b-\x0b][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x9f-\x9f][\x01-\x01][\x0b-\x0b][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ComputerZ_155921eb {
    meta:
        author = "Elastic Security"
        id = "155921eb-dfe8-4b21-a567-c281a6abd110"
        fingerprint = "71977dfb6172970ddb0f963c0630eb97c2f8672cd36a6aec4c8734a87ff86950"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 成都奇鲁科技有限公司, Version: <= 1.1020.1030.1217"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "3f3684a37b2645fa6827943d9812ffc2d83e89e962935b29874bec7c3714a06f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E6 88 90 E9 83 BD E5 A5 87 E9 B2 81 E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xfb][\x03-\x03])[\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\xfc-\xfc][\x03-\x03][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x05][\x04-\x04])|[\xfc-\xfc][\x03-\x03][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\xc0][\x04-\x04])[\x06-\x06][\x04-\x04]|[\xfc-\xfc][\x03-\x03][\x01-\x01][\x00-\x00][\xc1-\xc1][\x04-\x04][\x06-\x06][\x04-\x04])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ComputerZ_61b8c6a0 {
    meta:
        author = "Elastic Security"
        id = "61b8c6a0-7d23-4d91-81dc-96055969c2bd"
        fingerprint = "59205fc81068ba22597d8a2035ff4eec410851b35f6e7ac5ddcf52d0af43e62a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: QIHU 360 SOFTWARE CO. LIMITED, Version: <= 1.6.15.1045"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "5c9e257c9740561b5744812e1343815e7972c362c8993d972b96a56e18c712f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 51 49 48 55 20 33 36 30 20 53 4F 46 54 57 41 52 45 20 43 4F 2E 20 4C 49 4D 49 54 45 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x14][\x04-\x04])[\x0f-\x0f][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x15-\x15][\x04-\x04][\x0f-\x0f][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ComputerZ_046781f2 {
    meta:
        author = "Elastic Security"
        id = "046781f2-981a-4a06-ad51-9eed7f923a35"
        fingerprint = "eefcc358fa7e4f6d068a626eeff042c3c24ac52075d5f028adaea5dfbccf4ab9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Chengdu Ceshi Technology Co., Ltd., Version: <= 1.1.9.416"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "61e7f9a91ef25529d85b22c39e830078b96f40b94d00756595dded9d1a8f6629"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 6E 67 64 75 20 43 65 73 68 69 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x9f][\x01-\x01])[\x09-\x09][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\xa0-\xa0][\x01-\x01][\x09-\x09][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Zwuqi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ComputerZ_f05e48b8 {
    meta:
        author = "Elastic Security"
        id = "f05e48b8-a731-4e7c-895f-e88741511714"
        fingerprint = "362c5d3ec52a656c1edd5947e471c73cc97c8d9ccd8505bfd7994502631fda26"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: ComputerZ.Sys, Version: <= 1.0.8.818"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "61f3b1c026d203ce94fab514e3d15090222c0eedc2a768cc2d073ec658671874"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x31][\x03-\x03])[\x08-\x08][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x32-\x32][\x03-\x03][\x08-\x08][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "ComputerZ System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ComputerZ_11525146 {
    meta:
        author = "Elastic Security"
        id = "11525146-28dc-4edf-b1a2-1fee87ef071d"
        fingerprint = "aa3799fcdfbc2be96c919b2b6c79cbca02a3b0b1cebde9b0d507b967b11a01a0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Chengdu Qilu Technology Co. Ltd., Version: <= 1.1019.1025.918"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "64dddd5ac53fe2c9de2b317c09034d1bccaf21d6c03ccfde3518e5aa3623dd66"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 6E 67 64 75 20 51 69 6C 75 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xfa][\x03-\x03])[\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\xfb-\xfb][\x03-\x03][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x00][\x04-\x04])|[\xfb-\xfb][\x03-\x03][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x95][\x03-\x03])[\x01-\x01][\x04-\x04]|[\xfb-\xfb][\x03-\x03][\x01-\x01][\x00-\x00][\x96-\x96][\x03-\x03][\x01-\x01][\x04-\x04])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ComputerZ_f21d6a86 {
    meta:
        author = "Elastic Security"
        id = "f21d6a86-ac99-4f87-b721-b453d8014402"
        fingerprint = "556cc2b4ef1884d2d0b946c0b51db15682136416aea5aab2f75815dbcca54b46"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 360.cn, Version: <= 1.6.12.1018"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "8d3347c93dff62eecdde22ccc6ba3ce8c0446874738488527ea76d0645341409"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 33 36 30 2E 63 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xf9][\x03-\x03])[\x0c-\x0c][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\xfa-\xfa][\x03-\x03][\x0c-\x0c][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ComputerZ_571e2e0a {
    meta:
        author = "Elastic Security"
        id = "571e2e0a-1d2f-465d-8c45-0dd3bcb5b97c"
        fingerprint = "aebb0a7cc6bc8a72c7e3622cc7e6929f43aa75a866cb7de58eb7727b96a58c9b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Chengdu Qiying Technology Co.,Ltd., Version: <= 1.6.11.1008"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "a97b404aae301048e0600693457c3320d33f395e9312938831bc5a0e808f2e67"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 6E 67 64 75 20 51 69 79 69 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xef][\x03-\x03])[\x0b-\x0b][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\xf0-\xf0][\x03-\x03][\x0b-\x0b][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

