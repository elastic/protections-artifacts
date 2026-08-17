rule Windows_VulnDriver_Huawei_fbb14476 {
    meta:
        author = "Elastic Security"
        id = "fbb14476-6e19-41ec-bbde-322860c593a2"
        fingerprint = "674e6cc8247cc020b698ab4fc12449aa505032d3696c059555f6a839bd5a4482"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Huawei Technologies Co., Ltd."
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "13a38c92606de7bc61960606deb59e1db125fb4efbb8b29ba732e5d3c2dc169c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 61 77 65 69 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "winio64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Huawei_f7cd7337 {
    meta:
        author = "Elastic Security"
        id = "f7cd7337-f27c-4989-b30b-95fae976bba8"
        fingerprint = "7aaf91e1c10dd4061de44a41e5f45b729b486c001b11948ddde300a8424b9066"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Huawei Technologies Co.,Ltd."
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "19a212e6fc324f4cb9ee5eba60f5c1fc0191799a4432265cbeaa3307c76a7fc0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 61 77 65 69 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 6F 2E 2C 4C 74 64 2E }
        $str1 = "Phymemx64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Huawei_c1edf9a4 {
    meta:
        author = "Elastic Security"
        id = "c1edf9a4-d0c8-4486-b935-9b839cf76cc8"
        fingerprint = "aad2497ef73a0d71b39721f1d4c1a4454071a841cfebf285d4ee9ae295e8b74f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "90d2e9e994ed8e964845a26dce741ad43b29ff54cf5faa67271d62d4e24acbc8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 41 00 75 00 69 00 64 00 6F 00 4F 00 73 00 32 00 45 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HWAudioOs2Ec.pdb"
        $str2 = "Huawei Audio Driver" wide
        $str3 = "HWAuidoOs2Ec" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Huawei_fcf62f24 {
    meta:
        author = "Elastic Security"
        id = "fcf62f24-a284-4ac4-a005-73279c9df8ec"
        fingerprint = "4a05278d1767ea8f5f8cd3f11a9870c30bd3b10ae2219e1617f36fb61f3833a7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Huawei Technologies Co.,Ltd., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 61 77 65 69 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 6F 2E 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 77 00 4F 00 73 00 32 00 45 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HwOs2Ecx64.pdb"
        $str2 = "Huawei MateBook" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Huawei_651f0fbc {
    meta:
        author = "Elastic Security"
        id = "651f0fbc-71e1-46b1-9e56-bcc0d63ce7db"
        fingerprint = "53242f2a65b5339b4fbbe2e6d8498c18564026cac27e9f1461a0d8308e4e2382"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Huawei Technologies Co., Ltd., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "bb1135b51acca8348d285dc5461d10e8f57260e7d0c8cc4a092734d53fc40cbc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 61 77 65 69 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 77 00 4F 00 73 00 32 00 45 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HwOs2Ecx64.pdb"
        $str2 = "Huawei MateBook" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Huawei_66909102 {
    meta:
        author = "Elastic Security"
        id = "66909102-cedf-49ab-b791-679aee3a95f1"
        fingerprint = "cf80290ab403ea8862d8a18d4834f29144706ebec96147529abe0c37905c08fa"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Name: HWAuidoOs2Ec.sys, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "9122b0b4a1b76550020848c692a34715fed50bc2bd6395904bd31f92638f213e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 41 00 75 00 69 00 64 00 6F 00 4F 00 73 00 32 00 45 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HWAudioOs2Ec.pdb"
        $str2 = "IOCTL_SETTING_LOGO"
        $str3 = "IOCTL_SETTING_PDB"
        $str4 = "Huawei Audio Driver" wide
        $str5 = "HWAuidoOs2Ec" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Huawei_de9f3338 {
    meta:
        author = "Elastic Security"
        id = "de9f3338-180e-4ca9-9702-43ece1d0e569"
        fingerprint = "3e14c4a300519a891c0a7aa4355e731ef978fac3bdd06955c3f13eb75b7f1c96"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Huawei Device Co., Ltd., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "c4e93449453cf67c5d5605bb8f425207a738a242fdb432d720acc32faa74926c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 61 77 65 69 20 44 65 76 69 63 65 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 77 00 4F 00 73 00 32 00 45 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HwOs2Ec10x64_C233.pdb"
        $str2 = "IOCTL_SETTING_LOGO"
        $str3 = "IOCTL_SETTING_PDB"
        $str4 = "Huawei MateBook" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

