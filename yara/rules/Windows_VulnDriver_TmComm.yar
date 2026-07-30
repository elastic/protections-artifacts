rule Windows_VulnDriver_TmComm_333f3851 {
    meta:
        author = "Elastic Security"
        id = "333f3851-5d99-4b22-8af5-1587e9e44ea4"
        fingerprint = "94b718e4450f28b8a9562f89a2fd0e395012051f0af8617d8ab13a45afcd4191"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: TmComm.sys, Version: 8.0.0.0"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "cc687fe3741bbde1dd142eac0ef59fd1d4457daee43cdde23bb162ef28d04e64"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x08][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x07][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_TmComm_19bb2abb {
    meta:
        author = "Elastic Security"
        id = "19bb2abb-6b51-486d-9bbf-0ed12344410d"
        fingerprint = "a1357c0ee2f9a7ecf8f9c1c7f35adb453b99e80c9741012b3a9885410157f309"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Trend Micro, Inc., Version: <= 6.70.0.1106"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "0909005d625866ef8ccd8ae8af5745a469f4f70561b644d6e38b80bccb53eb06"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 72 65 6E 64 20 4D 69 63 72 6F 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x45][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x46-\x46][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x51][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x46-\x46][\x00-\x00][\x06-\x06][\x00-\x00][\x52-\x52][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "tmcomm.pdb"
        $str2 = "_UtilGetFileObjectForProcessByEPROC@8"
        $str3 = "_UtilbuildDynamicDiskMappingTable@0"
        $str4 = "Trend Micro Eyes" wide
        $str5 = "TrendMicro Common Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_TmComm_952c54ab {
    meta:
        author = "Elastic Security"
        id = "952c54ab-444d-4188-b51c-6057916796cb"
        fingerprint = "b60f3e2d2ec082633081131a3814f0964eb03fa2c353cf0341d277c2f491ad2e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Trend Micro, Inc., Version: <= 3.20.0.1012"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "4bc0921ffd4acc865525d3faf98961e8decc5aec4974552cbbf2ae8d5a569de4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 72 65 6E 64 20 4D 69 63 72 6F 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x13][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x14-\x14][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xf3][\x03-\x03])[\x00-\x00][\x00-\x00]|[\x14-\x14][\x00-\x00][\x03-\x03][\x00-\x00][\xf4-\xf4][\x03-\x03][\x00-\x00][\x00-\x00])/
        $str1 = "tmcomm.pdb"
        $str2 = "_UtilGetFileObjectForProcessByEPROC@8"
        $str3 = "_UtilbuildDynamicDiskMappingTable@0"
        $str4 = "Trend Micro AEGIS" wide
        $str5 = "TrendMicro Common Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_TmComm_4ba8b787 {
    meta:
        author = "Elastic Security"
        id = "4ba8b787-6e02-4f87-91d9-a8dccd69492a"
        fingerprint = "e08a49d0479119c447d0c293eaebbbd72e83fd7f5fb6f5becaa07678a63024b8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 6.70.0.1140"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "4e37592a2a415f520438330c32cfbdbd6af594deef5290b2fa4b9722b898ff69"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x45][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x46-\x46][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x73][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x46-\x46][\x00-\x00][\x06-\x06][\x00-\x00][\x74-\x74][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "tmcomm.pdb"
        $str2 = "\\Device\\ or \\??\\)"
        $str3 = "UtilGetFileObjectForProcessByEPROC"
        $str4 = "UtilbuildDynamicDiskMappingTable"
        $str5 = "Trend Micro Eyes" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_TmComm_96a22802 {
    meta:
        author = "Elastic Security"
        id = "96a22802-f8a1-4ba9-8988-1f805cfce43d"
        fingerprint = "4c91cd69571ac9b9fcbf079bbb8138586f69c14e744139fe30e42753c0c7b6af"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Trend Micro, Inc., Version: <= 6.70.0.1129"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "7c731c0ea7f28671ab7787800db69739ea5cd6be16ea21045b4580cf95cbf73b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 72 65 6E 64 20 4D 69 63 72 6F 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x45][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x46-\x46][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x68][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x46-\x46][\x00-\x00][\x06-\x06][\x00-\x00][\x69-\x69][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "tmcomm.pdb"
        $str2 = "\\Device\\ or \\??\\)"
        $str3 = "_UtilGetFileObjectForProcessByEPROC@8"
        $str4 = "_UtilbuildDynamicDiskMappingTable@0"
        $str5 = "Trend Micro Eyes" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_TmComm_c820c8c0 {
    meta:
        author = "Elastic Security"
        id = "c820c8c0-a0bc-453a-b689-4a57e0ad081c"
        fingerprint = "27344327453a47a0edf2cf938b4c3b9812ebbef2be48160089eb0a8abe26f18c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Trend Micro, Inc., Version: <= 7.30.0.1078"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "818e396595d08d724666803cd29dac566dc7db23bf50e9919d04b33afa988c01"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 72 65 6E 64 20 4D 69 63 72 6F 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x1d][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x1e-\x1e][\x00-\x00][\x07-\x07][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x35][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x1e-\x1e][\x00-\x00][\x07-\x07][\x00-\x00][\x36-\x36][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "TMCOMM.pdb"
        $str2 = "UtilGetFileObjectForProcessByEPROC"
        $str3 = "UtilbuildDynamicDiskMappingTable"
        $str4 = "Trend Micro Eyes" wide
        $str5 = "TrendMicro Common Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_TmComm_8523c85e {
    meta:
        author = "Elastic Security"
        id = "8523c85e-c6e4-47f8-9e8c-55ca144f1881"
        fingerprint = "d928ca41d83552ee0ec6cdd85fc7722f035634950fc7db27be7c555184062ba5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Trend Micro, Inc., Version: <= 2.5.0.1121"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "a8027daa6facf1ff81405daf6763249e9acf232a1a191b6bf106711630e6188e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 72 65 6E 64 20 4D 69 63 72 6F 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x60][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x61-\x61][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "tmcomm.pdb"
        $str2 = "_UtilGetFileObjectForProcessByEPROC@8"
        $str3 = "_UtilbuildDynamicDiskMappingTable@0"
        $str4 = "TrendMicro Common Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_TmComm_16bb40d2 {
    meta:
        author = "Elastic Security"
        id = "16bb40d2-ef30-42d9-9374-9eee6ae9d7d2"
        fingerprint = "1d2e29b693ee4547f4f2b692d8935aa9e0254630da70c7bd07af278303ca7af0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Trend Micro, Inc., Version: <= 2.2.0.1016"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "adc10de960f40fa9f6e28449748250fa9ddfd331115b77a79809a50c606753ee"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 72 65 6E 64 20 4D 69 63 72 6F 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xf7][\x03-\x03])[\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\xf8-\xf8][\x03-\x03][\x00-\x00][\x00-\x00])/
        $str1 = "tmcomm.pdb"
        $str2 = "_UtilWriteVersionToRegistry@8"
        $str3 = "_GetModuleInfoByModuleName@8"
        $str4 = "TrendMicro Common Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_TmComm_5c7020e3 {
    meta:
        author = "Elastic Security"
        id = "5c7020e3-bc01-4e5a-a778-2c90cd298f86"
        fingerprint = "c4c98b58a5cb6db89eefe0d59c1804fc960519128c88a3f2f524c679ed427c35"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Trend Micro, Inc., Version: <= 7.30.0.1065"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "b773511fdb2e370dec042530910a905472fcc2558eb108b246fd3200171b04d3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 72 65 6E 64 20 4D 69 63 72 6F 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x1d][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x1e-\x1e][\x00-\x00][\x07-\x07][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x28][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x1e-\x1e][\x00-\x00][\x07-\x07][\x00-\x00][\x29-\x29][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "TMCOMM.pdb"
        $str2 = "_UtilGetFileObjectForProcessByEPROC@8"
        $str3 = "_UtilbuildDynamicDiskMappingTable@0"
        $str4 = "Trend Micro Eyes" wide
        $str5 = "TrendMicro Common Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_TmComm_58053494 {
    meta:
        author = "Elastic Security"
        id = "58053494-4464-4270-b1b0-f57538d1c502"
        fingerprint = "3fc0f6c99be6555ccd18acfcde292b520c73a6e7a5503a20dfe44953aba38431"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Early Launch Anti-malware Publisher, Version: <= 1.6.0.1002"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "dd628061d6e53f3f0b44f409ad914b3494c5d7b5ff6ff0e8fc3161aacec93e96"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 45 61 72 6C 79 20 4C 61 75 6E 63 68 20 41 6E 74 69 2D 6D 61 6C 77 61 72 65 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 65 00 6C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xe9][\x03-\x03])[\x00-\x00][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\xea-\xea][\x03-\x03][\x00-\x00][\x00-\x00])/
        $str1 = "tmel.pdb"
        $str2 = "Trend Micro Early Launch Anti-Malware Driver" wide
        $str3 = "TrendMicro ELAM Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_TmComm_0ae93dda {
    meta:
        author = "Elastic Security"
        id = "0ae93dda-0606-40a0-a994-7ccbd7584251"
        fingerprint = "65000afa8f16646f2475849c712be560ed849191a0690221835d8f8a63868789"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Early Launch Anti-malware Publisher, Version: <= 1.6.0.1004"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "e505569892551b2ba79d8792badff0a41faea033e8d8f85c3afea33463c70bd9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 45 61 72 6C 79 20 4C 61 75 6E 63 68 20 41 6E 74 69 2D 6D 61 6C 77 61 72 65 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 65 00 6C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xeb][\x03-\x03])[\x00-\x00][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\xec-\xec][\x03-\x03][\x00-\x00][\x00-\x00])/
        $str1 = "tmel.pdb"
        $str2 = "Trend Micro Early Launch Anti-Malware Driver" wide
        $str3 = "TrendMicro ELAM Driver (64-Bit)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_TmComm_601515ed {
    meta:
        author = "Elastic Security"
        id = "601515ed-f9ae-4432-a888-fa117ea2e2d0"
        fingerprint = "59e9fc340e4ac7aed126727943d7f510a89cf9783389735433e3da798a1546e7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Trend Micro, Inc., Version: <= 6.70.0.1078"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "ec5fac0b6bb267a2bd10fc80c8cca6718439d56e82e053d3ff799ce5f3475db5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 72 65 6E 64 20 4D 69 63 72 6F 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x45][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x46-\x46][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x35][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x46-\x46][\x00-\x00][\x06-\x06][\x00-\x00][\x36-\x36][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "tmcomm.pdb"
        $str2 = "UtilGetFileObjectForProcessByEPROC"
        $str3 = "UtilbuildDynamicDiskMappingTable"
        $str4 = "Trend Micro Eyes" wide
        $str5 = "TrendMicro Common Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

