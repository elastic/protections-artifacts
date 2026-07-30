rule Windows_VulnDriver_Rising_0dd24a18 {
    meta:
        author = "Elastic Security"
        id = "0dd24a18-598e-426a-ab94-1e491e441fe3"
        fingerprint = "21df0e34902de4138dc34d0025cf2f8b8e5260af19a0538ea5ecfd6aa7546067"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing Rising Network Security Technology Co., Ltd., Version: <= 1.0.0.5"
        threat_name = "Windows.VulnDriver.Rising"
        reference_sample = "aae730aac6e49d636af9c5ac514faa40ccc7afbcce85c8f82bc639b53cd95151"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 52 69 73 69 6E 67 20 4E 65 74 77 6F 72 6B 20 53 65 63 75 72 69 74 79 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 73 00 6E 00 64 00 69 00 73 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x04][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "rsndisp_win10-x64.pdb"
        $str2 = "rsndisp_deregister"
        $str3 = "rsndisp_register"
        $str4 = "Rising AntiVirus" wide
        $str5 = "rsndisp.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Rising_d12d593a {
    meta:
        author = "Elastic Security"
        id = "d12d593a-7d2a-477e-83a6-a61c9f56c6da"
        fingerprint = "c8365a9e2020bda0256a4ef5c8bc603bf676a8907a9a48c0872c787d9f14d053"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing Rising Network Security Technology Co., Ltd., Version: <= 1.0.0.16"
        threat_name = "Windows.VulnDriver.Rising"
        reference_sample = "ea8c8f834523886b07d87e85e24f124391d69a738814a0f7c31132b6b712ed65"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 52 69 73 69 6E 67 20 4E 65 74 77 6F 72 6B 20 53 65 63 75 72 69 74 79 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 73 00 70 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0f][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x10-\x10][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "rspot_win10-x64.pdb"
        $str2 = "rspot.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

