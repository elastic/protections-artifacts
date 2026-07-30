rule Windows_VulnDriver_Speedfan_9b590eee {
    meta:
        author = "Elastic Security"
        id = "9b590eee-5938-4293-afac-c9e730753413"
        fingerprint = "c58a8c3bfa710896c35262cc880b9afbadcdfdd73d9969c707e7b5b64e6a70b5"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Subject: Sokno S.R.L."
        threat_name = "Windows.VulnDriver.Speedfan"
        reference_sample = "22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 6F 6B 6E 6F 20 53 2E 52 2E 4C 2E }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

rule Windows_VulnDriver_Speedfan_bc8dba72 {
    meta:
        author = "Elastic Security"
        id = "bc8dba72-b675-4a38-b2ca-40ad2afc63a7"
        fingerprint = "e5faa03bf5f5ebdf2e9ebfd04483ea0bdb204f16983d954f3a1080a2eb3d729d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SOKNO S.R.L., Version: <= 2.3.11.0"
        threat_name = "Windows.VulnDriver.Speedfan"
        reference_sample = "0bd1523a68900b80ed1bccb967643525cca55d4ff4622d0128913690e6bb619e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 4F 4B 4E 4F 20 53 2E 52 2E 4C 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 66 00 64 00 72 00 76 00 78 00 33 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "sfdrvx32.pdb"
        $str2 = "IOCTL_ACPI_EVAL_METHOD_EX"
        $str3 = "IOCTL_ACPI_ENUM_CHILDREN"
        $str4 = "SpeedFan" wide
        $str5 = "SpeedFan x32 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Speedfan_420fa8a4 {
    meta:
        author = "Elastic Security"
        id = "420fa8a4-dce2-47f8-bc25-252581d18da9"
        fingerprint = "e608f6e66cfe5a2b477f8973a09344e2b6eaa4fd4c820e88d1fb302a4da74aad"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sokno S.R.L., Version: <= 2.1.7.0"
        threat_name = "Windows.VulnDriver.Speedfan"
        reference_sample = "1e94d4e6d903e98f60c240dc841dcace5f9e8bbb0802e6648a49ab80c23318cb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 6F 6B 6E 6F 20 53 2E 52 2E 4C 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 66 00 64 00 72 00 76 00 78 00 33 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "sfdrvx32.pdb"
        $str2 = "IOCTL_ACPI_EVAL_METHOD_EX"
        $str3 = "IOCTL_ACPI_ENUM_CHILDREN"
        $str4 = "SpeedFan" wide
        $str5 = "SpeedFan x32 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Speedfan_378712e1 {
    meta:
        author = "Elastic Security"
        id = "378712e1-5c0a-4ea7-b8af-0825e6050091"
        fingerprint = "f37dce5e0ed8e204c93db3e9d14e92d0df82bc7938d79b320bc191f2df2ad9fb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sokno S.R.L., Version: <= 2.1.7.0"
        threat_name = "Windows.VulnDriver.Speedfan"
        reference_sample = "965d4f981b54669a96c5ab02d09bf0a9850d13862425b8981f1a9271350f28bb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 6F 6B 6E 6F 20 53 2E 52 2E 4C 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 66 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "sfdrvx64.pdb"
        $str2 = "IOCTL_ACPI_EVAL_METHOD_EX"
        $str3 = "IOCTL_ACPI_ENUM_CHILDREN"
        $str4 = "SpeedFan" wide
        $str5 = "SpeedFan x64 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Speedfan_7685a40b {
    meta:
        author = "Elastic Security"
        id = "7685a40b-898d-49b2-ab8a-00709e26366f"
        fingerprint = "666ac6f0bd71548a92f9f9383c5bd23ae7b8a2111e98f69a5a12ad38fae7a371"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SOKNO S.R.L., Version: <= 2.3.11.0"
        threat_name = "Windows.VulnDriver.Speedfan"
        reference_sample = "f4ee803eefdb4eaeedb3024c3516f1f9a202c77f4870d6b74356bbde32b3b560"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 4F 4B 4E 4F 20 53 2E 52 2E 4C 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 66 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "sfdrvx64.pdb"
        $str2 = "IOCTL_ACPI_EVAL_METHOD_EX"
        $str3 = "IOCTL_ACPI_ENUM_CHILDREN"
        $str4 = "SpeedFan" wide
        $str5 = "SpeedFan x64 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

