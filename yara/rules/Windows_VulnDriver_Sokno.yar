rule Windows_VulnDriver_Sokno_9c5202ef {
    meta:
        author = "Elastic Security"
        id = "9c5202ef-b861-40f3-bfd7-549f16fb1238"
        fingerprint = "d9204e39606b883c4e93accccd9151bb3a0c5ed6e19a9396ca349728e1d42a9e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sokno S.R.L., Version: <= 4.43.4.0"
        threat_name = "Windows.VulnDriver.Sokno"
        reference_sample = "88fb0a846f52c3b680c695cd349bf56151a53a75a07b8b0b4fe026ab8aa0a9af"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 6F 6B 6E 6F 20 53 2E 52 2E 4C 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 66 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x2a][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x2b-\x2b][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x2b-\x2b][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "sfdrvx64.pdb"
        $str2 = "IOCTL_ACPI_EVAL_METHOD_EX"
        $str3 = "IOCTL_ACPI_ENUM_CHILDREN"
        $str4 = "Speed Fan" wide
        $str5 = "Speed Fan x64 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Sokno_38de57cc {
    meta:
        author = "Elastic Security"
        id = "38de57cc-7e17-4a48-b926-2b0352e91af4"
        fingerprint = "76a40ca4b4fc9af98663f476928411346d20cbc37981298488079e3379d0b666"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sokno S.R.L., Version: <= 4.43.4.0"
        threat_name = "Windows.VulnDriver.Sokno"
        reference_sample = "ad23d77a38655acb71216824e363df8ac41a48a1a0080f35a0d23aa14b54460b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 6F 6B 6E 6F 20 53 2E 52 2E 4C 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 66 00 64 00 72 00 76 00 78 00 33 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x2a][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x2b-\x2b][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x2b-\x2b][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "sfdrvx32.pdb"
        $str2 = "IOCTL_ACPI_EVAL_METHOD_EX"
        $str3 = "IOCTL_ACPI_ENUM_CHILDREN"
        $str4 = "Speed Fan" wide
        $str5 = "Speed Fan x32 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

