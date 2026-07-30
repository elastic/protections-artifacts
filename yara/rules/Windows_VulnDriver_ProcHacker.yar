rule Windows_VulnDriver_ProcHacker_2efb5a11 {
    meta:
        author = "Elastic Security"
        id = "2efb5a11-51e6-4e0e-86f9-eca0ae4f2ece"
        fingerprint = "8859ab1d515cbccdd17152b9e5f51f7965947d7aeb7b26b5c9ee5b3f95cd75ef"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: NGO, Version: <= 3.1.0.0"
        threat_name = "Windows.VulnDriver.ProcHacker"
        reference_sample = "adccdfe31b51dbb64a82b7a0348bfe9cdf9e34254925e078e1918c19767d95d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 47 4F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6B 00 70 00 72 00 6F 00 63 00 65 00 73 00 73 00 68 00 61 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "xprocesshacker.pdb"
        $str2 = "KProcessHacker" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ProcHacker_da5de4a7 {
    meta:
        author = "Elastic Security"
        id = "da5de4a7-09b8-4661-be4a-576fe5ffa95a"
        fingerprint = "89fb400b5e9e3eea2ec2a5cde935fea6e032e67cd1ec63191c9a016320edaec3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: kprocesshacker.sys, Version: <= 3.1.0.0"
        threat_name = "Windows.VulnDriver.ProcHacker"
        reference_sample = "fa7900a0e2b435b9ea721cb562d11b752a4e974a1183f5cdf7fe14440fdf02e8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6B 00 70 00 72 00 6F 00 63 00 65 00 73 00 73 00 68 00 61 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "kprocesshacker.pdb"
        $str2 = "KProcessHacker" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

