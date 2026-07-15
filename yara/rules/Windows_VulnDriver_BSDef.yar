rule Windows_VulnDriver_BSDef_b8d8c22f {
    meta:
        author = "Elastic Security"
        id = "b8d8c22f-5850-4e0f-ae28-476acfef41bb"
        fingerprint = "6cb704d5686f0479752a73e02f968ece86348ec1dee68667a7dd8a5ff73ed0eb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 5.2.3790.0"
        threat_name = "Windows.VulnDriver.BSDef"
        reference_sample = "0040153302b88bee27eb4f1eca6855039e1a057370f5e8c615724fa5215bada3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 73 00 5F 00 44 00 65 00 66 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0d]|[\x00-\xcd][\x0e-\x0e])|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\xce-\xce][\x0e-\x0e])/
        $str1 = "BS_Def64.pdb"
        $str2 = "Support SST39SF020,SST29EE020,AT49F002T,AT29C020,AM29F002NT,AM29F002NB,V29C51002T,V29C51002B,M29F002T,W29C020." wide
        $str3 = "Default BIOS Flash Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

