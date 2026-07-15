rule Windows_VulnDriver_FeatureIntegration_2193f45a {
    meta:
        author = "Elastic Security"
        id = "2193f45a-2e1f-48f4-a768-ee60b5f13748"
        fingerprint = "395cf4487680247ee1609aefac0e01c3004360bdf0c5ce1759e88a357b73d0ce"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Feature Integration Technology Inc, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.FeatureIntegration"
        reference_sample = "17942865680bd3d6e6633c90cc4bd692ae0951a8589dbe103c1e293b3067344d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 65 61 74 75 72 65 20 49 6E 74 65 67 72 61 74 69 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 49 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 46 00 50 00 43 00 49 00 45 00 32 00 43 00 4F 00 4D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "FPCIE2COM.pdb"
        $str2 = "Fintek Corp. Fintek Pcie2Uart" wide
        $str3 = "Fintek Pcie2Uart Adapter" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_FeatureIntegration_8b25e126 {
    meta:
        author = "Elastic Security"
        id = "8b25e126-b04f-4a2f-82cd-35ccee590a75"
        fingerprint = "7e7458e0d640091a98e15e1f976d51eca37d166ff314731d7560f6e10e3b5c03"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Feature Integration Technology Inc., Version: <= 22.12.5.0"
        threat_name = "Windows.VulnDriver.FeatureIntegration"
        reference_sample = "81fbc9d02ef9e05602ea9c0804d423043d0ea5a06393c7ece3be03459f76a41d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 65 61 74 75 72 65 20 49 6E 74 65 67 72 61 74 69 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 46 00 50 00 43 00 49 00 45 00 32 00 43 00 4F 00 4D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x15][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0b][\x00-\x00][\x16-\x16][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0c-\x0c][\x00-\x00][\x16-\x16][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00]|[\x0c-\x0c][\x00-\x00][\x16-\x16][\x00-\x00][\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00])/
        $str1 = "FPCIE2COM.pdb"
        $str2 = "FINTEK PCIECOM " wide
        $str3 = "FINTEK PCIECOM Adapter" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

